//! Egress flow log (`ORBD_FLOW_LOG`): one structured event per new connection an orb in
//! orbd's network namespaces starts, with what orbd's egress policy did with it.
//!
//! The kernel does the matching: with the flow log on, orbd's nftables table (see
//! [`super::net`]) sends the first packets of each new orb flow (conntrack state `new`)
//! through a chain that mirrors the egress rules and logs, instead of deciding, to
//! NFLOG group [`GROUP`] with prefix [`PREFIX_ACCEPT`] or [`PREFIX_DROP`] and the first
//! [`SNAPLEN`] bytes (IPv4 and ports); an orb whose type restricts egress is logged by
//! its own chain's verdict, with [`PREFIX_RESTRICTED_ACCEPT`] or
//! [`PREFIX_RESTRICTED_DROP`]. The agent reads them from a netlink socket on a
//! thread of its own: the datapath never waits for it (the kernel drops log messages
//! the socket has no room for, and NFLOG's sequence numbers count them), and the kernel
//! logs at most [`super::net::FLOW_LOG_RATE`] new flows a second (the rest are counted
//! in the table's `flowlog_unlogged` counter).
//!
//! Flows are attributed by source: an orb's packets leave its namespace masqueraded to
//! its veth address, which encodes its durable network index (`<state>/net/<index>` names
//! the orb), so this works for every runtime on that network. The [`Aggregator`] logs
//! repeated first packets of one flow (SYN retransmissions, UDP before a reply) once,
//! and past a per-orb and an overall rate only counts flows, reporting the counts every
//! [`Limits::summary_every`]. Its memory is bounded.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// NFLOG group of orbd's flow log.
pub const GROUP: u16 = 4731;
/// Log prefixes for flows the egress policy accepts and drops.
pub const PREFIX_ACCEPT: &str = "orbd:a";
pub const PREFIX_DROP: &str = "orbd:d";
/// The same for orbs with restricted egress, decided by their orb type's policy.
pub const PREFIX_RESTRICTED_ACCEPT: &str = "orbd:ra";
pub const PREFIX_RESTRICTED_DROP: &str = "orbd:rd";
/// Bytes of each packet logged: an IPv4 header with options and the ports.
pub const SNAPLEN: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    Accept,
    Drop,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Accept => "accept",
            Verdict::Drop => "drop",
        }
    }
}

/// The first packet of an orb's flow, as logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flow {
    pub verdict: Verdict,
    /// Decided by the orb type's restricted egress policy.
    pub restricted: bool,
    /// IP protocol number.
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// TCP, UDP, SCTP and UDP-Lite only.
    pub sport: Option<u16>,
    pub dport: Option<u16>,
}

impl Flow {
    /// `tcp`, `udp`, ... or the protocol number.
    pub fn proto_name(&self) -> std::borrow::Cow<'static, str> {
        match self.proto {
            1 => "icmp".into(),
            6 => "tcp".into(),
            17 => "udp".into(),
            132 => "sctp".into(),
            136 => "udplite".into(),
            n => n.to_string().into(),
        }
    }

    /// `address:port`, or the address for protocols without ports.
    pub fn destination(&self) -> String {
        match self.dport {
            Some(p) => format!("{}:{p}", self.dst),
            None => self.dst.to_string(),
        }
    }
}

// --- netlink ----------------------------------------------------------------------

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
const NFULA_SEQ: u16 = 12;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULA_CFG_NLBUFSIZ: u16 = 3;
const NFULA_CFG_TIMEOUT: u16 = 4;
const NFULA_CFG_QTHRESH: u16 = 5;
const NFULA_CFG_FLAGS: u16 = 6;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;
const NFULNL_CFG_F_SEQ: u16 = 1;
const NLA_TYPE_MASK: u16 = 0x3fff;
/// Kernel-side batch: messages are sent when it is full, holds this many or is this old.
const BATCH_BYTES: u32 = 65536;
const BATCH_PACKETS: u32 = 64;
const BATCH_CENTISECS: u32 = 10;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn be16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn be32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

/// One NFLOG packet message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Logged<'a> {
    pub group: u16,
    /// Per-group sequence number (gaps are messages the kernel could not deliver).
    pub seq: Option<u32>,
    pub prefix: &'a [u8],
    pub payload: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum Message<'a> {
    Packet(Logged<'a>),
    /// An acknowledgement (0) or error (negative errno) for request `seq`.
    Ack {
        seq: u32,
        error: i32,
    },
    Done,
    Other,
}

/// The netlink messages of one datagram, or why it is malformed (messages before the
/// malformed one are kept).
pub fn parse(buf: &[u8]) -> (Vec<Message<'_>>, Option<String>) {
    let mut out = Vec::new();
    let mut at = 0;
    while buf.len().saturating_sub(at) >= NLMSG_HDRLEN {
        let (Some(len), Some(kind), Some(seq)) =
            (u32_at(buf, at), u16_at(buf, at + 4), u32_at(buf, at + 8))
        else {
            break;
        };
        let len = len as usize;
        if len < NLMSG_HDRLEN || len > buf.len() - at {
            return (out, Some(format!("netlink message of {len} bytes at {at}")));
        }
        let body = &buf[at + NLMSG_HDRLEN..at + len];
        out.push(match kind {
            NLMSG_ERROR => Message::Ack {
                seq,
                error: u32_at(body, 0).map_or(-1, |e| e as i32),
            },
            NLMSG_DONE => Message::Done,
            k if k == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET => match packet(body) {
                Some(p) => Message::Packet(p),
                None => return (out, Some(format!("bad NFLOG packet message at {at}"))),
            },
            _ => Message::Other,
        });
        at += align4(len);
    }
    (out, None)
}

/// An NFULNL_MSG_PACKET body: `nfgenmsg`, then attributes.
fn packet(body: &[u8]) -> Option<Logged<'_>> {
    let group = be16_at(body, 2)?;
    let mut p = Logged {
        group,
        seq: None,
        prefix: &[],
        payload: &[],
    };
    let mut at = 4;
    while body.len().saturating_sub(at) >= 4 {
        let len = u16_at(body, at)? as usize;
        let kind = u16_at(body, at + 2)? & NLA_TYPE_MASK;
        if len < 4 || at + len > body.len() {
            return None;
        }
        let data = &body[at + 4..at + len];
        match kind {
            NFULA_PAYLOAD => p.payload = data,
            NFULA_PREFIX => p.prefix = data.split(|b| *b == 0).next().unwrap_or_default(),
            NFULA_SEQ => p.seq = be32_at(data, 0),
            _ => {}
        }
        at += align4(len);
    }
    Some(p)
}

/// The flow a logged packet starts, if it is one of orbd's (by its prefix) and IPv4.
pub fn flow(p: &Logged<'_>) -> Option<Flow> {
    let (verdict, restricted) = match p.prefix {
        b if b == PREFIX_ACCEPT.as_bytes() => (Verdict::Accept, false),
        b if b == PREFIX_DROP.as_bytes() => (Verdict::Drop, false),
        b if b == PREFIX_RESTRICTED_ACCEPT.as_bytes() => (Verdict::Accept, true),
        b if b == PREFIX_RESTRICTED_DROP.as_bytes() => (Verdict::Drop, true),
        _ => return None,
    };
    let ip = p.payload;
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    let proto = ip[9];
    let first_fragment = be16_at(ip, 6)? & 0x1fff == 0;
    let ports = (first_fragment && matches!(proto, 6 | 17 | 132 | 136))
        .then(|| Some((be16_at(ip, ihl)?, be16_at(ip, ihl + 2)?)))
        .flatten();
    Some(Flow {
        verdict,
        restricted,
        proto,
        src: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        dst: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        sport: ports.map(|p| p.0),
        dport: ports.map(|p| p.1),
    })
}

fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = 4 + data.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(data);
    out.resize(align4(out.len()), 0);
}

/// The request binding `group` to the sending socket: whole packets up to [`SNAPLEN`],
/// sequence numbers, batches of at most [`BATCH_PACKETS`] or [`BATCH_CENTISECS`].
pub fn bind_request(group: u16, seq: u32) -> Vec<u8> {
    let mut m = vec![0u8; NLMSG_HDRLEN];
    m.extend_from_slice(&[0, 0]); // AF_UNSPEC, NFNETLINK_V0
    m.extend_from_slice(&group.to_be_bytes());
    attr(&mut m, NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND]);
    let mut mode = SNAPLEN.to_be_bytes().to_vec();
    mode.extend_from_slice(&[NFULNL_COPY_PACKET, 0]);
    attr(&mut m, NFULA_CFG_MODE, &mode);
    attr(&mut m, NFULA_CFG_NLBUFSIZ, &BATCH_BYTES.to_be_bytes());
    attr(&mut m, NFULA_CFG_TIMEOUT, &BATCH_CENTISECS.to_be_bytes());
    attr(&mut m, NFULA_CFG_QTHRESH, &BATCH_PACKETS.to_be_bytes());
    attr(&mut m, NFULA_CFG_FLAGS, &NFULNL_CFG_F_SEQ.to_be_bytes());
    let len = m.len() as u32;
    m[0..4].copy_from_slice(&len.to_ne_bytes());
    m[4..6].copy_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG).to_ne_bytes());
    m[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    m
}

// --- aggregation ------------------------------------------------------------------

/// Rate limits and bounds of the [`Aggregator`].
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Events per second one orb may emit, and its burst.
    pub per_orb_rate: f64,
    pub per_orb_burst: f64,
    /// Events per second all orbs together may emit, and their burst.
    pub total_rate: f64,
    pub total_burst: f64,
    /// Repeated first packets of one flow within this window are one event.
    pub repeat_window: Duration,
    /// Flows remembered for that (the oldest are forgotten first).
    pub max_remembered: usize,
    /// How often counts of what was not logged one by one are reported.
    pub summary_every: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_orb_rate: 50.0,
            per_orb_burst: 200.0,
            total_rate: 500.0,
            total_burst: 2000.0,
            repeat_window: Duration::from_secs(30),
            max_remembered: 16384,
            summary_every: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            at: now,
        }
    }

    fn refill(&mut self, rate: f64, burst: f64, now: Instant) {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + dt * rate).min(burst);
        self.at = now;
    }
}

/// What to do with a flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Log it.
    Emit,
    /// Another first packet of a flow already logged.
    Repeat,
    /// Over a rate limit: counted, reported in the next summary.
    Suppressed,
}

/// Flows not logged one by one, per orb, since the last summary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub accepted: u64,
    pub dropped: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// By network index.
    pub suppressed: Vec<(u32, Counts)>,
    /// Flows the kernel logged that never reached the agent.
    pub lost: u64,
}

/// Decides which flows are logged one by one (see the module docs). Pure: the caller
/// passes the time.
pub struct Aggregator {
    limits: Limits,
    total: Bucket,
    per_orb: HashMap<u32, Bucket>,
    recent: HashMap<Flow, Instant>,
    order: VecDeque<(Flow, Instant)>,
    suppressed: HashMap<u32, Counts>,
    lost: u64,
    next_seq: Option<u32>,
    last_summary: Instant,
}

impl Aggregator {
    pub fn new(limits: Limits, now: Instant) -> Self {
        Self {
            total: Bucket::full(limits.total_burst, now),
            limits,
            per_orb: HashMap::new(),
            recent: HashMap::new(),
            order: VecDeque::new(),
            suppressed: HashMap::new(),
            lost: 0,
            next_seq: None,
            last_summary: now,
        }
    }

    /// Counts messages skipped before sequence number `seq`.
    pub fn sequence(&mut self, seq: u32) {
        if let Some(want) = self.next_seq {
            // Gaps only; a sequence that goes back is a new instance.
            let gap = seq.wrapping_sub(want);
            if gap < u32::MAX / 2 {
                self.lost += u64::from(gap);
            }
        }
        self.next_seq = Some(seq.wrapping_add(1));
    }

    /// Counts flows lost that sequence numbers do not show (the kernel's rate limit).
    pub fn lost(&mut self, n: u64) {
        self.lost += n;
    }

    pub fn admit(&mut self, index: u32, flow: &Flow, now: Instant) -> Admit {
        let l = self.limits;
        while let Some((f, t)) = self.order.front() {
            if now.saturating_duration_since(*t) < l.repeat_window
                && self.order.len() < l.max_remembered
            {
                break;
            }
            if self.recent.get(f) == Some(t) {
                self.recent.remove(f);
            }
            self.order.pop_front();
        }
        if let Some(t) = self.recent.get(flow)
            && now.saturating_duration_since(*t) < l.repeat_window
        {
            return Admit::Repeat;
        }
        self.recent.insert(*flow, now);
        self.order.push_back((*flow, now));
        let orb = self
            .per_orb
            .entry(index)
            .or_insert_with(|| Bucket::full(l.per_orb_burst, now));
        orb.refill(l.per_orb_rate, l.per_orb_burst, now);
        self.total.refill(l.total_rate, l.total_burst, now);
        if orb.tokens >= 1.0 && self.total.tokens >= 1.0 {
            orb.tokens -= 1.0;
            self.total.tokens -= 1.0;
            return Admit::Emit;
        }
        let c = self.suppressed.entry(index).or_default();
        match flow.verdict {
            Verdict::Accept => c.accepted += 1,
            Verdict::Drop => c.dropped += 1,
        }
        Admit::Suppressed
    }

    /// Once every [`Limits::summary_every`]: what was not logged one by one since the
    /// last summary, if anything. Forgets orbs that have been quiet since.
    pub fn summary(&mut self, now: Instant) -> Option<Summary> {
        if now.saturating_duration_since(self.last_summary) < self.limits.summary_every {
            return None;
        }
        self.last_summary = now;
        let l = self.limits;
        self.per_orb.retain(|_, b| {
            b.refill(l.per_orb_rate, l.per_orb_burst, now);
            b.tokens < l.per_orb_burst
        });
        let mut suppressed: Vec<(u32, Counts)> = self.suppressed.drain().collect();
        suppressed.sort_by_key(|(i, _)| *i);
        let lost = std::mem::take(&mut self.lost);
        (!suppressed.is_empty() || lost > 0).then_some(Summary { suppressed, lost })
    }

    /// Flows remembered for repeat detection (bounded by [`Limits::max_remembered`]).
    pub fn remembered(&self) -> usize {
        self.order.len()
    }
}

// --- the listener -------------------------------------------------------------------

/// Who an orb is, for the log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowOrb {
    pub orb: String,
    pub amp_orb_id: Option<String>,
}

/// An NFLOG netlink socket bound to a group in the agent's network namespace.
#[cfg(target_os = "linux")]
pub struct Socket {
    fd: std::os::fd::OwnedFd,
    group: u16,
}

#[cfg(target_os = "linux")]
enum Recv {
    Data(usize),
    Idle,
    /// The receive buffer overflowed: messages were lost (sequence numbers count them).
    Overrun,
}

#[cfg(target_os = "linux")]
impl Socket {
    /// Opens a netlink socket and binds `group` to it (needs CAP_NET_ADMIN; fails if
    /// another socket holds the group).
    pub fn open(group: u16) -> Result<Self, String> {
        use nix::libc;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let err = |what: &str| format!("{what}: {}", std::io::Error::last_os_error());
        // SAFETY: plain socket syscalls on a descriptor this function owns.
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            );
            if fd < 0 {
                return Err(err("netlink socket"));
            }
            let fd = OwnedFd::from_raw_fd(fd);
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            if libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            ) < 0
            {
                return Err(err("binding the netlink socket"));
            }
            // Room for bursts; SO_RCVBUFFORCE needs CAP_NET_ADMIN, which the agent has.
            let size: libc::c_int = 8 << 20;
            let set = |opt, v: *const libc::c_void, len| {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    opt,
                    v,
                    len as libc::socklen_t,
                )
            };
            let int_len = std::mem::size_of::<libc::c_int>();
            if set(
                libc::SO_RCVBUFFORCE,
                (&size as *const libc::c_int).cast(),
                int_len,
            ) < 0
            {
                set(
                    libc::SO_RCVBUF,
                    (&size as *const libc::c_int).cast(),
                    int_len,
                );
            }
            let tv = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            set(
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>(),
            );
            let s = Self { fd, group };
            s.bind_group()?;
            Ok(s)
        }
    }

    fn bind_group(&self) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        let seq = 1;
        let req = bind_request(self.group, seq);
        // SAFETY: send from a valid buffer on our own descriptor.
        let sent =
            unsafe { nix::libc::send(self.fd.as_raw_fd(), req.as_ptr().cast(), req.len(), 0) };
        if sent < 0 {
            return Err(format!(
                "binding NFLOG group {}: {}",
                self.group,
                std::io::Error::last_os_error()
            ));
        }
        let mut buf = vec![0u8; 1 << 17];
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let n = match self.recv(&mut buf) {
                Ok(Recv::Data(n)) => n,
                Ok(Recv::Idle | Recv::Overrun) => continue,
                Err(e) => return Err(format!("binding NFLOG group {}: {e}", self.group)),
            };
            for m in parse(&buf[..n]).0 {
                match m {
                    Message::Ack { seq: s, error: 0 } if s == seq => return Ok(()),
                    Message::Ack { seq: s, error } if s == seq => {
                        let e = std::io::Error::from_raw_os_error(-error);
                        let hint = match -error {
                            nix::libc::EPERM => {
                                " (another process holds the group, or no CAP_NET_ADMIN)"
                            }
                            nix::libc::EBUSY => " (already bound)",
                            _ => "",
                        };
                        return Err(format!("binding NFLOG group {}: {e}{hint}", self.group));
                    }
                    _ => {}
                }
            }
        }
        Err(format!("binding NFLOG group {}: no answer", self.group))
    }

    fn recv(&self, buf: &mut [u8]) -> Result<Recv, String> {
        use std::os::fd::AsRawFd;
        loop {
            // SAFETY: receive into a valid buffer on our own descriptor.
            let n = unsafe {
                nix::libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0)
            };
            if n >= 0 {
                return Ok(Recv::Data(n as usize));
            }
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(nix::libc::EINTR) => continue,
                Some(nix::libc::EAGAIN) => return Ok(Recv::Idle),
                Some(nix::libc::ENOBUFS) => return Ok(Recv::Overrun),
                _ => return Err(e.to_string()),
            }
        }
    }
}

/// Reads flows from `socket` on a thread of its own until `shutdown`, logging each new
/// one as an `orbd::flow` event. `resolve` names the orb of a network index;
/// `unlogged` reads how many new flows the kernel did not log (its rate limit).
#[cfg(target_os = "linux")]
pub fn spawn(
    socket: Socket,
    mut resolve: impl FnMut(u32) -> Option<FlowOrb> + Send + 'static,
    mut unlogged: impl FnMut() -> Option<u64> + Send + 'static,
    shutdown: tokio_util::sync::CancellationToken,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("orbd-flowlog".into())
        .spawn(move || {
            let mut agg = Aggregator::new(Limits::default(), Instant::now());
            let mut buf = vec![0u8; 1 << 18];
            let mut kernel_unlogged = 0u64;
            let mut last_counter = Instant::now();
            tracing::info!(group = socket.group, "egress flow log on");
            while !shutdown.is_cancelled() {
                match socket.recv(&mut buf) {
                    Ok(Recv::Data(n)) => {
                        let now = Instant::now();
                        let (messages, bad) = parse(&buf[..n]);
                        if let Some(bad) = bad {
                            tracing::debug!(%bad, "flow log: malformed netlink data");
                        }
                        for m in messages {
                            let Message::Packet(p) = m else { continue };
                            if p.group != socket.group {
                                continue;
                            }
                            if let Some(seq) = p.seq {
                                agg.sequence(seq);
                            }
                            let Some(f) = flow(&p) else { continue };
                            let Some(index) = super::net::index_of(f.src) else {
                                continue;
                            };
                            match agg.admit(index, &f, now) {
                                Admit::Emit => emit(&f, index, resolve(index)),
                                Admit::Repeat => {
                                    metrics::counter!("orbd_flow_log_repeats_total").increment(1)
                                }
                                Admit::Suppressed => {
                                    metrics::counter!("orbd_flow_log_suppressed_total").increment(1)
                                }
                            }
                        }
                    }
                    Ok(Recv::Idle | Recv::Overrun) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "flow log: reading NFLOG");
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                let now = Instant::now();
                if now.duration_since(last_counter) >= Duration::from_secs(60) {
                    last_counter = now;
                    if let Some(n) = unlogged() {
                        // The table is replaced (counter reset) when a runtime starts.
                        agg.lost(n.checked_sub(kernel_unlogged).unwrap_or(n));
                        kernel_unlogged = n;
                    }
                }
                if let Some(s) = agg.summary(now) {
                    report(&s, &mut resolve);
                }
            }
        })
}

#[cfg(target_os = "linux")]
fn emit(f: &Flow, index: u32, who: Option<FlowOrb>) {
    let who = who.unwrap_or_default();
    let thread_id = who.amp_orb_id.as_deref().and_then(thread_of);
    metrics::counter!("orbd_flow_log_events_total", "verdict" => f.verdict.as_str()).increment(1);
    tracing::info!(
        target: "orbd::flow",
        orb = %who.orb,
        amp_orb_id = who.amp_orb_id.as_deref(),
        thread_id = thread_id.as_deref(),
        net_index = index,
        proto = %f.proto_name(),
        src_port = f.sport,
        dst = %f.destination(),
        verdict = f.verdict.as_str(),
        egress = if f.restricted { "restricted" } else { "default" },
        "orb flow"
    );
}

#[cfg(target_os = "linux")]
fn report(s: &Summary, resolve: &mut impl FnMut(u32) -> Option<FlowOrb>) {
    for (index, c) in &s.suppressed {
        let who = resolve(*index).unwrap_or_default();
        let thread_id = who.amp_orb_id.as_deref().and_then(thread_of);
        tracing::warn!(
            target: "orbd::flow",
            orb = %who.orb,
            amp_orb_id = who.amp_orb_id.as_deref(),
            thread_id = thread_id.as_deref(),
            net_index = *index,
            accepted = c.accepted,
            dropped = c.dropped,
            "orb flows over the flow log's rate limit, counted but not logged one by one"
        );
    }
    if s.lost > 0 {
        metrics::counter!("orbd_flow_log_lost_total").increment(s.lost);
        tracing::warn!(
            target: "orbd::flow",
            lost = s.lost,
            "orb flows not logged: the kernel's rate limit or a full socket buffer"
        );
    }
}

/// Amp's thread of an Amp orb id (`amp-<uuid>` → `T-<uuid>`).
#[cfg(target_os = "linux")]
fn thread_of(amp_orb_id: &str) -> Option<String> {
    Some(crate::cli::orbs::thread_id(amp_orb_id)).filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One datagram as nfnetlink_log sent it (Linux 7.2, x86_64) for a UDP packet from
    /// 127.0.0.1:59480 to 127.0.0.1:9 logged with `log group 4731 snaplen 64 prefix
    /// "orbd:a"` in an output chain, captured by `nflog_delivers_logged_flows`: packet
    /// header, prefix, outdev, uid, gid, seq, payload.
    const CAPTURED: &str = "700000000004000000000000000000000200127b08000100080003000b000a00\
        6f7262643a610000080005000000000108000b000000000008000e000000000008000c0000000000\
        2500090045000021514f40004011eb7a7f0000017f000001e8580009000dfe2068656c6c6f000000";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], ports: Option<(u16, u16)>) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        if let Some((s, d)) = ports {
            p.extend_from_slice(&s.to_be_bytes());
            p.extend_from_slice(&d.to_be_bytes());
        }
        p
    }

    /// An NFLOG packet message as the kernel builds it.
    fn message(group: u16, seq: u32, prefix: &str, payload: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; NLMSG_HDRLEN];
        m.extend_from_slice(&[2, 0]); // AF_INET
        m.extend_from_slice(&group.to_be_bytes());
        attr(&mut m, 1, &[0x08, 0x00, 4, 0]); // packet header: IPv4, forward hook
        let mut p = prefix.as_bytes().to_vec();
        p.push(0);
        attr(&mut m, NFULA_PREFIX, &p);
        attr(&mut m, 4, &7u32.to_be_bytes()); // indev
        attr(&mut m, NFULA_SEQ, &seq.to_be_bytes());
        attr(&mut m, NFULA_PAYLOAD, payload);
        let len = m.len() as u32;
        m[0..4].copy_from_slice(&len.to_ne_bytes());
        m[4..6].copy_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET).to_ne_bytes());
        m[6..8].copy_from_slice(&2u16.to_ne_bytes()); // NLM_F_MULTI
        m
    }

    #[test]
    fn parses_captured_kernel_messages() {
        let buf = hex(CAPTURED);
        assert_eq!(buf.len(), 112);
        let (messages, bad) = parse(&buf);
        assert_eq!(bad, None);
        let Some(Message::Packet(p)) = messages.first() else {
            panic!("{messages:?}");
        };
        assert_eq!((p.group, p.seq, p.prefix), (GROUP, Some(0), &b"orbd:a"[..]));
        let f = flow(p).unwrap();
        assert_eq!(f.verdict, Verdict::Accept);
        assert_eq!(f.proto_name(), "udp");
        assert_eq!(f.src, Ipv4Addr::LOCALHOST);
        assert_eq!(f.destination(), "127.0.0.1:9");
        assert_eq!(f.sport, Some(59480));
        assert_eq!(p.payload.len(), 33, "the whole (short) packet");
    }

    #[test]
    fn parses_batches_and_flows() {
        let tcp = ipv4(6, [169, 254, 0, 6], [1, 1, 1, 1], Some((40000, 443)));
        let icmp = ipv4(1, [169, 254, 0, 6], [10, 0, 0, 1], None);
        let mut buf = message(GROUP, 7, PREFIX_ACCEPT, &tcp);
        buf.extend(message(GROUP, 8, PREFIX_DROP, &icmp));
        buf.extend(message(GROUP, 9, "someone-else", &tcp));
        buf.extend(message(GROUP, 10, PREFIX_RESTRICTED_DROP, &tcp));
        buf.extend(message(GROUP, 11, PREFIX_RESTRICTED_ACCEPT, &tcp));
        let mut done = vec![0u8; 20];
        done[0..4].copy_from_slice(&20u32.to_ne_bytes());
        done[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        buf.extend(done);
        let (messages, bad) = parse(&buf);
        assert_eq!(bad, None);
        assert_eq!(messages.len(), 6);
        assert_eq!(messages[5], Message::Done);
        let flows: Vec<Option<Flow>> = messages[..5]
            .iter()
            .map(|m| match m {
                Message::Packet(p) => flow(p),
                other => panic!("{other:?}"),
            })
            .collect();
        let f = flows[0].unwrap();
        assert_eq!(
            (f.verdict, f.proto_name().as_ref(), f.destination(), f.sport),
            (Verdict::Accept, "tcp", "1.1.1.1:443".into(), Some(40000))
        );
        let f = flows[1].unwrap();
        assert_eq!(
            (f.verdict, f.proto_name().as_ref(), f.destination(), f.sport),
            (Verdict::Drop, "icmp", "10.0.0.1".into(), None)
        );
        assert_eq!(flows[2], None, "not orbd's prefix");
        assert!(!flows[0].unwrap().restricted && !flows[1].unwrap().restricted);
        let (d, a) = (flows[3].unwrap(), flows[4].unwrap());
        assert_eq!((d.verdict, d.restricted), (Verdict::Drop, true));
        assert_eq!((a.verdict, a.restricted), (Verdict::Accept, true));
        let Message::Packet(p) = &messages[1] else {
            unreachable!()
        };
        assert_eq!(p.seq, Some(8));
    }

    #[test]
    fn rejects_malformed_data() {
        let tcp = ipv4(6, [169, 254, 0, 6], [1, 1, 1, 1], Some((40000, 443)));
        let good = message(GROUP, 1, PREFIX_ACCEPT, &tcp);
        // Truncated: the first message survives, the cut one is reported.
        let mut buf = good.clone();
        buf.extend_from_slice(&good[..good.len() - 8]);
        let (messages, bad) = parse(&buf);
        assert_eq!(messages.len(), 1);
        assert!(bad.is_some());
        // An attribute running past its message.
        let mut broken = good.clone();
        broken[20..22].copy_from_slice(&200u16.to_ne_bytes());
        assert!(parse(&broken).1.is_some());
        // A length below the header.
        let mut tiny = good.clone();
        tiny[0..4].copy_from_slice(&4u32.to_ne_bytes());
        assert!(parse(&tiny).1.is_some());
        // Not IPv4, too short, a later fragment (no ports).
        for payload in [vec![0x60; 40], tcp[..12].to_vec(), {
            let mut f = tcp.clone();
            f[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
            f
        }] {
            let m = message(GROUP, 1, PREFIX_DROP, &payload);
            let (messages, _) = parse(&m);
            let Message::Packet(p) = &messages[0] else {
                panic!()
            };
            let f = flow(p);
            assert!(f.is_none() || f.unwrap().dport.is_none(), "{payload:?}");
        }
        // An empty datagram and garbage shorter than a header.
        assert_eq!(parse(&[]), (vec![], None));
        assert_eq!(parse(&[1, 2, 3]), (vec![], None));
    }

    #[test]
    fn bind_request_is_well_formed() {
        let m = bind_request(GROUP, 9);
        assert_eq!(u32_at(&m, 0), Some(m.len() as u32));
        assert_eq!(u16_at(&m, 4), Some(0x0401));
        assert_eq!(u16_at(&m, 6), Some(NLM_F_REQUEST | NLM_F_ACK));
        assert_eq!(u32_at(&m, 8), Some(9));
        assert_eq!(be16_at(&m, 18), Some(GROUP));
        let mut kinds = Vec::new();
        let mut at = 20;
        while at < m.len() {
            let len = u16_at(&m, at).unwrap() as usize;
            kinds.push((u16_at(&m, at + 2).unwrap(), m[at + 4..at + len].to_vec()));
            at += align4(len);
        }
        assert_eq!(at, m.len());
        assert_eq!(kinds[0], (NFULA_CFG_CMD, vec![NFULNL_CFG_CMD_BIND]));
        assert_eq!(kinds[1], (NFULA_CFG_MODE, vec![0, 0, 0, 64, 2, 0]));
        assert_eq!(kinds[5], (NFULA_CFG_FLAGS, vec![0, 1]));
    }

    fn tcp_flow(sport: u16, dport: u16, verdict: Verdict) -> Flow {
        Flow {
            verdict,
            restricted: false,
            proto: 6,
            src: Ipv4Addr::new(169, 254, 0, 6),
            dst: Ipv4Addr::new(1, 1, 1, 1),
            sport: Some(sport),
            dport: Some(dport),
        }
    }

    #[test]
    fn repeats_are_one_event() {
        let t0 = Instant::now();
        let mut a = Aggregator::new(Limits::default(), t0);
        let f = tcp_flow(40000, 443, Verdict::Drop);
        assert_eq!(a.admit(1, &f, t0), Admit::Emit);
        // SYN retransmissions of the same dropped connection.
        for s in [1, 3, 7, 15] {
            assert_eq!(a.admit(1, &f, t0 + Duration::from_secs(s)), Admit::Repeat);
        }
        assert_eq!(a.admit(1, &f, t0 + Duration::from_secs(31)), Admit::Emit);
        // Another connection to the same place is another flow.
        assert_eq!(
            a.admit(1, &tcp_flow(40001, 443, Verdict::Drop), t0),
            Admit::Emit
        );
    }

    #[test]
    fn rate_limits_count_what_they_hold_back() {
        let limits = Limits {
            per_orb_rate: 10.0,
            per_orb_burst: 20.0,
            total_rate: 25.0,
            total_burst: 30.0,
            ..Limits::default()
        };
        let t0 = Instant::now();
        let mut a = Aggregator::new(limits, t0);
        let burst = |a: &mut Aggregator, index: u32, n: u16, at: Instant| {
            (0..n)
                .map(|i| {
                    let f = Flow {
                        src: Ipv4Addr::new(169, 254, 0, 2 + 4 * index as u8),
                        ..tcp_flow(10000 + i, 443, Verdict::Accept)
                    };
                    a.admit(index, &f, at)
                })
                .filter(|d| *d == Admit::Emit)
                .count()
        };
        assert_eq!(burst(&mut a, 1, 50, t0), 20, "one orb's burst");
        assert_eq!(burst(&mut a, 2, 50, t0), 10, "what is left of the total");
        assert_eq!(a.summary(t0 + Duration::from_secs(1)), None, "not yet");
        let s = a.summary(t0 + Duration::from_secs(10)).unwrap();
        assert_eq!(
            s.suppressed,
            vec![
                (
                    1,
                    Counts {
                        accepted: 30,
                        dropped: 0
                    }
                ),
                (
                    2,
                    Counts {
                        accepted: 40,
                        dropped: 0
                    }
                )
            ]
        );
        // Refilled over time (and past the repeat window).
        let later = t0 + Duration::from_secs(40);
        assert_eq!(burst(&mut a, 1, 5, later), 5);
        assert_eq!(a.summary(later + Duration::from_secs(10)), None);
    }

    #[test]
    fn memory_is_bounded() {
        let limits = Limits {
            max_remembered: 100,
            ..Limits::default()
        };
        let t0 = Instant::now();
        let mut a = Aggregator::new(limits, t0);
        for i in 0..10_000u16 {
            a.admit(u32::from(i % 300), &tcp_flow(i, 443, Verdict::Drop), t0);
        }
        assert!(a.remembered() <= 100);
        assert!(a.recent.len() <= 100);
        a.summary(t0 + Duration::from_secs(600));
        assert!(a.per_orb.is_empty(), "quiet orbs are forgotten");
    }

    #[test]
    fn sequence_gaps_count_as_lost() {
        let t0 = Instant::now();
        let mut a = Aggregator::new(Limits::default(), t0);
        a.sequence(5);
        a.sequence(6);
        a.sequence(10); // 7, 8, 9 lost
        a.sequence(u32::MAX - 1); // implausibly far: a new instance, not a loss
        a.sequence(u32::MAX);
        a.sequence(1); // wraps; 0 lost
        a.sequence(0); // back: a new instance starts over, not a loss
        a.lost(1);
        let s = a.summary(t0 + Duration::from_secs(10)).unwrap();
        assert_eq!(s.lost, 3 + 1 + 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn thread_ids() {
        assert_eq!(thread_of("amp-1234").as_deref(), Some("T-1234"));
        assert_eq!(thread_of("other"), None);
    }

    /// Real kernel: binds an NFLOG group, logs a UDP packet with an nftables rule like
    /// orbd's and reads it back, in a throwaway user and network namespace (this test
    /// runs itself again inside `unshare -rn`). Skipped where that or nft is unavailable,
    /// unless `ORBD_TEST_NFT=1` (CI) requires it.
    #[cfg(target_os = "linux")]
    #[test]
    fn nflog_delivers_logged_flows() {
        use std::process::Command;
        const INNER: &str = "ORBD_TEST_NFLOG_INNER";
        if std::env::var_os(INNER).is_none() {
            let probe = Command::new("unshare")
                .args(["-rn", "nft", "list", "ruleset"])
                .output();
            if !probe.is_ok_and(|o| o.status.success()) {
                assert!(
                    std::env::var("ORBD_TEST_NFT").is_err(),
                    "ORBD_TEST_NFT is set but `unshare -rn nft` does not work"
                );
                eprintln!("skipped: no unprivileged network namespace with nft");
                return;
            }
            let out = Command::new("unshare")
                .arg("-rn")
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::vm::flowlog::tests::nflog_delivers_logged_flows",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(INNER, "1")
                .output()
                .unwrap();
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                out.status.success() && text.contains("1 passed"),
                "inner test failed:\n{text}"
            );
            return;
        }
        let ok = |c: &mut Command| {
            let o = c.output().unwrap();
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        };
        ok(Command::new("ip").args(["link", "set", "lo", "up"]));
        let socket = Socket::open(GROUP).expect("binding the NFLOG group");
        let rules = format!(
            r#"table inet t {{
    chain o {{
        type filter hook output priority filter; policy accept;
        ip daddr 127.0.0.1 udp dport 9 ct state new log group {GROUP} snaplen {SNAPLEN} prefix "{PREFIX_ACCEPT}"
    }}
}}
"#
        );
        let mut nft = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut nft.stdin.take().unwrap(), rules.as_bytes()).unwrap();
        assert!(nft.wait().unwrap().success());
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sport = udp.local_addr().unwrap().port();
        udp.send_to(b"hello", "127.0.0.1:9").unwrap();
        let mut buf = vec![0u8; 1 << 16];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "nothing logged");
            let Ok(Recv::Data(n)) = socket.recv(&mut buf) else {
                continue;
            };
            let datagram = &buf[..n];
            let hex: String = datagram.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("captured {n} bytes: {hex}");
            let (messages, bad) = parse(datagram);
            assert_eq!(bad, None);
            let Some(Message::Packet(p)) = messages
                .into_iter()
                .find(|m| matches!(m, Message::Packet(_)))
            else {
                continue;
            };
            assert_eq!((p.group, p.seq), (GROUP, Some(0)));
            let f = flow(&p).unwrap();
            assert_eq!(f.verdict, Verdict::Accept);
            assert_eq!(
                (f.src, f.destination()),
                (Ipv4Addr::LOCALHOST, "127.0.0.1:9".into())
            );
            assert_eq!((f.proto_name().as_ref(), f.sport), ("udp", Some(sport)));
            break;
        }
        // A second socket cannot take the group.
        let e = Socket::open(GROUP).err().expect("the group is taken");
        assert!(e.contains("NFLOG group"), "{e}");
    }
}
