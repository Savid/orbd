//! The restricted-egress DNS proxy's codec: the only code that reads what orbs send the
//! proxy ([`super::egress`]). It runs as a child process of its own, `orbd dns-codec`,
//! in the jail VMMs get (its own uid above every orb's, no capabilities, `no_new_privs`,
//! an empty read-only root, a network namespace with nothing in it), undumpable, with
//! memory and CPU limits, and a seccomp filter that allows it only to read and write its
//! socket (stdin), use memory, signal itself and exit
//! ([`crate::seccomp::codec_allowlist`]). Each restricted orb's launch gets a codec of
//! its own ([`super::egress`] starts one at the orb's first query and stops it once idle
//! or the launch is over), so a codec an orb took over handles only that orb's DNS.
//!
//! It holds no network socket: the agent receives and sends every packet and hands the
//! codec raw queries over a unix socket. The codec turns a query into its question
//! ([`Decoded`]); the agent decides on it (policy, upstream lookup, opening addresses)
//! and has the codec build the answer from that query and the agent's records
//! ([`Codec::encode`]), which the agent sends only to the orb that asked. The agent reads
//! the codec's messages strictly (exact lengths and kinds, a normalized hostname, an
//! answer within the transport's size, only to a request it has pending); anything else,
//! a codec that does not answer within [`CODEC_TIMEOUT`] or one that exits, and the codec
//! is killed and started again with backoff, its orb getting no answers meanwhile. A
//! codec taken over by an orb can so at most answer that orb's queries wrongly, or look up
//! names on that orb's own list: what the orb could do to its own DNS anyway.
//!
//! Messages are `u32` (big-endian) length-prefixed. Agent to codec: `1 tag query`
//! (decode) and `2 tag udp rcode n answers… query` (encode, `n` records of `ttl type
//! name data`). Codec to agent: `1 tag opcode qtype qclass len name` (a question, `len`
//! 0 if the name is no hostname), `2 tag bytes` (a message for the orb: a FORMERR to a
//! decode, the answer to an encode) and `3 tag` (no answer at all).

use super::dns::{self, Answer, AnswerData};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// The hidden subcommand the codec runs as.
pub const SUBCOMMAND: &str = "dns-codec";
/// How long the codec may take with one message before it is killed.
pub const CODEC_TIMEOUT: Duration = Duration::from_secs(1);
/// Largest query handed to the codec (the proxy reads no more).
pub const MAX_QUERY: usize = 4096;
/// Most records in one answer: an upstream answer's, plus its chain.
const MAX_RECORDS: usize = dns::MAX_ANSWERS + dns::MAX_CHAIN;
/// Largest message to the codec: an encode with every record at its longest.
const MAX_REQUEST: usize = 10 + MAX_RECORDS * (4 + 1 + 1 + 253 + 1 + 253) + MAX_QUERY;
/// Largest message from the codec: an answer over TCP.
const MAX_REPLY: usize = 5 + 65535;
/// Most requests left unanswered (each query has at most one in flight).
const MAX_PENDING: usize = 1024;
const MIN_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(10);
/// A codec up this long starts again quickly when it next stops.
const STABLE: Duration = Duration::from_secs(60);
/// Most of a codec's stderr read over its life.
#[cfg(target_os = "linux")]
const MAX_STDERR: usize = 4 * 1024;

const DECODE: u8 = 1;
const ENCODE: u8 = 2;
const QUESTION: u8 = 1;
const REPLY: u8 = 2;
const IGNORE: u8 = 3;
const RECORD_A: u8 = 1;
const RECORD_CNAME: u8 = 5;

/// A query's question, as the codec read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub opcode: u8,
    pub qtype: u16,
    pub qclass: u16,
    /// Normalized (lowercase, no trailing dot), if every label is a hostname label.
    pub name: Option<String>,
}

/// What a query is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    /// Not a query: no answer.
    Ignore,
    /// Malformed: this answer (FORMERR).
    Reply(Vec<u8>),
    Question(Question),
}

/// A message from the codec.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Reply {
    Question(Question),
    Bytes(Vec<u8>),
    Ignore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Decode,
    /// Over UDP or TCP.
    Encode {
        udp: bool,
    },
}

// ----- messages -----------------------------------------------------------------------

fn put_name(out: &mut Vec<u8>, name: &str) {
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
}

/// A normalized hostname as text, or why not.
fn hostname(b: &[u8]) -> Result<String, &'static str> {
    let s = std::str::from_utf8(b).map_err(|_| "a name that is not ASCII")?;
    match crate::model::egress::normalize_name(s) {
        Some(n) if n == s => Ok(n),
        _ => Err("a name that is not a normalized hostname"),
    }
}

/// Reads `msg` front to back; every read is bounds-checked.
struct Reader<'a> {
    msg: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(msg: &'a [u8]) -> Self {
        Self { msg, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let end = self.at.checked_add(n).ok_or("truncated")?;
        let b = self.msg.get(self.at..end).ok_or("truncated")?;
        self.at = end;
        Ok(b)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn name(&mut self) -> Result<String, &'static str> {
        let n = usize::from(self.u8()?);
        hostname(self.take(n)?)
    }

    fn rest(&mut self) -> &'a [u8] {
        let b = &self.msg[self.at..];
        self.at = self.msg.len();
        b
    }

    fn end(&self) -> Result<(), &'static str> {
        if self.at == self.msg.len() {
            Ok(())
        } else {
            Err("trailing bytes")
        }
    }
}

fn decode_request(tag: u32, query: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + query.len());
    out.push(DECODE);
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(query);
    out
}

fn encode_request(tag: u32, query: &[u8], udp: bool, rcode: u8, answers: &[Answer]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + query.len() + answers.len() * 32);
    out.push(ENCODE);
    out.extend_from_slice(&tag.to_be_bytes());
    out.push(u8::from(udp));
    out.push(rcode);
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    for a in answers {
        out.extend_from_slice(&a.ttl.to_be_bytes());
        match &a.data {
            AnswerData::A(ip) => {
                out.push(RECORD_A);
                put_name(&mut out, &a.name);
                out.extend_from_slice(&ip.octets());
            }
            AnswerData::Cname(target) => {
                out.push(RECORD_CNAME);
                put_name(&mut out, &a.name);
                put_name(&mut out, target);
            }
        }
    }
    out.extend_from_slice(query);
    out
}

/// The codec's message for `reply` to request `tag`.
fn reply_message(tag: u32, reply: &Reply) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    match reply {
        Reply::Question(q) => {
            out.push(QUESTION);
            out.extend_from_slice(&tag.to_be_bytes());
            out.push(q.opcode);
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
            put_name(&mut out, q.name.as_deref().unwrap_or(""));
        }
        Reply::Bytes(b) => {
            out.push(REPLY);
            out.extend_from_slice(&tag.to_be_bytes());
            out.extend_from_slice(b);
        }
        Reply::Ignore => {
            out.push(IGNORE);
            out.extend_from_slice(&tag.to_be_bytes());
        }
    }
    out
}

/// Reads a message from the codec (untrusted): its tag and reply, or why it is no
/// valid message.
fn parse_reply(msg: &[u8]) -> Result<(u32, Reply), &'static str> {
    let mut r = Reader::new(msg);
    let kind = r.u8()?;
    let tag = r.u32()?;
    let reply = match kind {
        QUESTION => {
            let opcode = r.u8()?;
            if opcode > 15 {
                return Err("an opcode above 15");
            }
            let qtype = r.u16()?;
            let qclass = r.u16()?;
            let n = usize::from(r.u8()?);
            let name = match n {
                0 => None,
                n => Some(hostname(r.take(n)?)?),
            };
            Reply::Question(Question {
                opcode,
                qtype,
                qclass,
                name,
            })
        }
        REPLY => {
            let b = r.rest();
            if b.len() < dns::HEADER {
                return Err("a message shorter than a DNS header");
            }
            if b.len() > 65535 {
                return Err("a message longer than 65535 bytes");
            }
            Reply::Bytes(b.to_vec())
        }
        IGNORE => Reply::Ignore,
        _ => return Err("an unknown kind of message"),
    };
    r.end()?;
    Ok((tag, reply))
}

/// Whether `reply` may answer a request of `stage`.
fn fits(stage: Stage, reply: &Reply) -> Result<(), &'static str> {
    match (stage, reply) {
        (Stage::Decode, Reply::Bytes(b)) if b.len() != dns::HEADER => {
            Err("a FORMERR that is not a bare header")
        }
        (Stage::Decode, _) => Ok(()),
        (Stage::Encode { .. }, Reply::Question(_)) => Err("a question in answer to an encode"),
        (Stage::Encode { udp: true }, Reply::Bytes(b)) if b.len() > usize::from(dns::MAX_EDNS) => {
            Err("a UDP answer longer than 1232 bytes")
        }
        (Stage::Encode { .. }, _) => Ok(()),
    }
}

// ----- the codec (child) ----------------------------------------------------------------

/// The codec's answer to request `msg` (from the agent); None if it is no valid
/// request.
fn handle(msg: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(msg);
    let kind = r.u8().ok()?;
    let tag = r.u32().ok()?;
    let reply = match kind {
        DECODE => {
            let query = r.rest();
            if query.len() > MAX_QUERY {
                return None;
            }
            match dns::parse_query(query) {
                Ok(q) => Reply::Question(Question {
                    opcode: q.header.opcode(),
                    qtype: q.question.qtype,
                    qclass: q.question.qclass,
                    name: q.question.name.text(),
                }),
                Err(dns::QueryError::Ignore) => Reply::Ignore,
                Err(dns::QueryError::Malformed(h)) => {
                    Reply::Bytes(dns::build_error(&h, dns::FORMERR))
                }
            }
        }
        ENCODE => {
            let udp = match r.u8().ok()? {
                0 => false,
                1 => true,
                _ => return None,
            };
            let rcode = r.u8().ok()?;
            let n = usize::from(r.u16().ok()?);
            if n > MAX_RECORDS || rcode > 15 {
                return None;
            }
            let mut answers = Vec::with_capacity(n);
            for _ in 0..n {
                let ttl = r.u32().ok()?;
                let kind = r.u8().ok()?;
                let name = r.name().ok()?;
                let data = match kind {
                    RECORD_A => {
                        let b = r.take(4).ok()?;
                        AnswerData::A(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
                    }
                    RECORD_CNAME => AnswerData::Cname(r.name().ok()?),
                    _ => return None,
                };
                answers.push(Answer { name, ttl, data });
            }
            let query = r.rest();
            if query.len() > MAX_QUERY {
                return None;
            }
            match dns::parse_query(query) {
                Ok(q) => {
                    let limit = if udp { q.udp_limit() } else { 65535 };
                    Reply::Bytes(dns::build_response(&q, rcode, &answers, limit))
                }
                Err(_) => Reply::Ignore,
            }
        }
        _ => return None,
    };
    Some(reply_message(tag, &reply))
}

/// Serves requests on `io` until it closes (0) or sends something that is no request
/// (1).
fn serve(io: &mut (impl std::io::Read + std::io::Write)) -> i32 {
    let mut len = [0u8; 4];
    loop {
        match io.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return 0,
            Err(_) => return 1,
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_REQUEST {
            return 1;
        }
        let mut msg = vec![0u8; n];
        if io.read_exact(&mut msg).is_err() {
            return 1;
        }
        let Some(out) = handle(&msg) else { return 1 };
        let mut framed = (out.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&out);
        if io.write_all(&framed).is_err() {
            return 0;
        }
    }
}

/// `orbd dns-codec`: serves the agent on stdin (a unix socket) under the codec's
/// seccomp filter; its exit code.
#[cfg(target_os = "linux")]
pub fn child_main() -> i32 {
    use nix::libc;
    use std::os::fd::FromRawFd;
    // SAFETY: fstat of stdin into a zeroed struct.
    let socket = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        libc::fstat(0, &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFSOCK
    };
    if !socket {
        eprintln!("orbd dns-codec: run by the agent only (stdin must be its socket)");
        return 2;
    }
    // SAFETY: plain prctl; the jail set it already, an unjailed codec needs it to take
    // a filter.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        eprintln!(
            "orbd dns-codec: no_new_privs: {}",
            std::io::Error::last_os_error()
        );
        return 2;
    }
    // Bounded (32 MiB of its own memory, the binary's mapping aside; killed by the
    // kernel after a CPU minute, and started again), at the lowest priority, and
    // undumpable (its memory holds its orb's queries).
    let limits = [
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_DATA, 32 << 20),
        (libc::RLIMIT_AS, 512 << 20),
        (libc::RLIMIT_CPU, 60),
    ];
    for (resource, max) in limits {
        let l = libc::rlimit {
            rlim_cur: max,
            rlim_max: max,
        };
        // SAFETY: setrlimit and prctl with valid arguments.
        if unsafe { libc::setrlimit(resource, &l) } != 0 {
            eprintln!(
                "orbd dns-codec: rlimit: {}",
                std::io::Error::last_os_error()
            );
            return 2;
        }
    }
    // SAFETY: as above.
    if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 19) } != 0 {
        eprintln!("orbd dns-codec: nice: {}", std::io::Error::last_os_error());
        return 2;
    }
    // SAFETY: as above.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        eprintln!(
            "orbd dns-codec: dumpable: {}",
            std::io::Error::last_os_error()
        );
        return 2;
    }
    let pid = std::process::id();
    if let Err(e) = crate::seccomp::install(&crate::seccomp::codec_allowlist(pid), false) {
        eprintln!("orbd dns-codec: seccomp: {e}");
        return 2;
    }
    // SAFETY: stdin, owned by this process from here on.
    let mut io = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) });
    serve(&mut *io)
}

#[cfg(not(target_os = "linux"))]
pub fn child_main() -> i32 {
    eprintln!("orbd dns-codec: Linux only");
    2
}

// ----- the agent's side -----------------------------------------------------------------

struct Waiter {
    stage: Stage,
    /// None once its caller gave up: the answer is read and dropped.
    tx: Option<oneshot::Sender<Reply>>,
}

/// One running codec's connection.
struct Conn {
    frames: mpsc::Sender<Vec<u8>>,
    pending: Mutex<HashMap<u32, Waiter>>,
    next: AtomicU32,
    dead: CancellationToken,
    why: Mutex<Option<String>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Conn {
    /// Serves the agent's end of a codec's socket.
    fn new(stream: std::os::unix::net::UnixStream) -> std::io::Result<Arc<Self>> {
        stream.set_nonblocking(true)?;
        let (read, write) = tokio::net::UnixStream::from_std(stream)?.into_split();
        let (frames, rx) = mpsc::channel(MAX_PENDING);
        let conn = Arc::new(Self {
            frames,
            pending: Mutex::new(HashMap::new()),
            next: AtomicU32::new(1),
            dead: CancellationToken::new(),
            why: Mutex::new(None),
        });
        tokio::spawn(writer(write, rx, conn.clone()));
        tokio::spawn(reader(read, conn.clone()));
        Ok(conn)
    }

    /// Marks the connection dead (the first reason counts); its codec is then killed.
    fn kill(&self, why: impl Into<String>) {
        let mut w = lock(&self.why);
        if w.is_none() {
            *w = Some(why.into());
        }
        drop(w);
        self.dead.cancel();
        lock(&self.pending).clear();
    }

    fn why(&self) -> String {
        lock(&self.why)
            .clone()
            .unwrap_or_else(|| "it exited".into())
    }
}

/// For a caller that goes away before its answer: its request is forgotten if it was
/// never queued, else marked abandoned (its answer is read and dropped).
struct Abandon<'a> {
    conn: &'a Conn,
    tag: u32,
    queued: bool,
}

impl Drop for Abandon<'_> {
    fn drop(&mut self) {
        let mut pending = lock(&self.conn.pending);
        if !self.queued {
            pending.remove(&self.tag);
        } else if let Some(w) = pending.get_mut(&self.tag) {
            w.tx = None;
        }
    }
}

async fn writer(
    mut w: tokio::net::unix::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Vec<u8>>,
    conn: Arc<Conn>,
) {
    loop {
        let frame = tokio::select! {
            _ = conn.dead.cancelled() => return,
            f = rx.recv() => match f {
                Some(f) => f,
                None => return,
            },
        };
        if let Err(e) = w.write_all(&frame).await {
            conn.kill(format!("writing to it: {e}"));
            return;
        }
    }
}

/// Reads one length-prefixed message of at most `max` bytes; None at the end.
async fn read_frame(
    r: &mut tokio::net::unix::OwnedReadHalf,
    max: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("reading from it: {e}")),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > max {
        return Err(format!("a message of {n} bytes"));
    }
    let mut msg = vec![0u8; n];
    r.read_exact(&mut msg)
        .await
        .map_err(|e| format!("reading from it: {e}"))?;
    Ok(Some(msg))
}

async fn reader(mut r: tokio::net::unix::OwnedReadHalf, conn: Arc<Conn>) {
    let why = loop {
        let frame = tokio::select! {
            _ = conn.dead.cancelled() => return,
            f = read_frame(&mut r, MAX_REPLY) => f,
        };
        let frame = match frame {
            Ok(Some(f)) => f,
            Ok(None) => break "it closed its socket".to_owned(),
            Err(e) => break e,
        };
        let (tag, reply) = match parse_reply(&frame) {
            Ok(x) => x,
            Err(e) => break format!("it sent {e}"),
        };
        let Some(w) = lock(&conn.pending).remove(&tag) else {
            break format!("it answered request {tag}, which is not pending");
        };
        if let Err(e) = fits(w.stage, &reply) {
            break format!("it sent {e}");
        }
        if let Some(tx) = w.tx {
            let _ = tx.send(reply);
        }
    };
    conn.kill(why);
}

/// The agent's handle on a codec, kept running by its supervisor until [`Codec::stop`]:
/// requests go to the codec that runs, waiting up to [`CODEC_TIMEOUT`] for one that is
/// starting.
#[derive(Clone)]
pub struct Codec {
    current: Arc<Mutex<Option<Arc<Conn>>>>,
    up: Arc<tokio::sync::Notify>,
    stopped: CancellationToken,
}

impl Codec {
    fn new() -> Self {
        Self {
            current: Arc::new(Mutex::new(None)),
            up: Arc::new(tokio::sync::Notify::new()),
            stopped: CancellationToken::new(),
        }
    }

    fn conn(&self) -> Option<Arc<Conn>> {
        lock(&self.current)
            .clone()
            .filter(|c| !c.dead.is_cancelled())
    }

    /// Makes `conn` the running codec's.
    fn set(&self, conn: Option<Arc<Conn>>) {
        let up = conn.is_some();
        *lock(&self.current) = conn;
        if up {
            self.up.notify_waiters();
        }
    }

    /// Stops the codec for good: its process is killed, requests get nothing.
    pub fn stop(&self) {
        self.stopped.cancel();
        if let Some(c) = lock(&self.current).take() {
            c.kill("stopped");
        }
    }

    /// The running codec's connection, waiting up to [`CODEC_TIMEOUT`] for one.
    async fn running(&self) -> Option<Arc<Conn>> {
        let deadline = tokio::time::Instant::now() + CODEC_TIMEOUT;
        loop {
            let up = self.up.notified();
            if let Some(c) = self.conn() {
                return Some(c);
            }
            if self.stopped.is_cancelled() || tokio::time::timeout_at(deadline, up).await.is_err() {
                return None;
            }
        }
    }

    async fn call(&self, stage: Stage, build: impl FnOnce(u32) -> Vec<u8>) -> Option<Reply> {
        let conn = self.running().await?;
        let tag = conn.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut p = lock(&conn.pending);
            if p.len() >= MAX_PENDING {
                drop(p);
                conn.kill(format!("it left {MAX_PENDING} requests unanswered"));
                return None;
            }
            p.insert(
                tag,
                Waiter {
                    stage,
                    tx: Some(tx),
                },
            );
        }
        let mut abandon = Abandon {
            conn: &conn,
            tag,
            queued: false,
        };
        // Killed meanwhile: the kill cleared the requests before this one was added.
        if conn.dead.is_cancelled() {
            return None;
        }
        let mut frame = Vec::new();
        let msg = build(tag);
        frame.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        frame.extend_from_slice(&msg);
        let exchange = async {
            conn.frames.send(frame).await.ok()?;
            abandon.queued = true;
            rx.await.ok()
        };
        match tokio::time::timeout(CODEC_TIMEOUT, exchange).await {
            Ok(r) => r,
            Err(_) => {
                conn.kill(format!("it did not answer within {CODEC_TIMEOUT:?}"));
                None
            }
        }
    }

    /// What `query` (from an orb, at most [`MAX_QUERY`] bytes) is; None without a
    /// codec.
    pub async fn decode(&self, query: &[u8]) -> Option<Decoded> {
        if query.len() > MAX_QUERY {
            return Some(Decoded::Ignore);
        }
        match self
            .call(Stage::Decode, |tag| decode_request(tag, query))
            .await?
        {
            Reply::Question(q) => Some(Decoded::Question(q)),
            Reply::Bytes(b) => Some(Decoded::Reply(b)),
            Reply::Ignore => Some(Decoded::Ignore),
        }
    }

    /// The answer to `query` with `rcode` and `answers` (over UDP: as large as the query
    /// allows, at most 1232 bytes); None without a codec, or for no answer.
    pub async fn encode(
        &self,
        query: &[u8],
        udp: bool,
        rcode: u8,
        answers: &[Answer],
    ) -> Option<Vec<u8>> {
        if answers.len() > MAX_RECORDS {
            return None;
        }
        match self
            .call(Stage::Encode { udp }, |tag| {
                encode_request(tag, query, udp, rcode, answers)
            })
            .await?
        {
            Reply::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

/// A started codec: the agent's end of its socket and the process (None for one run on a
/// thread, in tests).
pub struct Spawned {
    pub stream: std::os::unix::net::UnixStream,
    pub child: Option<tokio::process::Child>,
}

/// Starts a codec.
pub type Spawn = Box<dyn FnMut() -> Result<Spawned, String> + Send>;

struct Running {
    conn: Arc<Conn>,
    child: Option<tokio::process::Child>,
}

impl Running {
    /// Waits until the codec stops (its connection dies or it exits), kills it and says
    /// why it stopped.
    async fn stopped(mut self) -> String {
        let exited = match &mut self.child {
            Some(c) => tokio::select! {
                _ = self.conn.dead.cancelled() => None,
                s = c.wait() => Some(s),
            },
            None => {
                self.conn.dead.cancelled().await;
                None
            }
        };
        self.conn.kill("it exited");
        let status = match (exited, &mut self.child) {
            (Some(s), _) => s.ok(),
            (None, Some(c)) => {
                let _ = c.start_kill();
                c.wait().await.ok()
            }
            (None, None) => None,
        };
        match status {
            Some(s) => format!("{} ({s})", self.conn.why()),
            None => self.conn.why(),
        }
    }
}

impl Drop for Running {
    /// A supervisor stopped or dropped mid-wait: the connection dies (and the process
    /// with it, `kill_on_drop`).
    fn drop(&mut self) {
        self.conn.kill("stopped");
    }
}

/// Starts a codec with `spawn` and checks it answers.
async fn launch(spawn: &mut Spawn, codec: &Codec) -> Result<Running, String> {
    let s = spawn()?;
    let conn = Conn::new(s.stream).map_err(|e| format!("its socket: {e}"))?;
    let running = Running {
        conn: conn.clone(),
        child: s.child,
    };
    // Only this self-test talks to it before it is published.
    let probe = Codec::new();
    probe.set(Some(conn.clone()));
    let query = dns::build_query(0x0dc0, "self-test.orbd.invalid", dns::TYPE_A, None);
    let decoded = probe.decode(&query).await;
    let answer = probe.encode(&query, true, dns::NXDOMAIN, &[]).await;
    let ok = matches!(&decoded, Some(Decoded::Question(q))
            if q.name.as_deref() == Some("self-test.orbd.invalid"))
        && answer
            .as_deref()
            .is_some_and(|a| a.len() >= dns::HEADER && a[..2] == [0x0d, 0xc0]);
    if !ok {
        conn.kill("its self-test failed");
        let why = running.stopped().await;
        return Err(format!("the DNS codec did not answer its self-test: {why}"));
    }
    codec.set(Some(conn));
    Ok(running)
}

/// Keeps a codec running for `codec` (labelled `label` in logs) until it is stopped:
/// `running` first, if given; one that stops is started again after 0.1 s, doubling up
/// to 10 s while it keeps stopping.
fn supervise(mut spawn: Spawn, codec: Codec, mut running: Option<Running>, label: String) {
    tokio::spawn(async move {
        let mut backoff = MIN_BACKOFF;
        let mut first = running.is_none();
        loop {
            if let Some(r) = running.take() {
                let up = Instant::now();
                let why = tokio::select! {
                    why = r.stopped() => why,
                    // Dropping the wait kills the codec.
                    _ = codec.stopped.cancelled() => return,
                };
                if codec.stopped.is_cancelled() {
                    return;
                }
                codec.set(None);
                if up.elapsed() >= STABLE {
                    backoff = MIN_BACKOFF;
                }
                metrics::counter!("orbd_egress_dns_codec_restarts_total").increment(1);
                tracing::error!(
                    target: "orbd::egress",
                    codec = %label,
                    why = %why,
                    retry_in = ?backoff,
                    "restricted egress: the DNS codec stopped; its orb gets no DNS answers until it runs again"
                );
            }
            if !first {
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = codec.stopped.cancelled() => return,
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            let restarted = !first;
            first = false;
            let launched = tokio::select! {
                l = launch(&mut spawn, &codec) => l,
                _ = codec.stopped.cancelled() => return,
            };
            match launched {
                // Stopped while it started: the codec is dropped, so killed.
                Ok(_) if codec.stopped.is_cancelled() => return,
                Ok(r) => {
                    if restarted {
                        tracing::info!(target: "orbd::egress", codec = %label, "restricted egress: the DNS codec runs again");
                    }
                    running = Some(r);
                }
                Err(e) => tracing::error!(
                    target: "orbd::egress",
                    codec = %label,
                    error = %e,
                    retry_in = ?backoff,
                    "restricted egress: the DNS codec did not start"
                ),
            }
        }
    });
}

/// Starts a codec with `spawn`, failing if it does not answer, and keeps one running
/// (see [`run`]).
pub async fn start(mut spawn: Spawn, label: &str) -> Result<Codec, String> {
    let codec = Codec::new();
    let running = launch(&mut spawn, &codec).await?;
    supervise(spawn, codec.clone(), Some(running), label.to_owned());
    Ok(codec)
}

/// Keeps a codec started with `spawn` running until it is stopped: one that stops is
/// started again after 0.1 s, doubling up to 10 s while it keeps stopping. Requests
/// wait for the first one.
pub fn run(spawn: Spawn, label: &str) -> Codec {
    let codec = Codec::new();
    supervise(spawn, codec.clone(), None, label.to_owned());
    codec
}

/// Where the codec's binary is in its jail.
pub const JAILED_EXE: &str = "/orbd";

/// A factory of [`Spawn`]s: one per codec.
pub type Spawner = Arc<dyn Fn() -> Spawn + Send + Sync>;

/// Starts codecs with `dns-codec`: in `jail`, whose binary is at [`JAILED_EXE`], or
/// unjailed without one as the agent's own binary (`/proc/self/exe`), with every
/// descriptor beyond stdio closed.
#[cfg(target_os = "linux")]
pub fn process_spawner(jail: Option<orbd_vm::jail::Jail>) -> Spawner {
    use std::process::Stdio;
    Arc::new(move || {
        let jail = jail.clone();
        Box::new(move || {
            let (agent, codec) =
                std::os::unix::net::UnixStream::pair().map_err(|e| format!("socket pair: {e}"))?;
            let mut cmd = match &jail {
                Some(j) => orbd_vm::jail::command(j, std::path::Path::new(JAILED_EXE))
                    .map_err(|e| format!("the DNS codec's jail: {e}"))?,
                None => {
                    use std::os::unix::process::CommandExt;
                    let mut c = std::process::Command::new("/proc/self/exe");
                    c.env_clear();
                    // SAFETY: close_range only, between fork and exec.
                    unsafe {
                        c.pre_exec(|| {
                            nix::libc::syscall(
                                nix::libc::SYS_close_range,
                                3 as nix::libc::c_uint,
                                nix::libc::c_uint::MAX,
                                nix::libc::CLOSE_RANGE_CLOEXEC,
                            );
                            Ok(())
                        });
                    }
                    c
                }
            };
            cmd.arg(SUBCOMMAND)
                .stdin(Stdio::from(std::os::fd::OwnedFd::from(codec)))
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            let mut child = tokio::process::Command::from(cmd)
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| format!("starting the DNS codec: {e}"))?;
            if let Some(err) = child.stderr.take() {
                tokio::spawn(log_stderr(err));
            }
            Ok(Spawned {
                stream: agent,
                child: Some(child),
            })
        })
    })
}

/// Logs what a codec writes to stderr (its jail's or its own errors) as data: lines of
/// at most 1 KiB, the first [`MAX_STDERR`] bytes of each codec, within one budget for
/// all codecs of this agent (16 KiB, refilled at 1 KiB a minute, each line costing at
/// least 64 bytes). Past its share the codec's stderr is closed: its writes fail.
#[cfg(target_os = "linux")]
async fn log_stderr(mut err: tokio::process::ChildStderr) {
    static BUDGET: Mutex<Option<(f64, Instant)>> = Mutex::new(None);
    const ALL: f64 = 16.0 * 1024.0;
    let emit = |line: &[u8]| {
        let cost = (line.len() + 1).max(64) as f64;
        let mut b = lock(&BUDGET);
        let now = Instant::now();
        let (tokens, at) = b.unwrap_or((ALL, now));
        let tokens = (tokens + now.duration_since(at).as_secs_f64() * 1024.0 / 60.0).min(ALL);
        let ok = tokens >= cost;
        *b = Some((if ok { tokens - cost } else { tokens }, now));
        drop(b);
        if ok {
            let line = String::from_utf8_lossy(line);
            tracing::warn!(target: "orbd::egress", line = %line.escape_debug(), "restricted egress: the DNS codec wrote");
        }
    };
    let mut buf = [0u8; 4096];
    let mut line = Vec::with_capacity(1024);
    let mut read = 0;
    while read < MAX_STDERR {
        let n = match err.read(&mut buf).await {
            Ok(n @ 1..) => n.min(MAX_STDERR - read),
            _ => break,
        };
        read += n;
        for part in buf[..n].split_inclusive(|b| *b == b'\n') {
            let (text, end) = match part.split_last() {
                Some((b'\n', text)) => (text, true),
                _ => (part, false),
            };
            let room = 1024 - line.len();
            line.extend_from_slice(&text[..text.len().min(room)]);
            if end || line.len() == 1024 {
                emit(&line);
                line.clear();
            }
        }
    }
    if !line.is_empty() {
        emit(&line);
    }
}

/// Starts codecs on threads of this process, as tests do.
pub fn thread_spawner() -> Spawner {
    Arc::new(|| {
        Box::new(|| {
            let (agent, codec) =
                std::os::unix::net::UnixStream::pair().map_err(|e| format!("socket pair: {e}"))?;
            std::thread::Builder::new()
                .name("orbd-dns-codec".into())
                .spawn(move || {
                    let mut codec = codec;
                    serve(&mut codec)
                })
                .map_err(|e| e.to_string())?;
            Ok(Spawned {
                stream: agent,
                child: None,
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{TYPE_A, build_query, parse_response};
    use std::net::Ipv4Addr;

    fn question(name: Option<&str>) -> Reply {
        Reply::Question(Question {
            opcode: 0,
            qtype: TYPE_A,
            qclass: dns::CLASS_IN,
            name: name.map(str::to_owned),
        })
    }

    #[test]
    fn messages_round_trip() {
        for r in [
            question(Some("www.example.com")),
            question(None),
            Reply::Bytes(vec![7; 12]),
            Reply::Bytes(vec![7; 65535]),
            Reply::Ignore,
        ] {
            assert_eq!(parse_reply(&reply_message(42, &r)), Ok((42, r)));
        }
    }

    /// Messages from the codec are read strictly: anything malformed, oversized, out of
    /// range or with bytes left over is refused.
    #[test]
    fn hostile_replies_are_refused() {
        let ok = reply_message(1, &question(Some("a.example")));
        let mut bad: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("no tag", vec![QUESTION, 0, 0]),
            ("unknown kind", vec![9, 0, 0, 0, 1]),
            ("trailing", [ok.clone(), vec![0]].concat()),
            ("truncated", ok[..ok.len() - 1].to_vec()),
            ("ignore with data", vec![IGNORE, 0, 0, 0, 1, 0]),
            (
                "runt reply",
                [vec![REPLY, 0, 0, 0, 1], vec![0; 11]].concat(),
            ),
            (
                "huge reply",
                [vec![REPLY, 0, 0, 0, 1], vec![0; 65536]].concat(),
            ),
        ];
        let q = |opcode: u8, name: &[u8]| {
            let mut m = vec![QUESTION, 0, 0, 0, 1, opcode, 0, 1, 0, 1, name.len() as u8];
            m.extend_from_slice(name);
            m
        };
        bad.push(("opcode", q(16, b"a.example")));
        for (what, name) in [
            ("uppercase", &b"A.example"[..]),
            ("trailing dot", b"a.example."),
            ("not a hostname", b"a b.example"),
            ("empty label", b"a..example"),
            ("non-ASCII", b"\xc3\xa9.example"),
            ("NUL", b"a\0.example"),
            ("dash first", b"-a.example"),
        ] {
            bad.push((what, q(0, name)));
        }
        // 254 bytes: one too long, its length still fits the length byte.
        let long = format!("{}.{}", vec!["a".repeat(63); 3].join("."), "b".repeat(62));
        assert_eq!(long.len(), 254);
        bad.push(("longer than 253", q(0, long.as_bytes())));
        for (what, m) in bad {
            assert!(parse_reply(&m).is_err(), "{what}: {m:?}");
        }
        // A question may not answer an encode, nor a UDP answer exceed 1232 bytes.
        assert!(fits(Stage::Encode { udp: false }, &question(Some("a.example"))).is_err());
        assert!(fits(Stage::Encode { udp: true }, &Reply::Bytes(vec![0; 1233])).is_err());
        assert!(fits(Stage::Encode { udp: false }, &Reply::Bytes(vec![0; 1233])).is_ok());
        assert!(fits(Stage::Decode, &Reply::Bytes(vec![0; 12])).is_ok());
        assert!(fits(Stage::Decode, &Reply::Bytes(vec![0; 13])).is_err());
    }

    /// The codec decodes queries and builds answers from the agent's records; it refuses
    /// requests that are not valid (it is then stopped).
    #[test]
    fn the_codec_decodes_and_encodes() {
        let q = build_query(9, "WWW.Example.com", TYPE_A, Some(1232));
        let (tag, r) = parse_reply(&handle(&decode_request(5, &q)).unwrap()).unwrap();
        assert_eq!((tag, r), (5, question(Some("www.example.com"))));
        // Not a hostname; malformed (FORMERR); not a query.
        let odd = build_query(9, "a*b.example", TYPE_A, None);
        assert_eq!(
            parse_reply(&handle(&decode_request(1, &odd)).unwrap())
                .unwrap()
                .1,
            question(None)
        );
        let mut two = q.clone();
        two[5] = 2;
        let (_, r) = parse_reply(&handle(&decode_request(1, &two)).unwrap()).unwrap();
        assert!(
            matches!(&r, Reply::Bytes(b) if dns::Header::parse(b).unwrap().rcode() == dns::FORMERR)
        );
        assert_eq!(
            parse_reply(&handle(&decode_request(1, &[1, 2, 3])).unwrap())
                .unwrap()
                .1,
            Reply::Ignore
        );
        let answers = vec![
            Answer {
                name: "www.example.com".into(),
                ttl: 60,
                data: AnswerData::Cname("edge.cdn.example".into()),
            },
            Answer {
                name: "edge.cdn.example".into(),
                ttl: 60,
                data: AnswerData::A(Ipv4Addr::new(34, 1, 2, 3)),
            },
        ];
        let m = handle(&encode_request(6, &q, true, dns::NOERROR, &answers)).unwrap();
        let (tag, Reply::Bytes(b)) = parse_reply(&m).unwrap() else {
            panic!("no answer")
        };
        assert_eq!(tag, 6);
        let r = parse_response(&b).unwrap();
        assert!(r.answers_query(9, "www.example.com", TYPE_A));
        let (chain, addrs) = dns::answer_chain("www.example.com", &r.answers);
        assert_eq!(chain.len(), 1);
        assert_eq!(addrs, vec![(Ipv4Addr::new(34, 1, 2, 3), 60)]);
        // UDP answers fit the query's size; over TCP all of it.
        let many: Vec<Answer> = (0..200)
            .map(|i| Answer {
                name: "www.example.com".into(),
                ttl: 60,
                data: AnswerData::A(Ipv4Addr::new(34, 0, 0, i as u8)),
            })
            .collect();
        let small = build_query(9, "www.example.com", TYPE_A, None);
        let udp = handle(&encode_request(7, &small, true, dns::NOERROR, &many)).unwrap();
        let tcp = handle(&encode_request(7, &small, false, dns::NOERROR, &many)).unwrap();
        assert!(udp.len() <= 5 + 512 && tcp.len() > 5 + 1232);
        // Invalid requests.
        for bad in [
            vec![],
            vec![DECODE, 0, 0],
            vec![9, 0, 0, 0, 1],
            [vec![DECODE, 0, 0, 0, 1], vec![0; MAX_QUERY + 1]].concat(),
            [vec![ENCODE, 0, 0, 0, 1, 2, 0, 0, 0], q.clone()].concat(),
            [vec![ENCODE, 0, 0, 0, 1, 1, 16, 0, 0], q.clone()].concat(),
            [vec![ENCODE, 0, 0, 0, 1, 1, 0, 0xff, 0xff], q.clone()].concat(),
            [
                vec![ENCODE, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 3],
                b"A.B".to_vec(),
                vec![1, 2, 3, 4],
            ]
            .concat(),
            [
                vec![ENCODE, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 7, 1, b'a'],
                vec![1, 2, 3, 4],
            ]
            .concat(),
        ] {
            assert_eq!(handle(&bad), None, "{bad:?}");
        }
        // Over its socket: framed; a message it cannot read ends it with 1, the end of
        // the socket with 0.
        let mut io = std::io::Cursor::new(Vec::new());
        assert_eq!(serve(&mut io), 0);
        let framed = |m: &[u8]| [(m.len() as u32).to_be_bytes().to_vec(), m.to_vec()].concat();
        let mut io = Duplex(
            std::io::Cursor::new(framed(&decode_request(3, &q))),
            Vec::new(),
        );
        assert_eq!(serve(&mut io), 0);
        let (len, msg) = io.1.split_at(4);
        assert_eq!(
            u32::from_be_bytes(len.try_into().unwrap()) as usize,
            msg.len()
        );
        assert_eq!(parse_reply(msg).unwrap().0, 3);
        for bad in [
            vec![0, 0, 0, 0],
            (MAX_REQUEST as u32 + 1).to_be_bytes().to_vec(),
            framed(&[9]),
        ] {
            let mut io = Duplex(std::io::Cursor::new(bad), Vec::new());
            assert_eq!(serve(&mut io), 1);
        }
    }

    struct Duplex(std::io::Cursor<Vec<u8>>, Vec<u8>);

    impl std::io::Read for Duplex {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.0, b)
        }
    }

    impl std::io::Write for Duplex {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            std::io::Write::write(&mut self.1, b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What a fake codec sends for a request: raw bytes, framed or not; None for nothing.
    type Respond = fn(&[u8]) -> Option<Vec<u8>>;

    /// A fake codec on a thread that answers with `respond` (given each request): one
    /// started per spawn, counted.
    fn fake(respond: Respond) -> (Spawn, Arc<std::sync::atomic::AtomicUsize>) {
        let spawns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n = spawns.clone();
        let spawn: Spawn = Box::new(move || {
            n.fetch_add(1, Ordering::SeqCst);
            let (agent, mut codec) = std::os::unix::net::UnixStream::pair().unwrap();
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                loop {
                    let mut len = [0u8; 4];
                    if codec.read_exact(&mut len).is_err() {
                        return;
                    }
                    let mut m = vec![0u8; u32::from_be_bytes(len) as usize];
                    if codec.read_exact(&mut m).is_err() {
                        return;
                    }
                    let Some(out) = respond(&m) else { continue };
                    let _ = codec.write_all(&out);
                }
            });
            Ok(Spawned {
                stream: agent,
                child: None,
            })
        });
        (spawn, spawns)
    }

    fn framed(m: Vec<u8>) -> Vec<u8> {
        [(m.len() as u32).to_be_bytes().to_vec(), m].concat()
    }

    /// The real codec on a thread: decodes and encodes through its socket.
    #[tokio::test]
    async fn the_agent_talks_to_the_codec() {
        let codec = start(thread_spawner()(), "test").await.unwrap();
        let q = build_query(1, "a.example", TYPE_A, None);
        assert_eq!(
            codec.decode(&q).await,
            Some(Decoded::Question(Question {
                opcode: 0,
                qtype: TYPE_A,
                qclass: dns::CLASS_IN,
                name: Some("a.example".into())
            }))
        );
        let a = codec.encode(&q, true, dns::NXDOMAIN, &[]).await.unwrap();
        assert_eq!(dns::Header::parse(&a).unwrap().rcode(), dns::NXDOMAIN);
        // Concurrent requests each get their own answer.
        let names: Vec<String> = (0..64).map(|i| format!("n{i}.example")).collect();
        let answers = futures::future::join_all(names.iter().map(|n| {
            let codec = codec.clone();
            async move {
                let q = build_query(2, n, TYPE_A, None);
                codec.decode(&q).await
            }
        }))
        .await;
        for (n, a) in names.iter().zip(answers) {
            assert!(matches!(a, Some(Decoded::Question(q)) if q.name.as_deref() == Some(n)));
        }
    }

    /// A codec that misbehaves (garbage, an answer to a request never sent, an answer
    /// too large for UDP, silence) is stopped, its requests get nothing, and another is
    /// started.
    #[tokio::test]
    async fn a_misbehaving_codec_is_replaced() {
        fn tag(m: &[u8]) -> u32 {
            u32::from_be_bytes(m[1..5].try_into().unwrap())
        }
        let cases: Vec<(&str, Respond)> = vec![
            ("garbage", |_| Some(vec![1, 2, 3, 4, 5, 6, 7, 8])),
            ("oversized", |_| {
                Some((MAX_REPLY as u32 + 1).to_be_bytes().to_vec())
            }),
            ("unknown tag", |m| {
                Some(framed(reply_message(tag(m) + 1000, &Reply::Ignore)))
            }),
            ("bad name", |m| {
                let mut r = reply_message(tag(m), &question(Some("a.example")));
                let n = r.len();
                r[n - 1] = b'!';
                Some(framed(r))
            }),
            ("huge UDP answer", |m| {
                let r = match m[0] {
                    DECODE => question(Some("self-test.orbd.invalid")),
                    _ => Reply::Bytes(vec![0x0d; 1300]),
                };
                Some(framed(reply_message(tag(m), &r)))
            }),
            ("silent", |_| None),
        ];
        for (what, respond) in cases {
            let (spawn, spawns) = fake(respond);
            let started = start(spawn, "test").await;
            assert!(started.is_err(), "{what}: its self-test passed");
            assert_eq!(spawns.load(Ordering::SeqCst), 1, "{what}");
        }
        // One that passes its self-test, then misbehaves: killed and replaced.
        let (spawn, spawns) = fake(|m| {
            let t = tag(m);
            let r = if m[0] == DECODE {
                if m.len() > 5 + 12 && m[5..7] == [0x0d, 0xc0] {
                    question(Some("self-test.orbd.invalid"))
                } else {
                    // Any other query: an answer that is no valid message.
                    return Some(framed(vec![QUESTION, 0, 0, 0, 0]));
                }
            } else {
                let mut b = vec![0u8; 12];
                b[..2].copy_from_slice(&[0x0d, 0xc0]);
                Reply::Bytes(b)
            };
            Some(framed(reply_message(t, &r)))
        });
        let codec = start(spawn, "test").await.unwrap();
        assert_eq!(spawns.load(Ordering::SeqCst), 1);
        let q = build_query(1, "a.example", TYPE_A, None);
        assert_eq!(
            codec.decode(&q).await,
            None,
            "no answer from a codec that broke"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while spawns.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline, "not started again");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A query cancelled while the codec works on it leaves nothing behind: the late
    /// answer is read and dropped, and the codec keeps serving.
    #[tokio::test]
    async fn a_cancelled_request_is_dropped_when_answered() {
        let (spawn, spawns) = fake(|m| {
            std::thread::sleep(Duration::from_millis(if m[5..7] == [0x0d, 0xc0] {
                0
            } else {
                300
            }));
            let t = u32::from_be_bytes(m[1..5].try_into().unwrap());
            Some(framed(
                handle(m).unwrap_or_else(|| reply_message(t, &Reply::Ignore)),
            ))
        });
        let codec = start(spawn, "test").await.unwrap();
        let q = build_query(1, "slow.example", TYPE_A, None);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), codec.decode(&q))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        let q = build_query(0x0dc0, "b.example", TYPE_A, None);
        assert!(matches!(codec.decode(&q).await, Some(Decoded::Question(_))));
        assert_eq!(spawns.load(Ordering::SeqCst), 1, "still the first codec");
    }

    /// A codec run on demand answers its first request once it is up; stopped, it gets
    /// no more requests and its supervisor starts none again.
    #[tokio::test]
    async fn a_run_codec_answers_until_stopped() {
        let (spawn, spawns) = fake(|m| Some(framed(handle(m).unwrap())));
        let codec = run(spawn, "test");
        let q = build_query(1, "a.example", TYPE_A, None);
        assert!(matches!(codec.decode(&q).await, Some(Decoded::Question(_))));
        codec.stop();
        assert_eq!(codec.decode(&q).await, None);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(spawns.load(Ordering::SeqCst), 1, "not started again");
    }

    /// A codec flooding stderr is read only up to its share, then its stderr is closed:
    /// the agent stops reading at once and the codec's writes fail.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_codec_flooding_stderr_is_cut_off() {
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "head -c 10000000 /dev/zero | tr '\\0' '\\n' >&2"])
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let err = child.stderr.take().unwrap();
        tokio::time::timeout(Duration::from_secs(5), log_stderr(err))
            .await
            .expect("stopped reading");
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("the writer ended")
            .unwrap();
        assert!(!status.success(), "its writes failed: {status}");
    }
}
