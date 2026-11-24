//! Restricted egress (an orb type's `egress`, [`EgressPolicy`]) on a Linux agent: which
//! orbs are restricted, their nftables chains (rendered in [`super::net`]), and the DNS
//! proxy that resolves their allowlisted names and opens what it resolved.
//!
//! * An orb is restricted for life when its spec has a policy or its recipe a
//!   [`super::net::NetBackend::RestrictedTap`] (or it has a policy file): whatever a
//!   coordinator later sends, it never launches unrestricted. At every launch (create,
//!   cold boot, restore) its chain is installed with a fresh conntrack mark (only flows
//!   accepted under this launch count as established, so a flow of the index's earlier
//!   orb, or of this orb under an earlier policy, is decided again), and then
//!   `<state>/orbs/<orb>/egress.json` ([`Applied`]) records the policy and mark. The
//!   policy is the orb type's current one if the coordinator sent it, else the last one
//!   applied, else the one the orb was created with, else nothing. A launch that cannot
//!   be restricted fails. An unrestricted orb's launch removes whatever chain its index
//!   may still have.
//! * When a runtime starts, orbd's table is rendered with the chain of every restricted
//!   orb those files (or recipes) name, keeping the addresses their sets still hold, so a
//!   VMM that outlived an agent restart stays restricted and keeps working; an unreadable
//!   record restricts its orb to nothing. One agent per network namespace: the table is
//!   the namespace's (an abstract unix socket is the lock).
//! * The proxy listens on [`net::DNS_PROXY`] port 53 (UDP and TCP) on a thread of its
//!   own, and answers only restricted orbs, known by their veth address (which their
//!   traffic cannot fake: see `net`). What they send is read only by codecs
//!   ([`super::codec`]), jailed child processes, one per restricted orb's launch
//!   (started at its first query, stopped when the launch is over or after
//!   [`CODEC_IDLE`] without queries), which turn a query into its question and build the
//!   answer from the records the proxy decided on; the proxy itself only moves the
//!   bytes, and parses only its upstreams' answers. A name the orb's policy does not list gets
//!   NXDOMAIN and is never sent upstream. For a listed name, A queries go to the agent's
//!   DNS servers (`ORBD_DNS`) over UDP, then TCP when truncated, from a fresh port with
//!   a random id, to the next server on SERVFAIL or REFUSED; a response must match the
//!   query. The answer's CNAME chain is followed as returned for the listed name (its
//!   targets need not be listed: CDNs name their own hosts), and the addresses it ends
//!   at are opened for this orb's launch only, in its set `resolved<i>`, before the orb
//!   gets them: every record of the answer carries its lowest TTL, at most [`MAX_TTL`],
//!   and an address stays open for at least [`MIN_OPEN`], plus [`OPEN_GRACE`].
//!   Addresses that are private, link-local or otherwise never reachable
//!   ([`net::openable`]) are left out of the answer and never opened, whatever name they
//!   come from (DNS rebinding); the chain drops them too. Other query types for listed
//!   names get an empty answer (orbs have no IPv6). UDP answers fit 512 bytes, or the
//!   orb's EDNS size up to 1232: as many records as fit, with TC set.
//! * Bounds: [`MAX_INFLIGHT`] queries at once ([`MAX_INFLIGHT_PER_ORB`] per orb; UDP
//!   beyond them is dropped, so the orb retries), [`MAX_TCP`] TCP connections
//!   ([`MAX_TCP_PER_ORB`] per orb), each idle at most [`TCP_IDLE`], open at most
//!   [`TCP_LIFETIME`] and with at most [`TCP_QUERIES`] queries, every query answered
//!   within [`QUERY_BUDGET`] or not at all, [`MAX_OPEN_PER_ORB`] open addresses per orb
//!   (reserved before they are opened), and [`net::DNS_RATE`] packets a second per orb
//!   (in the input chain). Updates of the sets are batched into one `nft` run, checked
//!   against the orb's current launch under the same lock as launches and deletes.

use super::net::{self, NetAttachment, Restricted};
use crate::config::agent::Egress;
use crate::model::{EgressPolicy, OrbDefinition, OrbId};
use crate::runtime::RuntimeError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// The policy and mark a restricted orb last launched with, in its directory.
pub const POLICY_FILE: &str = "egress.json";
/// Longest TTL handed to orbs (seconds): they look names up again soon.
pub const MAX_TTL: u32 = 120;
/// Shortest time an address stays open (seconds), well past any answer's TTL.
pub const MIN_OPEN: u32 = 600;
/// How much longer than its TTL an address stays open (seconds).
pub const OPEN_GRACE: u32 = 30;
pub const MAX_INFLIGHT: usize = 256;
pub const MAX_INFLIGHT_PER_ORB: usize = 32;
pub const MAX_TCP: usize = 64;
pub const MAX_TCP_PER_ORB: usize = 4;
pub const TCP_IDLE: Duration = Duration::from_secs(10);
pub const TCP_LIFETIME: Duration = Duration::from_secs(30);
pub const TCP_QUERIES: usize = 32;
pub const QUERY_BUDGET: Duration = Duration::from_secs(5);
pub const MAX_OPEN_PER_ORB: usize = 1024;
/// Largest query read from an orb.
const MAX_QUERY: usize = super::codec::MAX_QUERY;
/// A restricted orb's codec stops after this long without queries (it starts again at
/// the next).
pub const CODEC_IDLE: Duration = Duration::from_secs(600);
/// UDP size advertised to upstream servers.
const EDNS_SIZE: u16 = 1232;
// Addresses outlive every answer that named them.
const _: () = assert!(MIN_OPEN > MAX_TTL);
const UPSTREAM_TRY: Duration = Duration::from_secs(2);
/// The abstract unix socket only one agent per network namespace may hold.
#[cfg(target_os = "linux")]
const NETNS_LOCK: &[u8] = b"orbd-agent";

/// What a restricted orb last launched with: `<orb>/egress.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applied {
    pub policy: EgressPolicy,
    /// The conntrack mark of its flows.
    pub mark: u32,
}

/// An address in an orb's set: until when, and whether `nft` has confirmed it (an
/// unconfirmed one is reserved by a query in flight).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Opened {
    until: Instant,
    confirmed: bool,
}

struct OrbEntry {
    orb: OrbId,
    /// Unique per launch (and per agent start): a query of an earlier one opens nothing.
    launch: u64,
    policy: Arc<EgressPolicy>,
    opened: HashMap<Ipv4Addr, Opened>,
    inflight: usize,
    tcp: usize,
    /// Log budget (tokens, last refill).
    log: (f64, Instant),
}

static LAUNCHES: AtomicU64 = AtomicU64::new(1);

impl OrbEntry {
    fn new(orb: OrbId, policy: EgressPolicy, opened: HashMap<Ipv4Addr, Opened>) -> Self {
        Self {
            orb,
            launch: LAUNCHES.fetch_add(1, Ordering::Relaxed),
            policy: Arc::new(policy),
            opened,
            inflight: 0,
            tcp: 0,
            log: (LOG_BURST, Instant::now()),
        }
    }

    /// Whether to log one more event for this orb (a few a second).
    fn may_log(&mut self) -> bool {
        let now = Instant::now();
        let (tokens, at) = self.log;
        let tokens =
            (tokens + now.saturating_duration_since(at).as_secs_f64() * LOG_RATE).min(LOG_BURST);
        let ok = tokens >= 1.0;
        self.log = (if ok { tokens - 1.0 } else { tokens }, now);
        ok
    }
}

const LOG_RATE: f64 = 2.0;
const LOG_BURST: f64 = 20.0;

/// Restricted orbs on this agent, by network index.
static ORBS: Mutex<BTreeMap<u32, OrbEntry>> = Mutex::new(BTreeMap::new());
/// Whether the DNS proxy runs (or why not); set by the first [`prepare`].
static PROXY: OnceLock<Result<(), String>> = OnceLock::new();
/// The agent's own egress settings, which restricted orbs' private `allow` rules must
/// also pass.
static AGENT: Mutex<Option<Egress>> = Mutex::new(None);
/// Held while restricted orbs' chains and sets change together with [`ORBS`]: table
/// rebuilds, launches, deletes and the proxy's set updates.
static NFT: Mutex<()> = Mutex::new(());

fn orbs() -> MutexGuard<'static, BTreeMap<u32, OrbEntry>> {
    ORBS.lock().unwrap_or_else(|e| e.into_inner())
}

fn nft_lock() -> MutexGuard<'static, ()> {
    NFT.lock().unwrap_or_else(|e| e.into_inner())
}

fn agent_egress() -> Egress {
    AGENT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default()
}

/// Whether this agent enforces restricted egress: a Linux VM agent whose DNS proxy
/// runs.
pub fn enforced() -> bool {
    cfg!(target_os = "linux") && matches!(PROXY.get(), Some(Ok(())))
}

/// Why restricted orbs cannot start here.
fn not_enforced() -> RuntimeError {
    let why = match PROXY.get() {
        Some(Err(e)) => format!(" (its DNS proxy did not start: {e})"),
        _ => String::new(),
    };
    RuntimeError::Unsupported(format!("{}{why}", crate::runtime::EGRESS_REFUSED))
}

/// Binds the abstract unix socket `name`: one holder per network namespace. Tries again
/// for a second while it is taken: a holder that just exited may still be closing it (a
/// child it forked holds the descriptor until it execs).
#[cfg(target_os = "linux")]
fn bind_lock(name: &[u8]) -> std::io::Result<std::os::unix::net::UnixListener> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
    let mut tries = 0;
    loop {
        match std::os::unix::net::UnixListener::bind_addr(&addr) {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && tries < 10 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
            r => return r,
        }
    }
}

/// The pid and uid of the process holding the abstract unix socket `name` (as seen from
/// this pid namespace; the pid is 0 for a holder in another one), from its credentials.
#[cfg(target_os = "linux")]
fn lock_holder(name: &[u8]) -> Option<(i32, u32)> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name).ok()?;
    let s = std::os::unix::net::UnixStream::connect_addr(&addr).ok()?;
    let c = nix::sys::socket::getsockopt(&s, nix::sys::socket::sockopt::PeerCredentials).ok()?;
    Some((c.pid(), c.uid()))
}

/// Takes this network namespace's agent lock for the life of the process: orbd's
/// nftables table is the namespace's, so a second agent there would replace the first
/// one's (its restricted orbs' chains included).
#[cfg(target_os = "linux")]
fn lock_netns() -> Result<(), String> {
    static LOCK: OnceLock<Result<std::os::unix::net::UnixListener, String>> = OnceLock::new();
    LOCK.get_or_init(|| {
        bind_lock(NETNS_LOCK).map_err(|e| match e.kind() {
            std::io::ErrorKind::AddrInUse => {
                let who = match lock_holder(NETNS_LOCK) {
                    Some((pid, uid)) => format!(" (pid {pid}, uid {uid})"),
                    None => String::new(),
                };
                format!(
                    "another orbd agent{who} with VM runtimes runs in this network \
                     namespace; each needs its own (Docker gives every container one; \
                     --network host or two services on one host do not)"
                )
            }
            _ => format!("taking the agent's network namespace lock: {e}"),
        })
    })
    .as_ref()
    .map(|_| ())
    .map_err(Clone::clone)
}

#[cfg(not(target_os = "linux"))]
fn lock_netns() -> Result<(), String> {
    Ok(())
}

/// A policy that allows nothing.
fn nothing() -> EgressPolicy {
    EgressPolicy {
        domains: Vec::new(),
        ports: Vec::new(),
        allow: Vec::new(),
    }
}

/// A random non-zero conntrack mark other than `old`.
fn new_mark(old: Option<u32>) -> u32 {
    loop {
        let m: u32 = rand::random();
        if m != 0 && Some(m) != old {
            return m;
        }
    }
}

/// An orb's policy file in `orb_dir`: None if it has none.
pub fn read_applied(orb_dir: &Path) -> Result<Option<Applied>, String> {
    let path = orb_dir.join(POLICY_FILE);
    match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Whether the recipe in `orb_dir` restricts the orb ([`net::NetBackend::RestrictedTap`]).
fn recipe_restricted(orb_dir: &Path) -> Result<bool, String> {
    let path = orb_dir.join("vm.json");
    let b = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(v["net"]["backend"]["kind"] == "restricted_tap")
}

/// Whether `orb` is restricted: its spec or recipe says so, or it launched restricted.
pub fn restricted(orb: &OrbDefinition, orb_dir: &Path, attachment: &NetAttachment) -> bool {
    orb.egress_policy().is_some()
        || attachment.is_restricted()
        || orb_dir.join(POLICY_FILE).exists()
}

/// The restricted orbs `state_dir` records, by network index: each whose orb has a
/// policy file or a restricted recipe. One whose policy cannot be read, or whose recipe
/// is restricted (or unreadable) without a policy, is restricted to nothing.
fn scan(state_dir: &Path) -> Vec<(u32, OrbId, Applied)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(state_dir.join("net"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let Some(index) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Some(orb) = net::owner(state_dir, index) else {
            continue;
        };
        let dir = state_dir.join("orbs").join(orb.to_string());
        if !dir.is_dir() {
            continue;
        }
        let applied = match read_applied(&dir) {
            Ok(Some(a)) => a,
            Ok(None) => match recipe_restricted(&dir) {
                Ok(false) => continue,
                Ok(true) => Applied {
                    policy: nothing(),
                    mark: new_mark(None),
                },
                Err(e) => {
                    tracing::error!(%orb, error = %e, "unreadable recipe: the orb reaches nothing");
                    Applied {
                        policy: nothing(),
                        mark: new_mark(None),
                    }
                }
            },
            Err(e) => {
                tracing::error!(%orb, error = %e, "unreadable egress policy: the orb reaches nothing");
                Applied {
                    policy: nothing(),
                    mark: new_mark(None),
                }
            }
        };
        out.push((index, orb, applied));
    }
    out.sort_by_key(|(index, _, _)| *index);
    out
}

/// Installs orbd's table (see [`net::prepare_host`]) with the chains of the restricted
/// orbs on this host, keeping the addresses their sets hold, and starts the DNS proxy
/// (once; upstreams `dns_servers`; its codec in `jail`'s codec jail). Run by each Linux
/// VM runtime when it starts. Fails if another agent runs in this network namespace. A
/// proxy that cannot start is logged, and restricted orbs are then refused (`enforced`
/// is false).
pub fn prepare(
    state_dir: &Path,
    egress: &Egress,
    dns_servers: &[String],
    jail: Option<&super::jail::Jailer>,
) -> Result<(), String> {
    lock_netns()?;
    *AGENT.lock().unwrap_or_else(|e| e.into_inner()) = Some(egress.clone());
    let found = scan(state_dir);
    {
        let _g = nft_lock();
        // A set holds only what its current orb opened: each launch empties it (unless
        // the policy is unchanged) before its policy file is written.
        let mut carried = match found.is_empty() {
            true => HashMap::new(),
            false => net::opened_sets(),
        };
        let restricted: Vec<Restricted<'_>> = found
            .iter()
            .map(|(index, _, a)| Restricted {
                index: *index,
                policy: &a.policy,
                mark: a.mark,
                opened: carried.get(index).map(Vec::as_slice).unwrap_or(&[]),
            })
            .collect();
        net::prepare_host(egress, dns_servers, &restricted)?;
        let now = Instant::now();
        let mut orbs = orbs();
        orbs.clear();
        for (index, orb, applied) in found {
            let opened = carried
                .remove(&index)
                .unwrap_or_default()
                .into_iter()
                .map(|(a, left)| {
                    let until = now + Duration::from_secs(u64::from(left));
                    (
                        a,
                        Opened {
                            until,
                            confirmed: true,
                        },
                    )
                })
                .collect();
            orbs.insert(index, OrbEntry::new(orb, applied.policy, opened));
        }
        if !orbs.is_empty() {
            tracing::info!(
                orbs = orbs.len(),
                "restricted egress: orbs restricted on this host"
            );
        }
    }
    match PROXY.get_or_init(|| codec_spawner(jail).and_then(|c| proxy::start(dns_servers, c))) {
        Ok(()) => {}
        Err(e) => tracing::error!(
            error = %e,
            "restricted egress off: the DNS proxy did not start; orb types with egress do not run here"
        ),
    }
    Ok(())
}

/// Starts the DNS proxy's codecs: this binary, in `jail`'s codec jail (unjailed without
/// one: `ORBD_VMM_JAIL=off`).
#[cfg(target_os = "linux")]
fn codec_spawner(jail: Option<&super::jail::Jailer>) -> Result<super::codec::Spawner, String> {
    let exe = std::env::current_exe().map_err(|e| format!("finding orbd's binary: {e}"))?;
    let jail = match jail {
        Some(j) => Some(j.codec_jail(&exe)?),
        None => {
            tracing::warn!(
                "ORBD_VMM_JAIL=off: the DNS proxy's codecs run unjailed as this agent's user \
                 (under their own seccomp filter only)"
            );
            None
        }
    };
    let jailed = jail.is_some();
    let spawner = super::codec::process_spawner(jail);
    if !jailed {
        // It runs /proc/self/exe.
        return Ok(spawner);
    }
    // A jailed codec runs the binary at `exe`: only while it is still the agent's own.
    Ok(std::sync::Arc::new(move || {
        let exe = exe.clone();
        let mut spawn = spawner();
        Box::new(move || {
            same_binary(&exe)?;
            spawn()
        })
    }))
}

/// Fails unless `exe` is still the file this process runs.
#[cfg(target_os = "linux")]
fn same_binary(exe: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let id = |p: &Path| std::fs::metadata(p).map(|m| (m.dev(), m.ino()));
    match (id(exe), id(Path::new("/proc/self/exe"))) {
        (Ok(a), Ok(b)) if a == b => Ok(()),
        _ => Err(format!(
            "{} is no longer the binary this agent runs (replaced or removed): restart the \
             agent",
            exe.display()
        )),
    }
}

#[cfg(not(target_os = "linux"))]
fn codec_spawner(_jail: Option<&super::jail::Jailer>) -> Result<super::codec::Spawner, String> {
    Err("the DNS proxy runs on Linux only".into())
}

async fn blocking(
    f: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Result<(), RuntimeError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| RuntimeError::Other(e.to_string()))?
        .map_err(|e| RuntimeError::Other(format!("restricted egress: {e}")))
}

/// What a launch does with an orb's network.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Unrestricted: remove whatever chain its index still has.
    Open,
    /// Restricted to `policy`; `keep`: the policy is the one it last launched with (its
    /// open addresses stay open); `previous_mark`: that launch's mark.
    Restrict {
        policy: EgressPolicy,
        keep: bool,
        previous_mark: Option<u32>,
    },
}

/// How `orb` launches, given whether its recipe restricts it and its policy file
/// (`recorded`). Restricted if its spec, recipe or file says so (an unreadable file
/// too), with: the orb type's current policy; else (the type lost `egress` or is gone)
/// the one it last launched with, not the wider one it may have been created with; else,
/// with no file at all, the one it was created with; else nothing.
fn plan(
    orb: &OrbDefinition,
    recipe_restricted: bool,
    recorded: Result<Option<Applied>, String>,
) -> Plan {
    let restricted =
        orb.egress_policy().is_some() || recipe_restricted || !matches!(recorded, Ok(None));
    if !restricted {
        return Plan::Open;
    }
    let (last, unreadable) = match recorded {
        Ok(last) => (last, false),
        Err(e) => {
            tracing::warn!(orb = %orb.id, error = %e, "unreadable egress policy: replaced");
            (None, true)
        }
    };
    let policy = match (&orb.egress, &last) {
        (Some(current), _) => current.clone(),
        (None, Some(a)) => a.policy.clone(),
        (None, None) if unreadable => nothing(),
        (None, None) => orb
            .spec
            .template
            .requirements
            .egress
            .clone()
            .unwrap_or_else(nothing),
    };
    let keep = last.as_ref().is_some_and(|a| a.policy == policy);
    Plan::Restrict {
        policy,
        keep,
        previous_mark: last.map(|a| a.mark),
    }
}

/// A restricted launch to install (see [`install`]).
struct Install<'a> {
    index: u32,
    orb: OrbId,
    policy: EgressPolicy,
    keep: bool,
    mark: u32,
    file: &'a Path,
}

/// Installs restricted launch `l`: its chain (and, unless `keep`, an emptied set)
/// through `nft`, then its policy file, which so names only what the set holds for this
/// orb, then its entry (keeping its confirmed open addresses with `keep`). Run with
/// [`NFT`] held.
fn install(
    l: Install<'_>,
    agent: &Egress,
    nft: &dyn Fn(&str) -> Result<(), String>,
) -> Result<(), String> {
    let r = Restricted {
        index: l.index,
        policy: &l.policy,
        mark: l.mark,
        opened: &[],
    };
    nft(&net::restrict_script(&r, agent, l.keep))?;
    let applied = Applied {
        policy: l.policy.clone(),
        mark: l.mark,
    };
    super::fsutil::write_json_atomic(l.file, &applied)
        .map_err(|e| format!("{}: {e}", l.file.display()))?;
    let mut orbs = orbs();
    let opened = match orbs.remove(&l.index) {
        Some(e) if l.keep && e.orb == l.orb => {
            e.opened.into_iter().filter(|(_, o)| o.confirmed).collect()
        }
        _ => HashMap::new(),
    };
    orbs.insert(l.index, OrbEntry::new(l.orb, l.policy, opened));
    tracing::debug!(orb = %l.orb, index = l.index, keep = l.keep, "restricted egress applied");
    Ok(())
}

/// Restricts `orb`'s network (in `orb_dir`, on `attachment`) before a launch, or, for an
/// unrestricted orb, removes any chain its index still has (see [`plan`]). Fails, so
/// the launch does, if a restricted orb cannot be restricted.
pub async fn apply(
    orb: &OrbDefinition,
    orb_dir: &Path,
    attachment: &NetAttachment,
) -> Result<(), RuntimeError> {
    let id = orb.id;
    let plan = plan(orb, attachment.is_restricted(), read_applied(orb_dir));
    let Some(index) = attachment.index() else {
        return match plan {
            Plan::Open => Ok(()),
            Plan::Restrict { .. } => Err(RuntimeError::Unsupported(
                crate::runtime::EGRESS_REFUSED.into(),
            )),
        };
    };
    match plan {
        // Idempotent: a chain left by the index's earlier orb (a delete whose removal
        // failed) never sticks to this one.
        Plan::Open => {
            blocking(move || {
                let _g = nft_lock();
                net::apply_script(&net::unrestrict_script(index))?;
                orbs().remove(&index);
                Ok(())
            })
            .await
        }
        Plan::Restrict {
            policy,
            keep,
            previous_mark,
        } => {
            if !enforced() {
                return Err(not_enforced());
            }
            let mark = new_mark(previous_mark);
            let file = orb_dir.join(POLICY_FILE);
            blocking(move || {
                let _g = nft_lock();
                let l = Install {
                    index,
                    orb: id,
                    policy,
                    keep,
                    mark,
                    file: &file,
                };
                install(l, &agent_egress(), &net::apply_script)
            })
            .await
        }
    }
}

/// Removes the chains of the network indexes `orb` holds (it is being deleted),
/// whether it was restricted or not. One that cannot be removed is kept, and its
/// orb's next launch removes it.
pub fn release(orb: OrbId, state_dir: &Path) {
    for index in net::indexes_of(state_dir, orb) {
        let _g = nft_lock();
        match net::apply_script(&net::unrestrict_script(index)) {
            Ok(()) => {
                let mut orbs = orbs();
                if orbs.get(&index).is_some_and(|e| e.orb == orb) {
                    orbs.remove(&index);
                }
            }
            Err(e) => {
                tracing::warn!(%orb, index, error = %e, "removing the orb's egress chain: kept")
            }
        }
    }
}

/// The DNS servers a restricted orb's guest uses: its gateway, which its namespace
/// sends on to the proxy.
pub fn guest_dns(attachment: &NetAttachment) -> Vec<String> {
    vec![attachment.ipv4_gateway.clone()]
}

/// A query of an orb's launch in flight; counted against its limit until dropped.
struct Slot {
    index: u32,
    orb: OrbId,
    launch: u64,
}

impl Slot {
    fn take(index: u32) -> Option<(Self, Arc<EgressPolicy>)> {
        let mut orbs = orbs();
        let e = orbs.get_mut(&index)?;
        if e.inflight >= MAX_INFLIGHT_PER_ORB {
            return None;
        }
        e.inflight += 1;
        let slot = Self {
            index,
            orb: e.orb,
            launch: e.launch,
        };
        Some((slot, e.policy.clone()))
    }

    /// The orb's entry, if it is still this launch.
    fn entry<'a>(&self, orbs: &'a mut BTreeMap<u32, OrbEntry>) -> Option<&'a mut OrbEntry> {
        orbs.get_mut(&self.index)
            .filter(|e| e.orb == self.orb && e.launch == self.launch)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(e) = self.entry(&mut orbs()) {
            e.inflight = e.inflight.saturating_sub(1);
        }
    }
}

/// A TCP connection of an orb's launch; counted against its limit until dropped.
struct TcpSlot(Slot);

impl TcpSlot {
    fn take(index: u32) -> Option<Self> {
        let mut orbs = orbs();
        let e = orbs.get_mut(&index)?;
        if e.tcp >= MAX_TCP_PER_ORB {
            return None;
        }
        e.tcp += 1;
        Some(Self(Slot {
            index,
            orb: e.orb,
            launch: e.launch,
        }))
    }
}

impl Drop for TcpSlot {
    fn drop(&mut self) {
        if let Some(e) = self.0.entry(&mut orbs()) {
            e.tcp = e.tcp.saturating_sub(1);
        }
        // The inner slot counted no query.
        self.0.launch = 0;
    }
}

/// How long an address resolved with `ttl` (as handed to the orb) stays open.
pub fn open_secs(ttl: u32) -> u32 {
    ttl.min(MAX_TTL).max(MIN_OPEN) + OPEN_GRACE
}

/// What [`reserve`] reserved: addresses to open (seconds), what each was before (to roll
/// back), and addresses over the orb's limit.
#[derive(Debug, Default, PartialEq, Eq)]
struct Reservation {
    todo: Vec<(Ipv4Addr, u32)>,
    undo: Vec<(Ipv4Addr, Option<Opened>, Opened)>,
    dropped: Vec<Ipv4Addr>,
}

/// Reserves in `entry` the addresses of `addrs` (with the TTLs handed to the orb) that
/// are not open long enough yet, within [`MAX_OPEN_PER_ORB`] (reservations count), and
/// forgets expired ones.
fn reserve(entry: &mut OrbEntry, addrs: &[(Ipv4Addr, u32)], now: Instant) -> Reservation {
    // Reservations expire too: a query cancelled before it settled leaves none for long
    // (and its guard rolls it back at once).
    entry.opened.retain(|_, o| o.until > now);
    let mut r = Reservation::default();
    for &(a, ttl) in addrs {
        let needed = now + Duration::from_secs(u64::from(ttl) + u64::from(OPEN_GRACE) / 2);
        let prev = entry.opened.get(&a).copied();
        if prev.is_some_and(|o| o.confirmed && o.until >= needed) {
            continue;
        }
        if prev.is_none() && entry.opened.len() >= MAX_OPEN_PER_ORB {
            r.dropped.push(a);
            continue;
        }
        let secs = open_secs(ttl);
        let mine = Opened {
            until: now + Duration::from_secs(u64::from(secs)),
            confirmed: false,
        };
        entry.opened.insert(a, mine);
        r.todo.push((a, secs));
        r.undo.push((a, prev, mine));
    }
    r
}

/// Confirms (`ok`) or rolls back what [`reserve`] reserved, where nothing else has
/// changed it since.
fn settle(entry: &mut OrbEntry, r: &Reservation, ok: bool) {
    for (a, prev, mine) in &r.undo {
        if entry.opened.get(a) != Some(mine) {
            continue;
        }
        match (ok, prev) {
            (true, _) => {
                entry.opened.insert(
                    *a,
                    Opened {
                        confirmed: true,
                        ..*mine
                    },
                );
            }
            (false, Some(p)) => {
                entry.opened.insert(*a, *p);
            }
            (false, None) => {
                entry.opened.remove(a);
            }
        }
    }
}

mod proxy {
    use super::*;
    use crate::runtime::vm::codec::{self, Codec, Decoded};
    use crate::runtime::vm::dns::{self, Answer, AnswerData};
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{Semaphore, mpsc, oneshot};

    pub(super) struct Open {
        pub index: u32,
        pub orb: OrbId,
        pub launch: u64,
        pub addrs: Vec<(Ipv4Addr, u32)>,
        pub done: oneshot::Sender<Result<(), String>>,
    }

    /// The restricted orb (network index) a query comes from, if any.
    type Source = Box<dyn Fn(SocketAddr) -> Option<u32> + Send + Sync>;

    pub(super) struct Proxy {
        pub upstreams: Vec<SocketAddr>,
        pub opener: mpsc::Sender<Open>,
        pub inflight: Arc<Semaphore>,
        pub tcp: Arc<Semaphore>,
        pub source: Source,
        pub codecs: Codecs,
    }

    /// A restricted orb launch's codec.
    struct OrbCodec {
        orb: OrbId,
        launch: u64,
        codec: Codec,
        used: Instant,
    }

    /// The codecs of restricted orbs' launches, by network index: each started at its
    /// launch's first query, stopped when the launch is over or idle.
    pub(super) struct Codecs {
        spawner: codec::Spawner,
        by_orb: Mutex<HashMap<u32, OrbCodec>>,
    }

    impl Codecs {
        pub(super) fn new(spawner: codec::Spawner) -> Self {
            Self {
                spawner,
                by_orb: Mutex::new(HashMap::new()),
            }
        }

        /// The codec of `slot`'s launch, started if it has none (None once the launch is
        /// over).
        fn get(&self, slot: &Slot) -> Option<Codec> {
            let mut m = self.by_orb.lock().unwrap_or_else(|e| e.into_inner());
            // A query of a launch that is over gets nothing, and stops nothing.
            slot.entry(&mut orbs())?;
            if let Some(e) = m.get_mut(&slot.index) {
                if e.orb == slot.orb && e.launch == slot.launch {
                    e.used = Instant::now();
                    return Some(e.codec.clone());
                }
                e.codec.stop();
                m.remove(&slot.index);
            }
            let codec = codec::run((self.spawner)(), &slot.orb.to_string());
            m.insert(
                slot.index,
                OrbCodec {
                    orb: slot.orb,
                    launch: slot.launch,
                    codec: codec.clone(),
                    used: Instant::now(),
                },
            );
            Some(codec)
        }

        /// Stops the codecs of launches that are over, and of those idle for
        /// [`CODEC_IDLE`].
        fn reap(&self) {
            let now = Instant::now();
            let mut m = self.by_orb.lock().unwrap_or_else(|e| e.into_inner());
            let orbs = orbs();
            m.retain(|index, e| {
                let live = orbs
                    .get(index)
                    .is_some_and(|o| o.orb == e.orb && o.launch == e.launch);
                let keep = live && now.saturating_duration_since(e.used) < CODEC_IDLE;
                if !keep {
                    e.codec.stop();
                }
                keep
            });
        }
    }

    impl Drop for Codecs {
        fn drop(&mut self) {
            let m = self.by_orb.lock().unwrap_or_else(|e| e.into_inner());
            for e in m.values() {
                e.codec.stop();
            }
        }
    }

    /// A query's restricted orb by its veth address.
    fn orb_source(src: SocketAddr) -> Option<u32> {
        let SocketAddr::V4(v4) = src else { return None };
        let index = net::index_of(*v4.ip())?;
        orbs().contains_key(&index).then_some(index)
    }

    /// Binds the proxy's sockets and serves them on a thread of its own, its codecs
    /// started by `spawner` (once there first: one that cannot start fails it).
    pub(super) fn start(dns_servers: &[String], spawner: codec::Spawner) -> Result<(), String> {
        let upstreams: Vec<SocketAddr> = dns_servers
            .iter()
            .filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 53))
            .collect();
        if upstreams.is_empty() {
            return Err("no DNS servers to resolve with (ORBD_DNS)".into());
        }
        let at = SocketAddr::from((net::DNS_PROXY, 53));
        let udp = std::net::UdpSocket::bind(at).map_err(|e| format!("binding udp {at}: {e}"))?;
        let tcp = std::net::TcpListener::bind(at).map_err(|e| format!("binding tcp {at}: {e}"))?;
        for r in [udp.set_nonblocking(true), tcp.set_nonblocking(true)] {
            r.map_err(|e| e.to_string())?;
        }
        let (started, ready) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("orbd-dns".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = started.send(Err(format!("its runtime: {e}")));
                        return;
                    }
                };
                rt.block_on(async move {
                    let sockets = (
                        tokio::net::UdpSocket::from_std(udp),
                        tokio::net::TcpListener::from_std(tcp),
                    );
                    let (udp, tcp) = match sockets {
                        (Ok(u), Ok(t)) => (Arc::new(u), t),
                        (Err(e), _) | (_, Err(e)) => {
                            let _ = started.send(Err(format!("its sockets: {e}")));
                            return;
                        }
                    };
                    // A codec as each orb's will run, checked (a few tries: a busy host).
                    let mut tries = 1;
                    loop {
                        match codec::start((spawner)(), "startup check").await {
                            Ok(c) => {
                                c.stop();
                                break;
                            }
                            Err(e) if tries < 5 => {
                                tracing::warn!(error = %e, "restricted egress: the DNS codec's startup check failed; trying again");
                                tries += 1;
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                            Err(e) => {
                                let _ = started.send(Err(e));
                                return;
                            }
                        }
                    }
                    if started.send(Ok(())).is_err() {
                        return;
                    }
                    serve(udp, tcp, upstreams, spawner).await;
                });
            })
            .map_err(|e| e.to_string())?;
        ready
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "its codec did not start within 30 s".to_owned())??;
        tracing::info!(listen = %at, upstreams = %dns_servers.join(","), "restricted egress: DNS proxy on");
        Ok(())
    }

    async fn serve(
        udp: Arc<tokio::net::UdpSocket>,
        tcp: tokio::net::TcpListener,
        upstreams: Vec<SocketAddr>,
        spawner: codec::Spawner,
    ) {
        let (tx, rx) = mpsc::channel(1024);
        let p = Arc::new(Proxy {
            upstreams,
            opener: tx,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            tcp: Arc::new(Semaphore::new(MAX_TCP)),
            source: Box::new(orb_source),
            codecs: Codecs::new(spawner),
        });
        tokio::spawn(opener(rx));
        let reaper = p.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                reaper.codecs.reap();
            }
        });
        tokio::spawn(serve_tcp(p.clone(), tcp));
        serve_udp(p, udp).await;
    }

    async fn serve_udp(p: Arc<Proxy>, sock: Arc<tokio::net::UdpSocket>) {
        let mut buf = vec![0u8; MAX_QUERY];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "restricted egress: DNS proxy receive");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Some(index) = (p.source)(src) else {
                continue;
            };
            let Ok(permit) = p.inflight.clone().try_acquire_owned() else {
                count("busy");
                continue;
            };
            let Some(slot) = Slot::take(index) else {
                count("busy");
                continue;
            };
            let (p, sock, query) = (p.clone(), sock.clone(), buf[..n].to_vec());
            tokio::spawn(async move {
                let answer = tokio::time::timeout(QUERY_BUDGET, answer(&p, slot, &query, true));
                if let Ok(Some(a)) = answer.await {
                    let _ = sock.send_to(&a, src).await;
                }
                drop(permit);
            });
        }
    }

    pub(super) async fn serve_tcp(p: Arc<Proxy>, listener: tokio::net::TcpListener) {
        loop {
            let (stream, src) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "restricted egress: DNS proxy accept");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Some(index) = (p.source)(src) else {
                continue;
            };
            let Ok(conn) = p.tcp.clone().try_acquire_owned() else {
                continue;
            };
            // Over the orb's own share: closed, so one orb cannot hold every connection.
            let Some(slot) = TcpSlot::take(index) else {
                count("busy");
                continue;
            };
            let p = p.clone();
            tokio::spawn(async move {
                let launch = (slot.0.orb, slot.0.launch);
                let _ =
                    tokio::time::timeout(TCP_LIFETIME, connection(&p, index, launch, stream)).await;
                drop(slot);
                drop(conn);
            });
        }
    }

    /// Answers the queries of one TCP connection (see the bounds in the module docs),
    /// accepted from the orb launch `launch` on `index`: it ends once that launch is over,
    /// so nothing an earlier orb sent reaches the index's next one.
    async fn connection(
        p: &Proxy,
        index: u32,
        launch: (OrbId, u64),
        mut stream: tokio::net::TcpStream,
    ) {
        for _ in 0..TCP_QUERIES {
            let mut len = [0u8; 2];
            if !matches!(
                tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut len)).await,
                Ok(Ok(_))
            ) {
                return;
            }
            let len = usize::from(u16::from_be_bytes(len));
            if !(dns::HEADER..=MAX_QUERY).contains(&len) {
                return;
            }
            let mut query = vec![0u8; len];
            if !matches!(
                tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut query)).await,
                Ok(Ok(_))
            ) {
                return;
            }
            let Ok(permit) = p.inflight.clone().try_acquire_owned() else {
                return;
            };
            let Some(slot) = Slot::take(index) else {
                return;
            };
            if (slot.0.orb, slot.0.launch) != launch {
                return;
            }
            let a = tokio::time::timeout(QUERY_BUDGET, answer(p, slot, &query, false)).await;
            drop(permit);
            let Ok(Some(a)) = a else { return };
            let mut out = (a.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&a);
            if !matches!(
                tokio::time::timeout(TCP_IDLE, stream.write_all(&out)).await,
                Ok(Ok(()))
            ) {
                return;
            }
        }
    }

    fn count(result: &'static str) {
        metrics::counter!("orbd_egress_dns_queries_total", "result" => result).increment(1);
    }

    /// The answer to `msg` from the orb of `slot` (`udp`: as large as its query allows,
    /// else as TCP); None for no answer at all. Only the codec reads `msg`.
    pub(super) async fn answer(
        p: &Proxy,
        (slot, policy): (Slot, Arc<EgressPolicy>),
        msg: &[u8],
        udp: bool,
    ) -> Option<Vec<u8>> {
        let orb = slot.orb;
        let Some(codec) = p.codecs.get(&slot) else {
            count("unavailable");
            return None;
        };
        let q = match codec.decode(msg).await {
            Some(Decoded::Question(q)) => q,
            Some(Decoded::Ignore) => return None,
            Some(Decoded::Reply(r)) => {
                count("formerr");
                return Some(r);
            }
            None => {
                count("unavailable");
                return None;
            }
        };
        let reply = |rcode: u8, answers: Vec<Answer>| {
            let codec = codec.clone();
            async move { codec.encode(msg, udp, rcode, &answers).await }
        };
        if q.opcode != 0 {
            count("notimp");
            return reply(dns::NOTIMP, vec![]).await;
        }
        if q.qclass != dns::CLASS_IN {
            count("refused");
            return reply(dns::REFUSED, vec![]).await;
        }
        let Some(name) = q.name.clone().filter(|n| policy.allows_name(n)) else {
            count("refused");
            let shown = q.name.as_deref().unwrap_or("(not a hostname)");
            if slot.entry(&mut orbs()).is_some_and(|e| e.may_log()) {
                tracing::info!(target: "orbd::egress", %orb, name = %shown, "DNS query refused: not on the orb type's egress list");
            }
            return reply(dns::NXDOMAIN, vec![]).await;
        };
        if q.qtype != dns::TYPE_A {
            count("nodata");
            return reply(dns::NOERROR, vec![]).await;
        }
        let response = match resolve(&p.upstreams, &name).await {
            Ok(r) => r,
            Err(e) => {
                count("servfail");
                tracing::debug!(%orb, %name, error = %e, "restricted egress: upstream DNS");
                return reply(dns::SERVFAIL, vec![]).await;
            }
        };
        match response.header.rcode() {
            dns::NOERROR => {}
            dns::NXDOMAIN => {
                count("nxdomain");
                return reply(dns::NXDOMAIN, vec![]).await;
            }
            _ => {
                count("servfail");
                return reply(dns::SERVFAIL, vec![]).await;
            }
        }
        let (chain, addrs) = dns::answer_chain(&name, &response.answers);
        let (openable, blocked): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|(a, _)| net::openable(*a));
        for (a, _) in &blocked {
            metrics::counter!("orbd_egress_dns_blocked_addresses_total").increment(1);
            if slot.entry(&mut orbs()).is_some_and(|e| e.may_log()) {
                tracing::warn!(target: "orbd::egress", %orb, %name, addr = %a, "an allowlisted name resolved to a private or blocked address: left out, never opened");
            }
        }
        // One TTL for the whole answer, so no cache keeps a CNAME past its addresses.
        let ttl = chain
            .iter()
            .map(|a| a.ttl)
            .chain(openable.iter().map(|(_, t)| *t))
            .min()
            .unwrap_or(0)
            .min(MAX_TTL);
        let to_open: Vec<(Ipv4Addr, u32)> = openable.iter().map(|(a, _)| (*a, ttl)).collect();
        let opened = match open(p, &slot, &to_open).await {
            Ok(o) => o,
            Err(e) => {
                count("servfail");
                tracing::warn!(%orb, %name, error = %e, "restricted egress: opening resolved addresses");
                return reply(dns::SERVFAIL, vec![]).await;
            }
        };
        let end = dns::chain_end(&name, &chain).to_owned();
        let mut answers: Vec<Answer> = chain.into_iter().map(|a| Answer { ttl, ..a }).collect();
        answers.extend(
            to_open
                .iter()
                .filter(|(a, _)| opened.contains(a))
                .map(|(a, _)| Answer {
                    name: end.clone(),
                    ttl,
                    data: AnswerData::A(*a),
                }),
        );
        count("allowed");
        reply(dns::NOERROR, answers).await
    }

    /// Rolls a reservation back unless it was settled: a query cancelled while it
    /// waits on its set update (its budget, its connection's lifetime) reserves nothing
    /// after it.
    struct Pending<'a> {
        slot: &'a Slot,
        r: Reservation,
        settled: bool,
    }

    impl Drop for Pending<'_> {
        fn drop(&mut self) {
            if !self.settled
                && let Some(e) = self.slot.entry(&mut orbs())
            {
                settle(e, &self.r, false);
            }
        }
    }

    /// Opens `addrs` for the orb launch of `slot` (see [`reserve`]); the addresses that
    /// are open. Fails if the launch is over (the orb was deleted or launched again).
    async fn open(
        p: &Proxy,
        slot: &Slot,
        addrs: &[(Ipv4Addr, u32)],
    ) -> Result<Vec<Ipv4Addr>, String> {
        let gone = || "the orb was deleted or launched again".to_owned();
        let now = Instant::now();
        let r = {
            let mut orbs = orbs();
            let e = slot.entry(&mut orbs).ok_or_else(gone)?;
            let r = reserve(e, addrs, now);
            if !r.dropped.is_empty() && e.may_log() {
                tracing::warn!(
                    orb = %slot.orb,
                    dropped = r.dropped.len(),
                    "restricted egress: too many open addresses for one orb; left out"
                );
            }
            r
        };
        let mut pending = Pending {
            slot,
            r,
            settled: false,
        };
        if !pending.r.todo.is_empty() {
            let (done, wait) = oneshot::channel();
            let sent = p
                .opener
                .send(Open {
                    index: slot.index,
                    orb: slot.orb,
                    launch: slot.launch,
                    addrs: pending.r.todo.clone(),
                    done,
                })
                .await;
            let result = match sent {
                Ok(()) => wait
                    .await
                    .unwrap_or_else(|_| Err("the set updater stopped".into())),
                Err(_) => Err("the set updater stopped".into()),
            };
            if let Some(e) = slot.entry(&mut orbs()) {
                settle(e, &pending.r, result.is_ok());
            }
            pending.settled = true;
            result?;
        }
        pending.settled = true;
        Ok(addrs
            .iter()
            .map(|(a, _)| *a)
            .filter(|a| !pending.r.dropped.contains(a))
            .collect())
    }

    /// Applies set updates, batching those that wait into one transaction (each alone
    /// again if the batch fails), never for an orb launch that is over.
    async fn opener(mut rx: mpsc::Receiver<Open>) {
        while let Some(first) = rx.recv().await {
            let mut batch = vec![first];
            while batch.len() < 64 {
                match rx.try_recv() {
                    Ok(o) => batch.push(o),
                    Err(_) => break,
                }
            }
            if tokio::task::spawn_blocking(move || apply_opens(batch))
                .await
                .is_err()
            {
                tracing::error!("restricted egress: the set updater panicked");
            }
        }
    }

    /// Runs `batch` under the nftables lock: the launch of each is checked there, so an
    /// update never reaches the set of the index's next orb or launch.
    fn apply_opens(batch: Vec<Open>) {
        let _g = nft_lock();
        let (live, stale): (Vec<Open>, Vec<Open>) = {
            let orbs = orbs();
            batch.into_iter().partition(|o| {
                orbs.get(&o.index)
                    .is_some_and(|e| e.orb == o.orb && e.launch == o.launch)
            })
        };
        for o in stale {
            let _ = o
                .done
                .send(Err("the orb was deleted or launched again".into()));
        }
        if live.is_empty() {
            return;
        }
        let script: String = live
            .iter()
            .map(|o| net::open_script(o.index, &o.addrs))
            .collect();
        match net::apply_script(&script) {
            Ok(()) => {
                for o in live {
                    let _ = o.done.send(Ok(()));
                }
            }
            Err(e) if live.len() == 1 => {
                for o in live {
                    let _ = o.done.send(Err(e.clone()));
                }
            }
            Err(_) => {
                for o in live {
                    let r = net::apply_script(&net::open_script(o.index, &o.addrs));
                    let _ = o.done.send(r);
                }
            }
        }
    }

    enum Udp {
        Answer(dns::Response),
        Truncated,
    }

    /// Resolves `name` (A) with the first upstream that answers it, moving on after a
    /// SERVFAIL or REFUSED (which is returned if no other answers), within the query's
    /// budget.
    pub(super) async fn resolve(
        upstreams: &[SocketAddr],
        name: &str,
    ) -> Result<dns::Response, String> {
        let mut last: Result<dns::Response, String> = Err("no DNS servers".into());
        for server in upstreams.iter().take(3) {
            let got = match tokio::time::timeout(UPSTREAM_TRY, query_udp(*server, name)).await {
                Ok(Ok(Udp::Answer(r))) => Ok(r),
                Ok(Ok(Udp::Truncated)) => {
                    match tokio::time::timeout(UPSTREAM_TRY, query_tcp(*server, name)).await {
                        Ok(r) => r.map_err(|e| format!("{server} (tcp): {e}")),
                        Err(_) => Err(format!("{server} (tcp): timed out")),
                    }
                }
                Ok(Err(e)) => Err(format!("{server}: {e}")),
                Err(_) => Err(format!("{server}: timed out")),
            };
            match got {
                Ok(r) if matches!(r.header.rcode(), dns::SERVFAIL | dns::REFUSED) => {
                    last = Ok(r);
                }
                Ok(r) => return Ok(r),
                Err(e) if last.is_err() => last = Err(e),
                Err(_) => {}
            }
        }
        last
    }

    async fn query_udp(server: SocketAddr, name: &str) -> Result<Udp, String> {
        let bind: SocketAddr = match server {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let sock = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|e| e.to_string())?;
        // Connected: datagrams from anyone else are not delivered.
        sock.connect(server).await.map_err(|e| e.to_string())?;
        let id: u16 = rand::random();
        sock.send(&dns::build_query(id, name, dns::TYPE_A, Some(EDNS_SIZE)))
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
            let Some(h) = dns::Header::parse(&buf[..n]) else {
                continue;
            };
            if h.id != id || !h.response() {
                continue;
            }
            if h.truncated() {
                return Ok(Udp::Truncated);
            }
            match dns::parse_response(&buf[..n]) {
                Ok(r) if r.answers_query(id, name, dns::TYPE_A) => return Ok(Udp::Answer(r)),
                // Not for this query, or malformed: keep waiting.
                _ => continue,
            }
        }
    }

    async fn query_tcp(server: SocketAddr, name: &str) -> Result<dns::Response, String> {
        let mut s = tokio::net::TcpStream::connect(server)
            .await
            .map_err(|e| e.to_string())?;
        let id: u16 = rand::random();
        let q = dns::build_query(id, name, dns::TYPE_A, None);
        let mut out = (q.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&q);
        s.write_all(&out).await.map_err(|e| e.to_string())?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.map_err(|e| e.to_string())?;
        let mut msg = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut msg).await.map_err(|e| e.to_string())?;
        match dns::parse_response(&msg) {
            Ok(r) if r.answers_query(id, name, dns::TYPE_A) => Ok(r),
            Ok(_) => Err("an answer to another query".into()),
            Err(e) => Err(e.into()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::runtime::vm::dns::{TYPE_A, build_query, parse_response};

        /// A fake upstream on 127.0.0.1: answers from `records` (NXDOMAIN for other
        /// names, `rcode` for every name if given); the names it was asked.
        async fn upstream(
            records: Vec<(&'static str, Vec<Answer>)>,
            rcode: Option<u8>,
        ) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let at = sock.local_addr().unwrap();
            let asked = Arc::new(Mutex::new(Vec::new()));
            let a = asked.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let (n, src) = sock.recv_from(&mut buf).await.unwrap();
                    let q = dns::parse_query(&buf[..n]).unwrap();
                    let name = q.question.name.text().unwrap();
                    a.lock().unwrap().push(name.clone());
                    let reply = match (rcode, records.iter().find(|(r, _)| *r == name)) {
                        (Some(rc), _) => dns::build_response(&q, rc, &[], 1232),
                        (None, Some((_, ans))) => dns::build_response(&q, dns::NOERROR, ans, 1232),
                        (None, None) => dns::build_response(&q, dns::NXDOMAIN, &[], 1232),
                    };
                    sock.send_to(&reply, src).await.unwrap();
                }
            });
            (at, asked)
        }

        fn a(name: &str, ip: [u8; 4], ttl: u32) -> Answer {
            Answer {
                name: name.into(),
                ttl,
                data: AnswerData::A(Ipv4Addr::from(ip)),
            }
        }

        /// Set updates recorded by a test proxy: orb index and addresses.
        type Opens = Arc<Mutex<Vec<(u32, Vec<(Ipv4Addr, u32)>)>>>;

        /// A proxy resolving with `upstreams` whose set updates are recorded and
        /// succeed; queries come from 127.0.0.<n>, orb index 16000 + n. Its codec runs on
        /// a thread.
        async fn proxy(upstreams: Vec<SocketAddr>) -> (Proxy, Opens) {
            let (tx, mut rx) = mpsc::channel::<Open>(16);
            let opened = Arc::new(Mutex::new(Vec::new()));
            let o = opened.clone();
            tokio::spawn(async move {
                while let Some(open) = rx.recv().await {
                    let live = orbs()
                        .get(&open.index)
                        .is_some_and(|e| e.orb == open.orb && e.launch == open.launch);
                    if live {
                        o.lock().unwrap().push((open.index, open.addrs));
                        let _ = open.done.send(Ok(()));
                    } else {
                        let _ = open.done.send(Err("gone".into()));
                    }
                }
            });
            let p = Proxy {
                upstreams,
                opener: tx,
                inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
                tcp: Arc::new(Semaphore::new(MAX_TCP)),
                source: Box::new(|src| match src {
                    SocketAddr::V4(v) if v.ip().octets()[..3] == [127, 0, 0] => {
                        let index = 16_000 + u32::from(v.ip().octets()[3]);
                        orbs().contains_key(&index).then_some(index)
                    }
                    _ => None,
                }),
                codecs: Codecs::new(codec::thread_spawner()),
            };
            (p, opened)
        }

        fn restrict(index: u32, policy: &str) -> OrbId {
            let orb = OrbId::generate();
            let policy: EgressPolicy = serde_json::from_str(policy).unwrap();
            orbs().insert(index, OrbEntry::new(orb, policy, HashMap::new()));
            orb
        }

        /// The proxy end to end, but for its sockets: only listed names are resolved
        /// (others are never sent upstream), CNAME chains as returned, only global
        /// addresses are opened (with their timeouts, once while open), and every record
        /// of an answer carries its lowest TTL, at most [`MAX_TTL`].
        #[tokio::test]
        async fn answers_only_listed_names_and_opens_only_global_addresses() {
            let (at, asked) = upstream(
                vec![
                    (
                        "www.ampcode.com",
                        vec![
                            Answer {
                                name: "www.ampcode.com".into(),
                                ttl: 7200,
                                data: AnswerData::Cname("edge.cdn.example".into()),
                            },
                            a("edge.cdn.example", [34, 1, 2, 3], 3000),
                            a("edge.cdn.example", [10, 0, 0, 9], 60),
                            a("edge.cdn.example", [169, 254, 169, 254], 60),
                        ],
                    ),
                    (
                        "short.ampcode.com",
                        vec![
                            Answer {
                                name: "short.ampcode.com".into(),
                                ttl: 3600,
                                data: AnswerData::Cname("edge2.cdn.example".into()),
                            },
                            a("edge2.cdn.example", [34, 1, 2, 4], 20),
                        ],
                    ),
                    (
                        "many.ampcode.com",
                        (1..=40)
                            .map(|i| a("many.ampcode.com", [34, 9, 0, i], 30))
                            .collect(),
                    ),
                    (
                        "denied.example",
                        vec![a("denied.example", [34, 1, 1, 1], 60)],
                    ),
                ],
                None,
            )
            .await;
            let (p, opened) = proxy(vec![at]).await;
            let index = 16_001;
            restrict(index, r#"{"domains":["*.ampcode.com"]}"#);
            let ask = |msg: Vec<u8>, udp: bool| {
                let p = &p;
                async move { answer(p, Slot::take(index).unwrap(), &msg, udp).await }
            };
            let rcode = |m: &[u8]| dns::Header::parse(m).unwrap().rcode();

            // Off the list: NXDOMAIN, never sent upstream.
            let r = ask(build_query(1, "denied.example", TYPE_A, None), true)
                .await
                .unwrap();
            assert_eq!(rcode(&r), dns::NXDOMAIN);
            let r = ask(build_query(2, "ampcode.com", TYPE_A, None), true)
                .await
                .unwrap();
            assert_eq!(rcode(&r), dns::NXDOMAIN, "the wildcard is below it only");
            assert!(asked.lock().unwrap().is_empty());

            // Listed: the chain, the global address only, opened before the answer.
            let r = ask(build_query(3, "WWW.ampcode.com", TYPE_A, None), true)
                .await
                .unwrap();
            let r = parse_response(&r).unwrap();
            assert!(r.answers_query(3, "www.ampcode.com", TYPE_A));
            let (chain, addrs) = dns::answer_chain("www.ampcode.com", &r.answers);
            assert_eq!(chain.len(), 1);
            assert_eq!(chain[0].ttl, MAX_TTL, "TTLs capped");
            assert_eq!(addrs, vec![(Ipv4Addr::new(34, 1, 2, 3), MAX_TTL)]);
            assert_eq!(
                opened.lock().unwrap().clone(),
                vec![(
                    index,
                    vec![(Ipv4Addr::new(34, 1, 2, 3), MIN_OPEN + OPEN_GRACE)]
                )]
            );
            assert_eq!(asked.lock().unwrap().clone(), ["www.ampcode.com"]);
            // Open long enough: answered again without opening again.
            ask(build_query(4, "www.ampcode.com", TYPE_A, None), true)
                .await
                .unwrap();
            assert_eq!(opened.lock().unwrap().len(), 1);
            // A short TTL anywhere is every record's.
            let r = ask(build_query(12, "short.ampcode.com", TYPE_A, None), true)
                .await
                .unwrap();
            let r = parse_response(&r).unwrap();
            assert_eq!(r.answers.len(), 2);
            assert!(r.answers.iter().all(|a| a.ttl == 20), "{:?}", r.answers);

            // Other types: empty, not asked upstream. Other classes: refused.
            let mut q = build_query(5, "www.ampcode.com", 28, None);
            let r = ask(q.clone(), true).await.unwrap();
            let r = parse_response(&r).unwrap();
            assert_eq!((r.header.rcode(), r.answers.len()), (dns::NOERROR, 0));
            let n = q.len();
            q[n - 1] = 3; // class CH
            assert_eq!(rcode(&ask(q, true).await.unwrap()), dns::REFUSED);
            assert_eq!(asked.lock().unwrap().len(), 3);

            // Malformed: FORMERR; a response: nothing.
            let mut two = build_query(6, "www.ampcode.com", TYPE_A, None);
            two[5] = 2;
            assert_eq!(rcode(&ask(two, true).await.unwrap()), dns::FORMERR);
            let mut resp = build_query(7, "www.ampcode.com", TYPE_A, None);
            resp[2] |= 0x80;
            assert_eq!(ask(resp, true).await, None);
            // Upstream NXDOMAIN passes through.
            let r = ask(build_query(8, "nope.ampcode.com", TYPE_A, None), true)
                .await
                .unwrap();
            assert_eq!(rcode(&r), dns::NXDOMAIN);

            // Too big for UDP: what fits, truncated, so the orb asks over TCP, which gets
            // it all; an EDNS query gets up to its size.
            let q = build_query(9, "many.ampcode.com", TYPE_A, None);
            let m = ask(q.clone(), true).await.unwrap();
            let r = parse_response(&m).unwrap();
            assert!(m.len() <= 512 && r.header.truncated() && !r.answers.is_empty());
            let r = parse_response(&ask(q, false).await.unwrap()).unwrap();
            assert_eq!(r.answers.len(), 40);
            assert_eq!(r.answers[0].ttl, 30);
            let e = build_query(10, "many.ampcode.com", TYPE_A, Some(1232));
            let r = parse_response(&ask(e, true).await.unwrap()).unwrap();
            assert!(!r.header.truncated() && r.answers.len() == 40);
            let last = opened.lock().unwrap().last().unwrap().1.clone();
            assert_eq!(last.len(), 40);
            assert!(last.iter().all(|(_, t)| *t == MIN_OPEN + OPEN_GRACE));

            // A query of a launch that is over (the orb launched again, or another orb
            // took the index) gets no answer and opens nothing for the new one.
            let slot = Slot::take(index).unwrap();
            restrict(index, r#"{"domains":["*.ampcode.com"]}"#);
            let before = opened.lock().unwrap().len();
            let q = build_query(11, "www.ampcode.com", TYPE_A, None);
            assert_eq!(answer(&p, slot, &q, true).await, None);
            assert_eq!(opened.lock().unwrap().len(), before);
            assert!(orbs()[&index].opened.is_empty(), "nothing reserved either");

            orbs().remove(&index);
            assert!(Slot::take(index).is_none());
        }

        /// A query cancelled while its addresses are being opened (its budget ran out,
        /// its connection closed) leaves nothing reserved.
        #[tokio::test]
        async fn a_cancelled_query_reserves_nothing() {
            let (at, _) = upstream(
                vec![("a.example", vec![a("a.example", [34, 1, 2, 3], 60)])],
                None,
            )
            .await;
            // A set updater that never answers.
            let (tx, mut rx) = mpsc::channel::<Open>(16);
            tokio::spawn(async move {
                let mut held = Vec::new();
                while let Some(o) = rx.recv().await {
                    held.push(o);
                }
            });
            let p = Proxy {
                upstreams: vec![at],
                opener: tx,
                inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
                tcp: Arc::new(Semaphore::new(MAX_TCP)),
                source: Box::new(|_| None),
                codecs: Codecs::new(codec::thread_spawner()),
            };
            let index = 16_004;
            restrict(index, r#"{"domains":["a.example"]}"#);
            let q = build_query(1, "a.example", TYPE_A, None);
            let r = tokio::time::timeout(
                Duration::from_millis(500),
                answer(&p, Slot::take(index).unwrap(), &q, true),
            )
            .await;
            assert!(r.is_err(), "the update never finished: cancelled");
            let (opened, inflight) = {
                let orbs = orbs();
                (orbs[&index].opened.clone(), orbs[&index].inflight)
            };
            assert!(opened.is_empty(), "{opened:?}");
            assert_eq!(inflight, 0);
            orbs().remove(&index);
        }

        /// One orb holding idle TCP connections takes no more than its share: another
        /// orb is still answered over TCP, and connections end.
        // Binds the proxy's link-local address on loopback, which only Linux has (and
        // only Linux agents run the proxy).
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn tcp_connections_are_shared_between_orbs() {
            let (p, _) = proxy(vec![]).await;
            let (a, b) = (16_002, 16_003);
            restrict(a, r#"{"domains":["a.example"]}"#);
            restrict(b, r#"{"domains":["b.example"]}"#);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            tokio::spawn(serve_tcp(Arc::new(p), listener));
            let connect = |from: [u8; 4]| async move {
                let s = tokio::net::TcpSocket::new_v4().unwrap();
                s.bind(SocketAddr::from((from, 0))).unwrap();
                s.connect(at).await.unwrap()
            };
            let mut idle = Vec::new();
            for _ in 0..MAX_TCP_PER_ORB + 3 {
                idle.push(connect([127, 0, 0, 2]).await);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Those over orb a's share were closed.
            let mut closed = 0;
            for s in &mut idle {
                let mut b = [0u8; 1];
                if let Ok(Ok(0)) =
                    tokio::time::timeout(Duration::from_millis(100), s.read(&mut b)).await
                {
                    closed += 1;
                }
            }
            assert_eq!(closed, 3);
            let mut s = connect([127, 0, 0, 3]).await;
            let q = build_query(1, "c.example", TYPE_A, None);
            let mut out = (q.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&q);
            s.write_all(&out).await.unwrap();
            let mut len = [0u8; 2];
            tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut len))
                .await
                .expect("orb b is answered")
                .unwrap();
            let mut m = vec![0u8; usize::from(u16::from_be_bytes(len))];
            s.read_exact(&mut m).await.unwrap();
            assert_eq!(dns::Header::parse(&m).unwrap().rcode(), dns::NXDOMAIN);
            // A source that is no restricted orb is not served at all.
            let mut stranger = connect([127, 0, 0, 9]).await;
            let mut b1 = [0u8; 1];
            assert!(matches!(
                tokio::time::timeout(Duration::from_millis(500), stranger.read(&mut b1)).await,
                Ok(Ok(0)) | Ok(Err(_))
            ));
            for i in [a, b] {
                orbs().remove(&i);
            }
        }

        /// A query of a launch that is over gets no codec and stops none: the index's
        /// current launch keeps its codec.
        #[tokio::test]
        async fn a_stale_query_leaves_the_current_codec() {
            let (p, _) = proxy(vec![]).await;
            let index = 16_005;
            restrict(index, r#"{"domains":["a.example"]}"#);
            let (old, _) = Slot::take(index).unwrap();
            restrict(index, r#"{"domains":["a.example"]}"#);
            let (current, _) = Slot::take(index).unwrap();
            let q = build_query(1, "a.example", TYPE_A, None);
            let codec = p.codecs.get(&current).unwrap();
            assert!(matches!(codec.decode(&q).await, Some(Decoded::Question(_))));
            assert!(p.codecs.get(&old).is_none());
            assert!(matches!(codec.decode(&q).await, Some(Decoded::Question(_))));
            drop((old, current));
            orbs().remove(&index);
        }

        /// A TCP connection serves the orb launch it was accepted from only: once the
        /// index has another launch, its next query ends it unanswered.
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn a_tcp_connection_ends_with_its_launch() {
            let (p, _) = proxy(vec![]).await;
            let index = 16_006;
            restrict(index, r#"{"domains":["a.example"]}"#);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            tokio::spawn(serve_tcp(Arc::new(p), listener));
            let s = tokio::net::TcpSocket::new_v4().unwrap();
            s.bind(SocketAddr::from(([127, 0, 0, 6], 0))).unwrap();
            let mut s = s.connect(at).await.unwrap();
            let ask = |id: u16| {
                let q = build_query(id, "a.example", TYPE_A, None);
                let mut out = (q.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&q);
                out
            };
            s.write_all(&ask(1)).await.unwrap();
            let mut len = [0u8; 2];
            tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut len))
                .await
                .expect("answered")
                .unwrap();
            let mut m = vec![0u8; usize::from(u16::from_be_bytes(len))];
            s.read_exact(&mut m).await.unwrap();
            // Another orb (or launch) takes the index.
            restrict(index, r#"{"domains":["a.example"]}"#);
            s.write_all(&ask(2)).await.unwrap();
            let mut b = [0u8; 1];
            let r = tokio::time::timeout(Duration::from_secs(5), s.read(&mut b)).await;
            assert!(matches!(r, Ok(Ok(0)) | Ok(Err(_))), "{r:?}");
            orbs().remove(&index);
        }

        /// Upstream answers that are not for the query (another id or question, or
        /// garbage) are ignored; a truncated one is asked again over TCP; a SERVFAIL or
        /// REFUSED moves on to the next server.
        #[tokio::test]
        async fn upstream_answers_must_match_and_fall_back() {
            let (udp, tcp) = loop {
                let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let port = udp.local_addr().unwrap().port();
                if let Ok(tcp) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
                    break (udp, tcp);
                }
            };
            let at = udp.local_addr().unwrap();
            let answer = vec![a("big.example.com", [34, 5, 6, 7], 60)];
            let ans = answer.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let (n, src) = udp.recv_from(&mut buf).await.unwrap();
                let q = dns::parse_query(&buf[..n]).unwrap();
                // A stray with another id, garbage, an answer to another question.
                let mut stray = dns::build_response(
                    &q,
                    dns::NOERROR,
                    &[a("big.example.com", [6, 6, 6, 6], 60)],
                    512,
                );
                stray[0] ^= 0xff;
                udp.send_to(&stray, src).await.unwrap();
                udp.send_to(&[1, 2, 3], src).await.unwrap();
                let other =
                    dns::parse_query(&build_query(q.header.id, "evil.example.com", TYPE_A, None))
                        .unwrap();
                let wrong = dns::build_response(
                    &other,
                    dns::NOERROR,
                    &[a("evil.example.com", [6, 6, 6, 6], 60)],
                    512,
                );
                udp.send_to(&wrong, src).await.unwrap();
                // Then the real one, truncated.
                let tc = dns::build_response(&q, dns::NOERROR, &vec![ans[0].clone(); 60], 512);
                udp.send_to(&tc, src).await.unwrap();
            });
            tokio::spawn(async move {
                let (mut s, _) = tcp.accept().await.unwrap();
                let mut len = [0u8; 2];
                s.read_exact(&mut len).await.unwrap();
                let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                s.read_exact(&mut q).await.unwrap();
                let q = dns::parse_query(&q).unwrap();
                let r = dns::build_response(&q, dns::NOERROR, &answer, 65535);
                let mut out = (r.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&r);
                s.write_all(&out).await.unwrap();
            });
            // A server that fails first: the next one answers.
            let (failing, asked) = upstream(vec![], Some(dns::SERVFAIL)).await;
            let r = resolve(&[failing, at], "big.example.com").await.unwrap();
            assert_eq!(asked.lock().unwrap().len(), 1);
            let (_, addrs) = dns::answer_chain("big.example.com", &r.answers);
            assert_eq!(addrs, vec![(Ipv4Addr::new(34, 5, 6, 7), 60)]);
            // Only refusing servers: their answer.
            let (refusing, _) = upstream(vec![], Some(dns::REFUSED)).await;
            let r = resolve(&[refusing], "big.example.com").await.unwrap();
            assert_eq!(r.header.rcode(), dns::REFUSED);
            // Nothing answers: an error within the budget, not a hang.
            let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let t = Instant::now();
            assert!(
                resolve(&[silent.local_addr().unwrap()], "big.example.com")
                    .await
                    .is_err()
            );
            assert!(t.elapsed() < QUERY_BUDGET);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> OrbEntry {
        OrbEntry::new(OrbId::generate(), nothing(), HashMap::new())
    }

    #[test]
    fn open_addresses_outlive_the_answer() {
        assert_eq!(open_secs(0), MIN_OPEN + OPEN_GRACE);
        assert_eq!(open_secs(MAX_TTL), MIN_OPEN + OPEN_GRACE);
        let now = Instant::now();
        let mut e = entry();
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let r = reserve(&mut e, &[(a, 100)], now);
        assert_eq!(
            (r.todo.clone(), r.dropped.clone()),
            (vec![(a, 630)], vec![])
        );
        settle(&mut e, &r, true);
        // Open long enough: nothing to do; about to expire: opened again.
        assert!(reserve(&mut e, &[(a, 100)], now).todo.is_empty());
        let late = now + Duration::from_secs(600);
        assert_eq!(reserve(&mut e, &[(a, 100)], late).todo, vec![(a, 630)]);
        // Expired entries are forgotten.
        let later = now + Duration::from_secs(5000);
        let mut e = entry();
        let r = reserve(&mut e, &[(a, 1)], now);
        settle(&mut e, &r, true);
        reserve(&mut e, &[], later);
        assert!(e.opened.is_empty());
    }

    /// The limit holds with queries in flight: reservations count, and one that fails
    /// is rolled back (without undoing what another query confirmed since).
    #[test]
    fn open_addresses_are_bounded_per_orb() {
        let now = Instant::now();
        let mut e = entry();
        let addr = |i: u32| Ipv4Addr::from(0x2200_0000 + i);
        let first: Vec<_> = (0..MAX_OPEN_PER_ORB as u32 - 1)
            .map(|i| (addr(i), 60))
            .collect();
        let r1 = reserve(&mut e, &first, now);
        assert_eq!(r1.todo.len(), MAX_OPEN_PER_ORB - 1);
        // Two queries in flight together: only one more fits.
        let r2 = reserve(&mut e, &[(addr(5000), 60)], now);
        let r3 = reserve(&mut e, &[(addr(5001), 60)], now);
        assert_eq!((r2.todo.len(), r3.dropped), (1, vec![addr(5001)]));
        // r2 fails: rolled back, and there is room again.
        settle(&mut e, &r2, false);
        assert!(!e.opened.contains_key(&addr(5000)));
        let r4 = reserve(&mut e, &[(addr(5001), 60)], now);
        assert_eq!(r4.todo.len(), 1);
        settle(&mut e, &r1, true);
        settle(&mut e, &r4, true);
        assert_eq!(e.opened.len(), MAX_OPEN_PER_ORB);
        assert!(e.opened.values().all(|o| o.confirmed));
        // A rollback leaves an address another query confirmed in the meantime.
        let mut e = entry();
        let x = addr(1);
        let ra = reserve(&mut e, &[(x, 60)], now);
        let rb = reserve(&mut e, &[(x, 60)], now);
        settle(&mut e, &rb, true);
        settle(&mut e, &ra, false);
        assert!(e.opened[&x].confirmed);
    }

    #[test]
    fn logs_are_rate_limited() {
        let mut e = entry();
        let logged = (0..1000).filter(|_| e.may_log()).count();
        assert!(logged <= LOG_BURST as usize + 1, "{logged}");
    }

    #[test]
    fn scan_finds_restricted_orbs_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let st = dir.path();
        std::fs::create_dir_all(st.join("net")).unwrap();
        let orbs: Vec<OrbId> = (0..5).map(|_| OrbId::generate()).collect();
        for (i, o) in orbs.iter().enumerate() {
            std::fs::write(st.join("net").join((i + 1).to_string()), o.to_string()).unwrap();
            std::fs::create_dir_all(st.join("orbs").join(o.to_string())).unwrap();
        }
        let dir = |i: usize| st.join("orbs").join(orbs[i].to_string());
        let recipe = |i: usize, kind: &str| {
            let json = format!(
                r#"{{"orb":"x","net":{{"backend":{{"kind":"{kind}","netns":"n","index":{}}}}}}}"#,
                i + 1
            );
            std::fs::write(dir(i).join("vm.json"), json).unwrap();
        };
        let policy: EgressPolicy =
            serde_json::from_str(r#"{"domains":["ampcode.com"],"allow":[]}"#).unwrap();
        let applied = Applied {
            policy: policy.clone(),
            mark: 7,
        };
        // 1: launched restricted; 2: unrestricted; 3: unreadable policy; 4: restricted
        // recipe without a policy; 5: no readable recipe and no policy.
        recipe(0, "restricted_tap");
        std::fs::write(
            dir(0).join(POLICY_FILE),
            serde_json::to_vec(&applied).unwrap(),
        )
        .unwrap();
        recipe(1, "tap");
        recipe(2, "tap");
        std::fs::write(dir(2).join(POLICY_FILE), b"{oops").unwrap();
        recipe(3, "restricted_tap");
        let found = scan(st);
        let got: Vec<(u32, OrbId)> = found.iter().map(|(i, o, _)| (*i, *o)).collect();
        assert_eq!(
            got,
            vec![(1, orbs[0]), (3, orbs[2]), (4, orbs[3]), (5, orbs[4])]
        );
        assert_eq!(found[0].2, applied);
        for (_, _, a) in &found[1..] {
            assert_eq!(a.policy, nothing(), "restricted to nothing");
            assert_ne!(a.mark, 0);
        }
    }

    fn definition(created: Option<&str>, current: Option<&str>) -> OrbDefinition {
        use crate::model::*;
        let p = |j: &str| serde_json::from_str::<EgressPolicy>(j).unwrap();
        let spec = OrbSpec {
            template: SpecTemplate {
                target: ExecutionTarget::Fleet {
                    runtime: RuntimeKind::Firecracker,
                },
                resources: Resources {
                    vcpus: 2,
                    memory_bytes: 2 * GIB,
                    disk_bytes: 4 * GIB,
                },
                requirements: CapabilityRequirements {
                    release_compute_when_paused: true,
                    nested_kvm: NestedKvmRequirement::NotRequired,
                    project_snapshots: SnapshotRequirement::NotRequired,
                    arch: Arch::Amd64,
                    egress: created.map(p),
                },
                pause_policy: PausePolicy::MemoryPreserving {
                    on_failure: CheckpointFailurePolicy::ColdStop,
                },
            },
            initial_disk: InitialDiskSource::Image {
                image_ref: "i".into(),
            },
        };
        OrbDefinition {
            id: OrbId::generate(),
            identity: OrbIdentity {
                amp_endpoint: AmpEndpointId::new("amp"),
                amp_orb_id: AmpOrbId::new("amp-1"),
            },
            offering_id: OfferingId::new("t"),
            spec_digest: spec.digest(),
            spec,
            egress: current.map(p),
        }
    }

    /// A launch's policy: the orb type's current one, else the one last applied, else
    /// (no policy file at all) the one the orb was created with, else nothing; an
    /// unreadable file never falls back to the creation-time policy. Restricted if the
    /// spec, the recipe or the file says so.
    #[test]
    fn launches_take_the_current_then_the_last_applied_policy() {
        let p = |j: &str| serde_json::from_str::<EgressPolicy>(j).unwrap();
        let (created, last, current) = (
            r#"{"domains":["wide.example","*.wide.example"]}"#,
            r#"{"domains":["last.example"]}"#,
            r#"{"domains":["now.example"]}"#,
        );
        let applied = |j: &str, mark: u32| Applied { policy: p(j), mark };
        let restrict = |policy: &str, keep: bool, previous_mark: Option<u32>| Plan::Restrict {
            policy: p(policy),
            keep,
            previous_mark,
        };
        // The current policy wins; kept when it is the last one.
        assert_eq!(
            plan(
                &definition(Some(created), Some(current)),
                true,
                Ok(Some(applied(last, 7)))
            ),
            restrict(current, false, Some(7))
        );
        assert_eq!(
            plan(
                &definition(Some(created), Some(current)),
                true,
                Ok(Some(applied(current, 7)))
            ),
            restrict(current, true, Some(7))
        );
        // No current policy (the type lost it or is gone): the last one, not the wider
        // creation-time one.
        assert_eq!(
            plan(
                &definition(Some(created), None),
                true,
                Ok(Some(applied(last, 7)))
            ),
            restrict(last, true, Some(7))
        );
        // First launch: the creation-time one.
        assert_eq!(
            plan(&definition(Some(created), None), true, Ok(None)),
            restrict(created, false, None)
        );
        // An unreadable file and no current policy: nothing.
        assert_eq!(
            plan(&definition(Some(created), None), true, Err("bad".into())),
            Plan::Restrict {
                policy: nothing(),
                keep: false,
                previous_mark: None
            }
        );
        // A coordinator that drops the restriction from the spec: still restricted, by
        // the recipe or the file.
        assert_eq!(
            plan(&definition(None, None), true, Ok(None)),
            Plan::Restrict {
                policy: nothing(),
                keep: false,
                previous_mark: None
            }
        );
        assert_eq!(
            plan(&definition(None, None), false, Ok(Some(applied(last, 3)))),
            restrict(last, true, Some(3))
        );
        assert!(matches!(
            plan(&definition(None, None), false, Err("bad".into())),
            Plan::Restrict { .. }
        ));
        // Unrestricted everywhere: open (a current policy for an unrestricted spec is
        // never sent, and ignored).
        assert_eq!(
            plan(&definition(None, Some(current)), false, Ok(None)),
            Plan::Open
        );
    }

    /// A launch installs its chain first, then its policy file, then its entry; a chain
    /// that fails to install writes nothing. With an unchanged policy the orb keeps its
    /// confirmed open addresses.
    #[test]
    fn launches_record_their_policy_only_after_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(POLICY_FILE);
        let index = 16_200;
        let orb = OrbId::generate();
        let policy: EgressPolicy = serde_json::from_str(r#"{"domains":["a.example"]}"#).unwrap();
        let l = |keep: bool, mark: u32| Install {
            index,
            orb,
            policy: policy.clone(),
            keep,
            mark,
            file: &file,
        };
        let agent = Egress::default();
        let failed = install(l(false, 5), &agent, &|_| Err("no nft".into()));
        assert_eq!(failed, Err("no nft".into()));
        assert!(!file.exists() && !orbs().contains_key(&index));
        // What each nft run saw of the policy file: the previous launch's mark, never
        // its own.
        let scripts = Mutex::new(Vec::new());
        let seen = Mutex::new(Vec::new());
        let nft = |script: &str| {
            let mark = read_applied(dir.path()).unwrap().map(|a| a.mark);
            seen.lock().unwrap().push(mark);
            scripts.lock().unwrap().push(script.to_owned());
            Ok(())
        };
        install(l(false, 5), &agent, &nft).unwrap();
        assert_eq!(
            read_applied(dir.path()).unwrap(),
            Some(Applied {
                policy: policy.clone(),
                mark: 5
            })
        );
        assert!(scripts.lock().unwrap()[0].contains("flush set inet orbd resolved16200"));
        assert!(scripts.lock().unwrap()[0].contains("ct mark 0x00000005"));
        // Open addresses: kept (confirmed ones) with an unchanged policy.
        let (a, b) = (Ipv4Addr::new(34, 1, 1, 1), Ipv4Addr::new(34, 1, 1, 2));
        let until = Instant::now() + Duration::from_secs(60);
        {
            let mut orbs = orbs();
            let e = orbs.get_mut(&index).unwrap();
            e.opened.insert(
                a,
                Opened {
                    until,
                    confirmed: true,
                },
            );
            e.opened.insert(
                b,
                Opened {
                    until,
                    confirmed: false,
                },
            );
        }
        install(l(true, 6), &agent, &nft).unwrap();
        assert!(!scripts.lock().unwrap()[1].contains("flush set"));
        let kept: Vec<Ipv4Addr> = orbs()[&index].opened.keys().copied().collect();
        assert_eq!(kept, vec![a]);
        install(l(false, 7), &agent, &nft).unwrap();
        assert!(orbs()[&index].opened.is_empty());
        assert_eq!(read_applied(dir.path()).unwrap().unwrap().mark, 7);
        assert_eq!(seen.lock().unwrap().clone(), vec![None, Some(5), Some(6)]);
        orbs().remove(&index);
    }

    /// Only one agent per network namespace takes the lock.
    #[cfg(target_os = "linux")]
    #[test]
    fn one_agent_per_network_namespace() {
        let name = format!("orbd-test-{}", uuid::Uuid::new_v4().simple());
        let first = bind_lock(name.as_bytes()).unwrap();
        let second = bind_lock(name.as_bytes()).unwrap_err();
        assert_eq!(second.kind(), std::io::ErrorKind::AddrInUse);
        // Its holder, named.
        let me = (std::process::id() as i32, nix::unistd::getuid().as_raw());
        assert_eq!(lock_holder(name.as_bytes()), Some(me));
        drop(first);
        assert!(bind_lock(name.as_bytes()).is_ok(), "free again");
    }
}
