//! The egress fence of QEMU orbs on macOS. There orbs use QEMU's user-mode network
//! (slirp), so their traffic is QEMU's own sockets: QEMU runs with
//! `runtime.qemu.network_group` (through the setgid `orbd-netgroup`) and pf rules for
//! that group keep orbs off the LAN, the tailnet and the Mac itself (slirp maps the
//! orb's gateway to the Mac's 127.0.0.1). The agent runs as a normal user and cannot
//! read pf's state (`pfctl` needs root), so it tests the fence instead of trusting a
//! report about it:
//!
//! 1. it listens on `127.0.0.1:<ephemeral>` and connects there itself, which must work
//!    (nothing else blocks loopback);
//! 2. it runs `orbd-netgroup <orbd> fence-probe 127.0.0.1:<port> --gid <gid>`: the same
//!    connection with the network group, as QEMU would make it, which pf must block, and
//!    no connection may reach the listener.
//!
//! That holds only while pf is enabled and the group's rules are loaded and evaluated
//! (not skipped on `lo0`), and while `orbd-netgroup` really gives the group. Whether the
//! rules also cover the LAN's and tailnet's ranges is the operator's ruleset (README).
//!
//! QEMU orbs start only after a passing probe at most [`FRESH`] old; the agent also
//! probes every [`FRESH`] in the background, so a fence that goes away is logged while
//! orbs run. `ORBD_ALLOW_UNFENCED_EGRESS` runs them without a fence. Linux agents do not
//! need it (their orbs are fenced by orbd's own network namespaces and nftables).

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a passing probe vouches for the fence.
pub const FRESH: Duration = Duration::from_secs(30);
/// `fence-probe` exit codes: connected (no fence), blocked, not running with the group.
pub const PROBE_CONNECTED: i32 = 0;
pub const PROBE_BLOCKED: i32 = 3;
pub const PROBE_WRONG_GROUP: i32 = 4;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// The hidden subcommand the probe runs (`orbd fence-probe`).
pub const PROBE_COMMAND: &str = "fence-probe";

/// `orbd fence-probe <addr> --gid <gid>`: connects to `addr` with this process's
/// credentials; the exit code says what happened (see [`PROBE_CONNECTED`] etc.).
pub fn probe_main(addr: SocketAddr, gid: u32) -> i32 {
    let egid = nix::unistd::getegid().as_raw();
    if egid != gid {
        eprintln!("fence-probe: running with group {egid}, not {gid}");
        return PROBE_WRONG_GROUP;
    }
    match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Ok(_) => PROBE_CONNECTED,
        Err(e) => {
            eprintln!("fence-probe: {addr}: {e}");
            PROBE_BLOCKED
        }
    }
}

/// How a probe runs: `<exec> <program> fence-probe <addr> --gid <gid>`.
#[derive(Clone, Debug)]
pub struct Probe {
    /// `orbd-netgroup`, setgid to the network group.
    pub exec: PathBuf,
    /// The orbd binary (`fence-probe`).
    pub program: PathBuf,
    pub group: String,
    pub gid: u32,
}

impl Probe {
    /// Tests the fence once (blocking, a few ms when it holds; up to ~15 s otherwise).
    pub fn run(&self) -> Result<(), String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|l| l.set_nonblocking(true).map(|()| l))
            .map_err(|e| format!("listening on 127.0.0.1: {e}"))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| {
            format!(
                "the agent's own connection to {addr} failed ({e}): something else blocks loopback"
            )
        })?;
        if accepted(&listener, Duration::from_secs(2)) == 0 {
            return Err(format!("the agent's own connection never reached {addr}"));
        }
        let spawn = || {
            Command::new(&self.exec)
                .arg(&self.program)
                .args([
                    PROBE_COMMAND,
                    &addr.to_string(),
                    "--gid",
                    &self.gid.to_string(),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
        };
        // ETXTBSY: a just-written executable is briefly held open for writing by a
        // process another thread forked (until it execs); retry shortly.
        let mut child = spawn();
        for _ in 0..20 {
            match &child {
                Err(e) if e.raw_os_error() == Some(nix::libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(25));
                    child = spawn();
                }
                _ => break,
            }
        }
        let mut child = child.map_err(|e| format!("{}: {e}", self.exec.display()))?;
        let status = wait_bounded(&mut child, PROBE_TIMEOUT);
        let mut stderr = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut stderr);
        }
        let stderr = stderr.trim();
        let leaked = accepted(&listener, Duration::ZERO) > 0;
        let group = &self.group;
        match status.and_then(|s| s.code()) {
            Some(PROBE_BLOCKED) if !leaked => Ok(()),
            Some(PROBE_BLOCKED | PROBE_CONNECTED) => Err(format!(
                "a connection with group {group} reached 127.0.0.1: pf does not block it (pf \
                 must be enabled, with rules blocking the group loaded and lo0 not skipped)"
            )),
            Some(PROBE_WRONG_GROUP) => Err(format!(
                "{} did not run its program with group {group} ({stderr})",
                self.exec.display()
            )),
            None if status.is_none() => {
                Err(format!("the probe did not finish in {PROBE_TIMEOUT:?}"))
            }
            _ => Err(format!(
                "the probe failed ({}): {stderr}",
                status.map_or("killed".into(), |s| s.to_string())
            )),
        }
    }
}

/// Connections accepted on `l` until `within` has passed (at least one try).
fn accepted(l: &TcpListener, within: Duration) -> usize {
    let deadline = Instant::now() + within;
    let mut n = 0;
    loop {
        match l.accept() {
            Ok(_) => n += 1,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if n > 0 || Instant::now() >= deadline {
                    return n;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return n,
        }
    }
}

/// Waits for `child` up to `limit`, killing it after; None if it had to be killed.
fn wait_bounded(
    child: &mut std::process::Child,
    limit: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[derive(Debug)]
enum Mode {
    /// Not macOS: QEMU orbs need no pf fence.
    NotNeeded,
    /// `ORBD_ALLOW_UNFENCED_EGRESS`.
    Unfenced,
    /// No way to fence orbs (why).
    Missing(String),
    Probe(Probe),
}

/// Whether QEMU orbs may start, as far as their egress fence goes. Cheap to clone.
#[derive(Clone, Debug)]
pub struct EgressFence(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    mode: Mode,
    /// When a probe last passed.
    verified: Mutex<Option<Instant>>,
}

impl EgressFence {
    /// `required`: this host needs the fence (macOS). `probe`: how to test it, None when
    /// `runtime.qemu.network_group` is not set.
    pub fn new(required: bool, allow_unfenced: bool, probe: Option<Probe>) -> Self {
        let mode = match (required, allow_unfenced, probe) {
            (false, _, _) => Mode::NotNeeded,
            (true, true, _) => Mode::Unfenced,
            (true, false, Some(p)) => Mode::Probe(p),
            (true, false, None) => Mode::Missing(
                "runtime.qemu.network_group is not set, so nothing keeps QEMU orbs off the \
                 LAN"
                .into(),
            ),
        };
        Self(Arc::new(Inner {
            mode,
            verified: Mutex::new(None),
        }))
    }

    /// Ok when QEMU orbs may start: a probe passed within [`FRESH`] (probing now if
    /// not), or no fence is needed. Blocking.
    pub fn check(&self) -> Result<(), String> {
        let explain = |why: &str| {
            format!(
                "QEMU orbs do not start without their egress fence: {why}; see the README's \
                 macOS section, or set ORBD_ALLOW_UNFENCED_EGRESS=true to run them unfenced"
            )
        };
        let probe = match &self.0.mode {
            Mode::NotNeeded | Mode::Unfenced => return Ok(()),
            Mode::Missing(why) => return Err(explain(why)),
            Mode::Probe(p) => p,
        };
        let fresh = |t: &Option<Instant>| t.is_some_and(|t| t.elapsed() < FRESH);
        if fresh(&self.0.verified.lock().unwrap_or_else(|e| e.into_inner())) {
            return Ok(());
        }
        let result = probe.run();
        let mut verified = self.0.verified.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(()) => {
                *verified = Some(Instant::now());
                Ok(())
            }
            Err(why) => {
                *verified = None;
                Err(explain(&why))
            }
        }
    }

    /// Logs whether the fence holds, once now and then every time it changes, probing
    /// every [`FRESH`] while the process runs (needs a tokio runtime; a no-op without a
    /// fence to probe).
    pub fn monitor(&self) {
        match &self.0.mode {
            Mode::NotNeeded => return,
            Mode::Unfenced => {
                tracing::warn!(
                    "QEMU orbs run without an egress fence (ORBD_ALLOW_UNFENCED_EGRESS): they \
                     reach whatever this Mac can, its LAN included"
                );
                return;
            }
            Mode::Missing(_) | Mode::Probe(_) => {}
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let fence = self.clone();
        handle.spawn(async move {
            let mut last: Option<bool> = None;
            loop {
                let f = fence.clone();
                let result = tokio::task::spawn_blocking(move || {
                    // A fresh probe each round, not the cached verdict.
                    *f.0.verified.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    f.check()
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()));
                metrics::gauge!("orbd_egress_fence_verified").set(f64::from(result.is_ok()));
                if last != Some(result.is_ok()) {
                    match &result {
                        Ok(()) => tracing::info!("egress fence verified: pf blocks QEMU orbs"),
                        Err(e) => tracing::error!(error = %e, "egress fence not verified"),
                    }
                    last = Some(result.is_ok());
                }
                if matches!(fence.0.mode, Mode::Missing(_)) {
                    return;
                }
                tokio::time::sleep(FRESH).await;
            }
        });
    }
}

/// The probe for `group` through `exec` (`orbd-netgroup`), run with this orbd binary.
pub fn probe_for(exec: &Path, group: &str) -> Result<Probe, String> {
    let gid = nix::unistd::Group::from_name(group)
        .map_err(|e| format!("group {group}: {e}"))?
        .ok_or_else(|| format!("group {group} does not exist"))?
        .gid
        .as_raw();
    let program = std::env::current_exe().map_err(|e| format!("finding orbd's binary: {e}"))?;
    Ok(Probe {
        exec: exec.to_owned(),
        program,
        group: group.to_owned(),
        gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// A probe whose `orbd-netgroup` runs its program as is and whose program is `body`
    /// (args: fence-probe <addr> --gid <gid>).
    fn probe(dir: &Path, body: &str) -> Probe {
        Probe {
            // The program runs under bash rather than by exec: a script written a
            // moment ago can be ETXTBSY while another test's fork holds it open.
            exec: script(dir, "netgroup", r#"exec bash "$@""#),
            program: script(dir, "orbd", body),
            group: "orbdvm".into(),
            gid: nix::unistd::getegid().as_raw(),
        }
    }

    /// Connects to the address `fence-probe` is given.
    const CONNECT_ONLY: &str = r#"a=$2; exec 3<>/dev/tcp/${a%:*}/${a##*:}"#;
    /// What `fence-probe` does when pf lets it through.
    const CONNECT: &str = r#"a=$2; exec 3<>/dev/tcp/${a%:*}/${a##*:} && exit 0"#;

    #[test]
    fn probe_passes_only_when_the_grouped_connection_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(probe(d, "exit 3").run(), Ok(()));
        let e = probe(d, CONNECT).run().unwrap_err();
        assert!(e.contains("pf does not block it"), "{e}");
        // Reports blocked, but the connection went through anyway.
        let e = probe(d, &format!("{CONNECT_ONLY}; exit 3"))
            .run()
            .unwrap_err();
        assert!(e.contains("reached 127.0.0.1"), "{e}");
        let e = probe(d, "echo 'running with group 20, not 401' >&2; exit 4")
            .run()
            .unwrap_err();
        assert!(
            e.contains("did not run its program with group orbdvm"),
            "{e}"
        );
        let e = probe(d, "echo boom >&2; exit 7").run().unwrap_err();
        assert!(e.contains("boom"), "{e}");
        let mut missing = probe(d, "exit 3");
        missing.exec = d.join("nonexistent");
        assert!(missing.run().is_err());
    }

    #[test]
    fn fence_probe_subcommand_reports_what_happened() {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let open = l.local_addr().unwrap();
        let gid = nix::unistd::getegid().as_raw();
        assert_eq!(probe_main(open, gid), PROBE_CONNECTED);
        assert_eq!(probe_main(open, gid.wrapping_add(1)), PROBE_WRONG_GROUP);
        // A port this connection holds, where nothing listens: connections are refused.
        let held = TcpStream::connect(open).unwrap();
        let closed = held.local_addr().unwrap();
        assert_eq!(probe_main(closed, gid), PROBE_BLOCKED, "nothing listens");
    }

    #[test]
    fn fence_policy() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // Elsewhere than macOS nothing is probed.
        assert!(EgressFence::new(false, false, None).check().is_ok());
        assert!(
            EgressFence::new(false, false, Some(probe(d, CONNECT)))
                .check()
                .is_ok()
        );
        // macOS without a network group: refused unless explicitly unfenced.
        let e = EgressFence::new(true, false, None).check().unwrap_err();
        assert!(
            e.contains("network_group") && e.contains("ORBD_ALLOW_UNFENCED_EGRESS"),
            "{e}"
        );
        assert!(EgressFence::new(true, true, None).check().is_ok());
        assert!(
            EgressFence::new(true, true, Some(probe(d, CONNECT)))
                .check()
                .is_ok()
        );
        let e = EgressFence::new(true, false, Some(probe(d, CONNECT)))
            .check()
            .unwrap_err();
        assert!(e.contains("pf does not block it"), "{e}");
    }

    /// A passing probe vouches for [`FRESH`]; a failing one is retried on every check.
    #[test]
    fn verdicts_are_cached_only_when_the_fence_holds() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let count = d.join("count");
        let body = format!(
            "echo x >>{c}; [ -e {d}/open ] && {{ {CONNECT}; }}; exit 3",
            c = count.display(),
            d = d.display()
        );
        let fence = EgressFence::new(true, false, Some(probe(d, &body)));
        let runs = || {
            std::fs::read_to_string(&count)
                .unwrap_or_default()
                .lines()
                .count()
        };
        fence.check().unwrap();
        fence.check().unwrap();
        assert_eq!(runs(), 1, "a passing probe is reused while fresh");
        *fence.0.verified.lock().unwrap() = Some(Instant::now() - FRESH);
        std::fs::write(d.join("open"), "").unwrap();
        assert!(fence.check().is_err(), "a stale verdict is probed again");
        assert!(fence.check().is_err());
        assert_eq!(runs(), 3, "a failing probe is not cached");
    }
}
