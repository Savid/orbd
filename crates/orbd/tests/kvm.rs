//! Opt-in KVM gate tests for the VM runtimes: real VMs through a real coordinator, agent
//! and `orbd dispatch`. Ignored by default. Run as root on a host with `/dev/kvm` and
//! nested virtualization, one at a time, for `ORBD_KVM_RUNTIME=qemu` (the default; QEMU
//! 9.0 or newer) or `firecracker` (needs `firecracker`, `ip` and `nft`):
//!
//! ```sh
//! guest/kernel/build.sh /tmp/k        # or any kernel with orbd's config
//! crates/orbd/tests/kvm-guest/build-rootfs.sh <orbd-guest> /tmp/k/bzImage /tmp/rootfs.ext4
//! ORBD_KVM_KERNEL=/tmp/k/bzImage ORBD_KVM_ROOTFS=/tmp/rootfs.ext4 ORBD_KVM_RUNTIME=qemu \
//!   cargo test -p orbd --features failpoints --test kvm -- --ignored --test-threads=1
//! ```
//!
//! The guest prints a process counter and a nested KVM guest's counter to its serial
//! console. A memory restore must continue both sequences: a counter that restarts means
//! processes were lost, one that repeats or goes back means stale RAM was replayed.
//! Firecracker orbs have no `/dev/kvm`, so there the nested guest must not run at all.
//!
//! On Linux every VMM must run jailed (its own uid, no capabilities, only its orb's files)
//! in its orb's own network namespace behind orbd's egress filter, checked from outside.
//! The upgrade gate needs the previous release's binaries, `ORBD_KVM_PREVIOUS_AGENT=<orbd>`
//! and `ORBD_KVM_PREVIOUS_GUEST=<orbd-guest>` (put into a copy of the root disk with
//! `debugfs`), and fails without them unless `ORBD_KVM_PREVIOUS_AGENT=skip`. Only the
//! agent binary is the previous release's: VMMs, kernel and image are this tree's.
//!
//! On an Apple Silicon Mac (QEMU with Hypervisor.framework; arm64 orbs, no `/dev/kvm`)
//! run as your user with `ORBD_KVM_NESTED=0 TMPDIR=/tmp` (the default temp dir makes
//! socket paths too long), an arm64 `Image` and a rootfs from `ARCH=arm64
//! build-rootfs.sh` (built in a privileged linux/arm64 container). Orbs there run
//! without the pf egress fence unless `ORBD_KVM_NETWORK_GROUP` names the fenced group
//! (`runtime.qemu.network_group`), whose fence the agent then verifies.
#![cfg(feature = "failpoints")]

mod common;
use common::*;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const IMAGE: &str = "example.invalid/amp-orb:latest";
const MEMORY_MIB: u64 = 1024;

/// The runtime under test: `qemu` or `firecracker`.
fn runtime() -> String {
    std::env::var("ORBD_KVM_RUNTIME").unwrap_or_else(|_| "qemu".into())
}

/// A crash or fault point of the runtime under test, e.g. `save::after_stop`.
fn point(name: &str) -> String {
    format!("{}::{name}", runtime())
}

fn cluster(orbs: u64) -> Cluster {
    cluster_on(
        orbs,
        &std::env::var("ORBD_KVM_ROOTFS").expect("set ORBD_KVM_ROOTFS"),
    )
}

/// A cluster whose image is the root disk `rootfs`.
fn cluster_on(orbs: u64, rootfs: &str) -> Cluster {
    let kernel = std::env::var("ORBD_KVM_KERNEL").expect("set ORBD_KVM_KERNEL");
    let rt = runtime();
    if rt == "qemu" && !nested() {
        eprintln!("NOTICE: ORBD_KVM_NESTED=0: the nested KVM guest assertions are SKIPPED");
    }
    let group = std::env::var("ORBD_KVM_NETWORK_GROUP").ok();
    let network_group = match &group {
        Some(g) => format!("\n    network_group: {g}"),
        None => String::new(),
    };
    let mut c = Cluster::with_runtime(
        &["agent-a"],
        orbs,
        &rt,
        &format!(
            r#"runtime:
  {rt}:
    kernel: {kernel}{network_group}
images:
  static_images:
    - {{ image_ref: "{IMAGE}", rootfs: {rootfs} }}
"#
        ),
    );
    // macOS starts QEMU orbs only behind a verified pf fence.
    if cfg!(target_os = "macos") && group.is_none() {
        eprintln!("NOTICE: no ORBD_KVM_NETWORK_GROUP: orbs run without the egress fence");
        c.agent_env
            .push(("ORBD_ALLOW_UNFENCED_EGRESS".into(), "true".into()));
    }
    c
}

/// First uid of jailed VMMs (`ORBD_VMM_JAIL_UID_BASE`'s default).
#[cfg(target_os = "linux")]
const JAIL_UID_BASE: u32 = 1_300_000_000;

/// Kills every VMM started under this cluster, even when a test fails.
struct Vms(PathBuf);

impl Drop for Vms {
    fn drop(&mut self) {
        for pid in vmm_pids(&self.0) {
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status();
        }
    }
}

fn state(c: &Cluster) -> PathBuf {
    c.root().join("agents/agent-a/state")
}

/// VMM processes (QEMU, Firecracker) whose arguments point into `root`.
#[cfg(target_os = "linux")]
fn vmm_pids(root: &std::path::Path) -> Vec<i32> {
    let needle = root.display().to_string();
    let mut pids = Vec::new();
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else {
            continue;
        };
        let cmd = String::from_utf8_lossy(&cmd);
        let program = cmd.split('\0').next().unwrap_or_default();
        let vmm = program.ends_with("qemu-system-x86_64") || program.ends_with("firecracker");
        if vmm && cmd.contains(&needle) {
            pids.push(pid);
        }
    }
    pids
}

/// VMM processes (QEMU) whose arguments point into `root`.
#[cfg(not(target_os = "linux"))]
fn vmm_pids(root: &std::path::Path) -> Vec<i32> {
    let needle = root.display().to_string();
    let out = std::process::Command::new("ps")
        .args(["-axww", "-o", "pid=,command="])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (pid, cmd) = l.trim().split_once(' ')?;
            let vmm = cmd.split(' ').next()?.ends_with("qemu-system-aarch64");
            (vmm && cmd.contains(&needle)).then(|| pid.parse().ok())?
        })
        .collect()
}

/// The VMM of the orb at `orb` (its id is in the VMM's arguments).
#[cfg(target_os = "linux")]
fn vmm_pid(orb: &Path) -> Option<i32> {
    let id = orb.file_name().unwrap().to_string_lossy().into_owned();
    let root = orb.ancestors().nth(4).unwrap();
    vmm_pids(root).into_iter().find(|pid| {
        std::fs::read(format!("/proc/{pid}/cmdline"))
            .is_ok_and(|c| String::from_utf8_lossy(&c).contains(&id))
    })
}

/// A field of `/proc/<pid>/status`, split into its values.
#[cfg(target_os = "linux")]
fn status(pid: i32, field: &str) -> Vec<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    s.lines()
        .find_map(|l| l.strip_prefix(field))
        .unwrap_or_else(|| panic!("no {field} in /proc/{pid}/status"))
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// The VMM `pid` of the orb at `orb` runs jailed: its own unprivileged uid and gid,
/// no capabilities, `no_new_privs`, its seccomp filter, and a mount namespace with this
/// orb's files and nothing of the agent's state or other orbs. Returns its uid.
#[cfg(target_os = "linux")]
fn assert_jailed(c: &Cluster, orb: &Path, pid: i32) -> u32 {
    let uid = status(pid, "Uid:");
    let gid = status(pid, "Gid:");
    assert!(
        uid.iter().all(|u| *u == uid[0]),
        "real, effective, saved, fs uid: {uid:?}"
    );
    assert_eq!(uid, gid, "the orb's gid is its uid");
    let n: u32 = uid[0].parse().unwrap();
    assert!(n > JAIL_UID_BASE, "VMM {pid} runs as uid {n}, not a jail's");
    for cap in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        assert_eq!(status(pid, cap), ["0000000000000000"], "{cap} of VMM {pid}");
    }
    assert_eq!(status(pid, "NoNewPrivs:"), ["1"]);
    assert_eq!(
        status(pid, "Seccomp:"),
        ["2"],
        "the VMM's own seccomp filter"
    );
    let root = PathBuf::from(format!("/proc/{pid}/root"));
    let inside = |p: &Path| root.join(p.strip_prefix("/").unwrap());
    assert!(
        inside(orb).join("vm.json").exists(),
        "its orb's files are there"
    );
    let st = state(c);
    for hidden in [
        st.join("identity"),
        st.join("agent.sqlite"),
        c.root().join("coordinator"),
        "/proc/self".into(),
        "/sys/kernel".into(),
        "/etc/passwd".into(),
        "/var/run/docker.sock".into(),
    ] {
        assert!(
            !inside(&hidden).exists(),
            "VMM {pid} can see {}",
            hidden.display()
        );
    }
    let names = |dir: &Path| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(inside(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    let own = orb.file_name().unwrap().to_string_lossy().into_owned();
    assert_eq!(
        names(&st.join("orbs")),
        std::slice::from_ref(&own),
        "no other orbs"
    );
    for n in names(&st) {
        assert!(
            ["orbs", "run", "projects", "images"].contains(&n.as_str()),
            "VMM {pid} sees {n} in the agent's state"
        );
    }
    // Its launch's run directory is its own socket directory, without the launch record.
    let rt = runtime();
    let run = st.join("run").join(&rt).join(&own);
    assert!(!inside(&run).join("launch.json").exists());
    assert!(run.join("launch.json").exists());
    n
}

/// The orb's VMM runs in the orb's own network namespace on a TAP it owns, and a
/// private destination this agent reaches (the container's gateway) is unreachable from
/// there: orbd's egress filter.
#[cfg(target_os = "linux")]
fn assert_own_network(orb: &Path, pid: i32, uid: Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    let ns = format!("orbd-{}", orb.file_name().unwrap().to_string_lossy());
    let ino = |p: &str| std::fs::metadata(p).unwrap().ino();
    assert_eq!(
        ino(&format!("/proc/{pid}/ns/net")),
        ino(&format!("/run/netns/{ns}")),
        "VMM {pid} runs in {ns}"
    );
    if let Some(uid) = uid {
        let out = std::process::Command::new("ip")
            .args(["-j", "-d", "-n", &ns, "link", "show", "tap0"])
            .output()
            .unwrap();
        let json = String::from_utf8_lossy(&out.stdout);
        assert!(
            json.contains(&format!("\"user\":{uid},")),
            "tap0 in {ns} is owned by {uid}: {json}"
        );
    }
    let route = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .unwrap();
    let route = String::from_utf8_lossy(&route.stdout);
    let gw: Option<std::net::Ipv4Addr> = route
        .split_whitespace()
        .skip_while(|w| *w != "via")
        .nth(1)
        .and_then(|a| a.parse().ok());
    let Some(gw) = gw.filter(|g| g.is_private()) else {
        eprintln!("NOTICE: no private default gateway ({route:?}): egress probe SKIPPED");
        return;
    };
    let probe = |netns: Option<&str>| {
        let mut cmd = match netns {
            Some(ns) => {
                let mut c = std::process::Command::new("ip");
                c.args(["netns", "exec", ns, "timeout"]);
                c
            }
            None => std::process::Command::new("timeout"),
        };
        cmd.args(["3", "bash", "-c", &format!("exec 3<>/dev/tcp/{gw}/1")])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .code()
    };
    if probe(None) == Some(124) {
        eprintln!("NOTICE: {gw}:1 does not answer this agent either: egress probe SKIPPED");
        return;
    }
    assert_eq!(
        probe(Some(&ns)),
        Some(124),
        "{gw} (private) must be unreachable from {ns}"
    );
}

/// On Linux the orb's VMM runs jailed, in the orb's own filtered network namespace;
/// returns its uid.
fn assert_isolated(c: &Cluster, orb: &Path) -> u32 {
    #[cfg(target_os = "linux")]
    {
        let pid = vmm_pid(orb).expect("the orb's VMM runs");
        let uid = assert_jailed(c, orb, pid);
        assert_own_network(orb, pid, Some(uid));
        uid
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (c, orb);
        0
    }
}

/// Private TCP destinations this agent reaches, each answering it (if only with a
/// reset): its own address and its default gateway (Docker's bridge in the gates'
/// container). Port 1: nothing listens there.
#[cfg(target_os = "linux")]
fn private_targets() -> Vec<String> {
    let ip = |args: &[&str]| {
        let out = std::process::Command::new("ip")
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let gateway = ip(&["-4", "route", "show", "default"]);
    let gateway = gateway
        .split_whitespace()
        .skip_while(|w| *w != "via")
        .nth(1);
    let own = ip(&["-4", "-o", "addr", "show", "scope", "global"]);
    let own = own
        .split_whitespace()
        .skip_while(|w| *w != "inet")
        .nth(1)
        .and_then(|a| a.split('/').next());
    let answers = |a: &str| {
        // A reset (refused) or an accept, not a timeout.
        std::process::Command::new("timeout")
            .args(["3", "bash", "-c", &format!("exec 3<>/dev/tcp/{a}/1")])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .code()
            != Some(124)
    };
    let mut targets = Vec::new();
    for a in [own, gateway].into_iter().flatten() {
        let private = a
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|a| a.is_private());
        if private && answers(a) {
            targets.push(format!("{a}:1"));
        } else {
            eprintln!("NOTICE: {a} is not a private address answering this agent: not probed");
        }
    }
    targets
}

/// Spawn environment for the test guest's bootstrap to probe `targets` (`E2E_PROBE`).
fn probe_env(targets: &str) -> [(&'static str, &str); 2] {
    [
        ("E2E_PROBE", targets),
        (
            "ORB_ENVS",
            "AMP_URL ORB_TOKEN AMP_THREAD_ID AMP_SANDBOX_ID E2E_PROBE",
        ),
    ]
}

/// The guest found every target dropped (a dropped probe takes 5 s).
fn assert_probes_dropped(orb: &Path, targets: &[String]) {
    let deadline = Instant::now() + Duration::from_secs(60);
    for t in targets {
        let result = loop {
            let found = printed(orb).lines().rev().find_map(|l| {
                l.strip_prefix(&format!("probe {t} "))
                    .map(|r| r.trim().to_owned())
            });
            if let Some(r) = found {
                break r;
            }
            assert!(
                Instant::now() < deadline,
                "the guest did not probe {t}; console tail:\n{}",
                tail(&console(orb))
            );
            std::thread::sleep(Duration::from_millis(500));
        };
        assert_eq!(
            result, "dropped",
            "the guest reaches {t}, a private address"
        );
        eprintln!("guest probe {t}: {result}");
    }
}

/// The console without the kernel's own messages (`[    1.801470] ...` to the end of its
/// line): printk can land in the middle of a line a guest service is printing, splitting
/// it (Yama reports the very ptrace denial the security check provokes). orbd-guest's
/// lines (through journald, with the same prefix) go too: read those from [`console`].
fn without_kernel_messages(console: &str) -> String {
    let mut out = String::with_capacity(console.len());
    let mut rest = console;
    while let Some(i) = rest.find('[') {
        let stamp = rest[i + 1..]
            .find(']')
            .map(|j| rest[i + 1..i + 1 + j].trim());
        if stamp
            .is_some_and(|t| t.contains('.') && t.chars().all(|c| c.is_ascii_digit() || c == '.'))
        {
            out.push_str(&rest[..i]);
            rest = rest[i..].find('\n').map_or("", |n| &rest[i + n + 1..]);
        } else {
            out.push_str(&rest[..=i]);
            rest = &rest[i + 1..];
        }
    }
    out.push_str(rest);
    out
}

/// What CI's QEMU guest printed: kernel lines landing inside the security check's.
#[test]
fn kernel_messages_are_taken_out() {
    let console = "security: net.core.bpf_jit_harde[    1.801470] e2scrub_all (153) used \
                   greatest stack depth: 12288 bytes left\nn=2\nsecurity: user-m[    1.831064] \
                   ptrace attach of \"sh\" was attempted by \"sh\"\nem-parent=denied\n\
                   [    2.000000] a whole kernel line\nsecurity: lsm=[x] kept\n";
    assert_eq!(
        without_kernel_messages(console),
        "security: net.core.bpf_jit_harden=2\nsecurity: user-mem-parent=denied\n\
         security: lsm=[x] kept\n"
    );
}

/// The guest kernel's hardening, as `orbd-test-security` reports it on the console
/// (`security: <name>=<value>`): the LSMs, the sysctls of guest/rootfs/etc/sysctl.d, and
/// what `user` may do without capabilities.
const GUEST_SECURITY: &[(&str, &str)] = &[
    ("lsm", "capability,landlock,yama"),
    ("kernel.yama.ptrace_scope", "1"),
    ("kernel.kptr_restrict", "1"),
    ("kernel.dmesg_restrict", "1"),
    ("kernel.unprivileged_bpf_disabled", "1"),
    ("net.core.bpf_jit_harden", "2"),
    ("fs.suid_dumpable", "0"),
    ("dev.tty.legacy_tiocsti", "0"),
    ("vm.mmap_min_addr", "65536"),
    // Root keeps the kernel log: `sudo dmesg` works.
    ("root-dmesg", "allowed"),
    ("user-dmesg", "denied"),
    // Yama: the memory of a child, not of the parent. The parent's environment is read
    // access, which Yama leaves alone (README, "Inside an orb").
    ("user-mem-child", "allowed"),
    ("user-mem-parent", "denied"),
    ("user-environ-parent", "allowed"),
    // Unprivileged user namespaces still work (bwrap, unshare, rootless containers).
    ("user-userns", "allowed"),
];

fn assert_guest_security(orb: &Path) {
    let want: Vec<String> = GUEST_SECURITY
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let console = printed(orb);
        let reported: Vec<&str> = console
            .lines()
            .filter_map(|l| l.trim().strip_prefix("security: "))
            .collect();
        let missing: Vec<&String> = want
            .iter()
            .filter(|w| !reported.contains(&w.as_str()))
            .collect();
        if missing.is_empty() {
            eprintln!("guest security: {}", want.join(" "));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "guest hardening: want {missing:?}; the guest reported {reported:?}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The cluster's orb directories, oldest orb first (orb ids are time-ordered).
fn orb_dirs(c: &Cluster) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(state(c).join("orbs"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    dirs.sort();
    dirs
}

fn orb_dir(c: &Cluster) -> PathBuf {
    let mut dirs = orb_dirs(c);
    assert_eq!(dirs.len(), 1, "expected one orb");
    dirs.pop().unwrap()
}

/// The orb's serial console. A VMM killed mid-character leaves invalid UTF-8 behind.
fn console(orb: &Path) -> String {
    String::from_utf8_lossy(&std::fs::read(orb.join("logs/console.log")).unwrap_or_default())
        .into_owned()
}

/// What the guest's test services printed: the console without kernel messages.
fn printed(orb: &Path) -> String {
    without_kernel_messages(&console(orb))
}

/// `text` from byte `from` on (from the character there, if it starts inside one).
fn since(text: &str, from: usize) -> &str {
    let mut i = from.min(text.len());
    while !text.is_char_boundary(i) {
        i -= 1;
    }
    &text[i..]
}

/// The agent's log, without colours (`\x1b[...m`).
fn agent_log(c: &Cluster) -> String {
    let log = std::fs::read(c.root().join("agent-agent-a.log")).unwrap_or_default();
    let log = String::from_utf8_lossy(&log);
    let mut plain = String::with_capacity(log.len());
    let mut chars = log.chars();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            chars.by_ref().find(|c| c.is_ascii_alphabetic());
        } else {
            plain.push(ch);
        }
    }
    plain
}

/// Counter samples in console order: `(pid, n)` for the process counter and `n` for
/// the nested guest. A kernel message inside a counter line would otherwise read as a
/// counter going back.
fn samples(console: &str) -> (Vec<(u32, u64)>, Vec<u64>) {
    let num = |s: &str| -> Option<u64> {
        let d: String = s.chars().take_while(char::is_ascii_digit).collect();
        d.parse().ok()
    };
    let (mut counter, mut l2) = (Vec::new(), Vec::new());
    for line in without_kernel_messages(console).lines() {
        if let Some(rest) = line.strip_prefix("counter pid=")
            && let Some((pid, n)) = rest.split_once(" n=")
            && let (Some(pid), Some(n)) = (num(pid), num(n))
        {
            counter.push((pid as u32, n));
        } else if let Some(rest) = line.strip_prefix("l2: l2counter n=")
            && let Some(n) = num(rest)
        {
            l2.push(n);
        }
    }
    (counter, l2)
}

/// Whether the orb's nested guest runs: on QEMU when the host's KVM nests
/// (`ORBD_KVM_NESTED=0` skips only the nested-guest checks), never on Firecracker.
fn nested() -> bool {
    runtime() == "qemu" && std::env::var("ORBD_KVM_NESTED").map_or(true, |v| v != "0")
}

/// Waits until both counters advanced by at least two since `after`.
fn wait_progress(orb: &Path, after: (usize, usize)) -> ((u32, u64), u64) {
    let deadline = Instant::now() + Duration::from_secs(90);
    let nested = nested();
    loop {
        let (counter, l2) = samples(&console(orb));
        if counter.len() >= after.0 + 2 && (!nested || l2.len() >= after.1 + 2) {
            return (*counter.last().unwrap(), l2.last().copied().unwrap_or(0));
        }
        assert!(
            Instant::now() < deadline,
            "guest counters did not advance; console tail:\n{}",
            tail(&console(orb))
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Starts the (stopped) agent once the coordinator has seen its last session end, so no
/// job is sent to a session that is already dead.
fn start_again(c: &mut Cluster, failpoints: &str) {
    wait_until(Duration::from_secs(20), "agent session ended", || {
        c.connected_agents() == Some(0)
    });
    c.start_agent("agent-a", failpoints);
    c.wait_connected(1);
}

fn counts(orb: &Path) -> (usize, usize) {
    let (a, b) = samples(&console(orb));
    (a.len(), b.len())
}

fn tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().rev().take(30).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

/// Every counter sample since the first boot strictly increases: no restart (processes
/// lost) and no repeat (stale RAM replayed). Same for the nested guest's counter.
fn assert_continuous(orb: &Path) {
    let (counter, l2) = samples(&console(orb));
    let n: Vec<u64> = counter.iter().map(|(_, n)| *n).collect();
    assert!(
        n.windows(2).all(|w| w[1] > w[0]),
        "process counter restarted, repeated or went back: {n:?}"
    );
    assert!(
        l2.windows(2).all(|w| w[1] > w[0]),
        "nested guest counter restarted, repeated or went back: {l2:?}"
    );
}

/// Memory files: (checkpoint directory, apparent size, allocated bytes).
fn checkpoint_files(orb: &Path) -> Vec<(String, u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(orb.join("checkpoints")) {
        for e in rd.flatten() {
            let mem = e.path().join("memory");
            if let Ok(m) = std::fs::metadata(&mem) {
                out.push((
                    e.file_name().to_string_lossy().into(),
                    m.len(),
                    m.blocks() * 512,
                ));
            }
        }
    }
    out
}

/// Sleep → wake keeps a running process and a nested KVM guest (QEMU; a Firecracker orb
/// has no `/dev/kvm`), sleeping orbs hold no VMM process, and a restarted agent adopts
/// the running VM instead of booting another.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn sleep_preserves_processes_and_nested_guest() {
    let mut c = cluster(1);
    let _vms = Vms(c.root().to_owned());
    c.start_all();

    // On Linux the orb has its own filtered network: private destinations that answer
    // this agent are dropped for it.
    #[cfg(target_os = "linux")]
    let targets = private_targets();
    #[cfg(not(target_os = "linux"))]
    let targets: Vec<String> = Vec::new();
    let t = Instant::now();
    assert_ok(
        &c.dispatch("spawn", "amp-1", &probe_env(&targets.join(" "))),
        "first spawn",
    );
    eprintln!("cold spawn (create, boot, Wake ack): {:?}", t.elapsed());
    wait_progress(&orb_dir(&c), (0, 0));
    // orbd-test-dns leaves resolv.conf as a killed tailscaled would, after the first
    // Wake; orbd-guest must restore its own before any other wake.
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let console = console(&orb_dir(&c));
        let unit = without_kernel_messages(&console);
        // The unit's own line can reach the console before orbd-guest's (via journald).
        if unit.contains("stale-dns: restored")
            && console.contains("dns: tailscaled is not running but its /etc/resolv.conf")
        {
            break;
        }
        assert!(
            Instant::now() < deadline
                && !unit.contains("stale-dns: still stale")
                && !unit.contains("stale-dns: orbd-guest never wrote"),
            "orbd-guest's watcher did not restore a stale Tailscale resolv.conf; console tail:\n{}",
            tail(&console)
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let console = console(&orb_dir(&c));
    assert!(
        console.contains("landlock: Up and running."),
        "the guest kernel must enable Landlock"
    );
    // Read as `user` (securityfs is readable without root); the exact list is checked
    // by assert_guest_security.
    assert!(
        console.contains("guest lsm: capability,landlock,yama"),
        "/sys/kernel/security/lsm must list Landlock and Yama; console tail:\n{}",
        tail(&console)
    );
    // ABI 8 added LANDLOCK_RESTRICT_SELF_TSYNC; multithreaded sandboxers (go-landlock)
    // otherwise signal every thread, which seccomp filters blocking tkill break.
    let abi: i64 = console
        .lines()
        .find_map(|l| l.split("guest landlock abi: ").nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("no Landlock ABI on the console; tail:\n{}", tail(&console)));
    assert!(
        abi >= 8,
        "the guest kernel's Landlock ABI is {abi}, need >= 8 (TSYNC)"
    );
    assert_guest_security(&orb_dir(&c));
    if runtime() == "firecracker" {
        assert!(
            console.contains("/dev/kvm is missing") && !console.contains("l2counter"),
            "a Firecracker orb must have no /dev/kvm"
        );
    }
    let uid = assert_isolated(&c, &orb_dir(&c));
    assert_probes_dropped(&orb_dir(&c), &targets);

    // The second round saves a VM that was itself restored.
    for round in 1..=2 {
        let before = counts(&orb_dir(&c));
        let t = Instant::now();
        assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause");
        let sleep_time = t.elapsed();
        assert!(
            vmm_pids(c.root()).is_empty(),
            "a sleeping orb must not hold a VMM process"
        );
        let files = checkpoint_files(&orb_dir(&c));
        assert_eq!(
            files.len(),
            1,
            "exactly one published checkpoint: {files:?}"
        );
        eprintln!(
            "round {round}: sleep {sleep_time:?}, checkpoint {} = {} MiB written ({} MiB sparse file) for {MEMORY_MIB} MiB RAM",
            files[0].0,
            files[0].2 >> 20,
            files[0].1 >> 20
        );
        assert!(files[0].1 < (MEMORY_MIB + 256) << 20);

        let t = Instant::now();
        let job = c.dispatch("spawn", "amp-1", &[]);
        assert_ok(&job, "wake");
        let restored = job
            .stdout
            .lines()
            .chain(job.stderr.lines())
            .filter(|l| l.contains("restored checkpoint") || l.contains("guest "))
            .collect::<Vec<_>>()
            .join("; ");
        eprintln!("round {round}: wake {:?} ({restored})", t.elapsed());
        assert!(
            checkpoint_files(&orb_dir(&c)).is_empty(),
            "the restored checkpoint is discarded"
        );
        wait_progress(&orb_dir(&c), before);
        assert_continuous(&orb_dir(&c));
    }
    assert_eq!(
        assert_isolated(&c, &orb_dir(&c)),
        uid,
        "a restored VMM is jailed as the orb"
    );

    // Agent crash with the VM running: the restarted agent adopts it.
    let before = counts(&orb_dir(&c));
    c.kill_agent("agent-a");
    let vms = vmm_pids(c.root());
    assert_eq!(vms.len(), 1, "the VMM must outlive the agent");
    start_again(&mut c, "");
    assert_ok(
        &c.dispatch("spawn", "amp-1", &[]),
        "spawn after agent restart",
    );
    assert_eq!(vmm_pids(c.root()), vms, "the running VM was adopted");
    wait_progress(&orb_dir(&c), before);
    assert_continuous(&orb_dir(&c));
    assert_eq!(assert_isolated(&c, &orb_dir(&c)), uid);

    assert_ok(&c.dispatch("delete", "amp-1", &[]), "delete");
    assert!(vmm_pids(c.root()).is_empty());
    assert!(
        std::fs::read_dir(state(&c).join("orbs"))
            .unwrap()
            .next()
            .is_none()
    );
}

/// The agent is killed (abort, like a power cut) at every publication boundary of a
/// save and a restore. After it restarts, the interrupted operation converges: a
/// pause ends with no VM process, a spawn with a running VM, and the guest's counters
/// never restart or replay.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn agent_crash_at_publication_boundaries_never_replays_stale_ram() {
    let mut c = cluster(1);
    let _vms = Vms(c.root().to_owned());
    c.start_all();
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "first spawn");
    wait_progress(&orb_dir(&c), (0, 0));

    // Every boundary below runs against a VM that was itself restored.
    let before = counts(&orb_dir(&c));
    assert_ok(&c.dispatch("pause", "amp-1", &[]), "warm-up pause");
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "warm-up wake");
    wait_progress(&orb_dir(&c), before);

    let crash = |c: &mut Cluster, op: &str, point: &str| {
        let before = counts(&orb_dir(c));
        let mark = agent_log(c).len();
        c.kill_agent("agent-a");
        // QEMU writes the memory file itself: slowed down, it is still writing when the
        // agent dies right after starting the save. (Firecracker's crash point waits until
        // Firecracker is writing.)
        let throttle = if point == "qemu::save::after_migrate" {
            ";qemu::save::throttle=return(32)"
        } else {
            ""
        };
        start_again(c, &format!("{point}=return{throttle}"));
        let job = c.dispatch_bg(op, "amp-1", &[]);
        c.wait_agent_crash("agent-a", Duration::from_secs(120));
        c.start_agent("agent-a", "");
        let job = job.join().unwrap();
        assert_ok(&job, &format!("{op} interrupted at {point}"));
        let vms = vmm_pids(c.root()).len();
        match op {
            "pause" => {
                assert_eq!(vms, 0, "{point}: a paused orb must not run");
                assert_eq!(
                    checkpoint_files(&orb_dir(c)).len(),
                    1,
                    "{point}: one checkpoint"
                );
            }
            _ => {
                assert_eq!(vms, 1, "{point}: a spawned orb must run");
                wait_progress(&orb_dir(c), before);
            }
        }
        let logs = agent_log(c);
        let recovery: Vec<&str> = logs[mark..]
            .lines()
            .filter(|l| {
                l.contains("orbd::runtime::") && (l.contains(" WARN ") || l.contains("ERROR"))
            })
            .filter_map(|l| l.split_once("orbd::runtime::").map(|(_, r)| r))
            .collect();
        eprintln!("{op} crash at {point}: converged; runtime recovery: {recovery:?}");
    };

    for p in [
        point("save::after_stop"),
        point("save::after_migrate"),
        point("save::after_manifest"),
        point("save::after_quit"),
        point("save::after_publish"),
        "agent::pause::after_stop".into(),
    ] {
        crash(&mut c, "pause", &p);
        let before = counts(&orb_dir(&c));
        assert_ok(&c.dispatch("spawn", "amp-1", &[]), "wake");
        wait_progress(&orb_dir(&c), before);
        assert_continuous(&orb_dir(&c));
    }
    for p in [
        // Before the launch record has the VMM's pid: adopted, not duplicated.
        "vm::launch::after_exec".into(),
        point("restore::after_load"),
        point("restore::after_consume"),
        "agent::spawn::after_start".into(),
    ] {
        assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause");
        crash(&mut c, "spawn", &p);
        assert_continuous(&orb_dir(&c));
    }

    // Disk full mid-save under the cold-stop policy: the pause fails with processes
    // lost, the VM is shut down, and the next spawn cold-boots without replaying RAM.
    c.kill_agent("agent-a");
    // A save that fills the disk fails; injected while it is still in progress.
    start_again(
        &mut c,
        &format!(
            "{};{}",
            point("save::throttle=return(32)"),
            point("save::write=3*off->return")
        ),
    );
    let job = c.dispatch("pause", "amp-1", &[]);
    assert_ne!(job.code, 0, "an injected ENOSPC must fail the pause");
    assert!(
        vmm_pids(c.root()).is_empty(),
        "cold-stop policy stops the VM"
    );
    assert!(
        checkpoint_files(&orb_dir(&c)).is_empty(),
        "the partial checkpoint is gone"
    );
    // A restarted counter shows up as its count going down.
    let boots = |c: &Cluster| {
        let n: Vec<u64> = samples(&console(&orb_dir(c)))
            .0
            .iter()
            .map(|(_, n)| *n)
            .collect();
        n.windows(2).filter(|w| w[1] < w[0]).count()
    };
    let boots_before = boots(&c);
    let before = counts(&orb_dir(&c));
    assert_ok(
        &c.dispatch("spawn", "amp-1", &[]),
        "cold boot after failed save",
    );
    wait_progress(&orb_dir(&c), before);
    assert_eq!(
        boots(&c),
        boots_before + 1,
        "the spawn cold-boots a new counter"
    );
}

fn line_count(orb: &Path, pat: &str) -> usize {
    console(orb).lines().filter(|l| l.contains(pat)).count()
}

/// A graceful agent stop (SIGTERM, as a container stop sends) checkpoints both running
/// orbs and leaves no VMM behind; the next agent start restores them without any Amp
/// command: processes and nested guests continue, Amp's bootstrap is not restarted, and
/// the guest only had its clock and network resynced. Then a drain cut short by kill -9
/// (with the VMMs dying alongside, as in a container) ends honestly: what was not saved
/// is reported stopped with processes lost and cold-boots on the next spawn.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn graceful_agent_restart_keeps_running_orbs() {
    let mut c = cluster(2);
    let _vms = Vms(c.root().to_owned());
    c.start_all();
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn 1");
    assert_ok(&c.dispatch("spawn", "amp-2", &[]), "spawn 2");
    let orbs = orb_dirs(&c);
    for o in &orbs {
        wait_progress(o, (0, 0));
    }
    let bootstraps: Vec<usize> = orbs
        .iter()
        .map(|o| line_count(o, "fake-amp-bootstrap:"))
        .collect();
    let before: Vec<(usize, usize)> = orbs.iter().map(|o| counts(o)).collect();

    let t = Instant::now();
    let status = c.terminate_agent("agent-a", Duration::from_secs(300));
    eprintln!("drain took {:?}, agent exit {status:?}", t.elapsed());
    assert!(status.success());
    assert!(vmm_pids(c.root()).is_empty(), "drained orbs hold no VMM");
    for o in &orbs {
        assert_eq!(checkpoint_files(o).len(), 1, "one checkpoint per orb");
    }

    let t = Instant::now();
    start_again(&mut c, "");
    eprintln!("agent ready with restored orbs after {:?}", t.elapsed());
    let log = std::fs::read_to_string(c.root().join("agent-agent-a.log")).unwrap();
    for l in log.lines().filter(|l| {
        l.contains("drain") || l.contains("restore finished") || l.contains("after agent restart")
    }) {
        eprintln!("  {}", l.split_once("Z ").map_or(l, |(_, r)| r));
    }
    assert_eq!(vmm_pids(c.root()).len(), 2, "both orbs run again");
    for (i, o) in orbs.iter().enumerate() {
        wait_progress(o, before[i]);
        assert_continuous(o);
        assert!(
            checkpoint_files(o).is_empty(),
            "restored checkpoints are discarded"
        );
        assert_eq!(
            line_count(o, "fake-amp-bootstrap:"),
            bootstraps[i],
            "Amp's bootstrap must not be restarted without a spawn"
        );
    }
    // Acknowledged by the guest; its own console line comes later, through journald.
    let log = agent_log(&c);
    for o in &orbs {
        let orb = format!("orb={}", o.file_name().unwrap().to_string_lossy());
        assert!(
            log.lines()
                .any(|l| l.contains("guest resynced (clock, network)") && l.contains(&orb)),
            "{orb} resynced"
        );
    }
    let uids: Vec<u32> = orbs.iter().map(|o| assert_isolated(&c, o)).collect();
    if cfg!(target_os = "linux") {
        assert_ne!(uids[0], uids[1], "each orb's VMM has its own uid");
    }
    // A spawn after the maintenance restore is an ordinary warm wake.
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn after restore");
    assert_continuous(&orbs[0]);

    // Drain cut short: the first save is slowed down (1 MiB/s, so it is still running
    // however little memory the guest touched), the agent is killed once it started and
    // every VMM dies with it.
    c.terminate_agent("agent-a", Duration::from_secs(300));
    start_again(&mut c, &point("save::throttle=return(1)"));
    assert_eq!(vmm_pids(c.root()).len(), 2);
    let mark = agent_log(&c).len();
    c.signal_agent("agent-a", "TERM");
    wait_until(Duration::from_secs(60), "the drain's first save", || {
        let log = agent_log(&c);
        since(&log, mark).contains("saving memory checkpoint")
    });
    c.kill_agent("agent-a");
    for pid in vmm_pids(c.root()) {
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
    let max_before: Vec<u64> = orbs
        .iter()
        .map(|o| {
            samples(&console(o))
                .0
                .iter()
                .map(|(_, n)| *n)
                .max()
                .unwrap()
        })
        .collect();
    start_again(&mut c, "");
    assert!(vmm_pids(c.root()).is_empty(), "nothing unsaved is resumed");
    let log = std::fs::read_to_string(c.root().join("agent-agent-a.log")).unwrap();
    let honest: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("no longer running") || l.contains("not restorable"))
        .collect();
    eprintln!("after the cut-short drain:\n{}", honest.join("\n"));
    assert!(!honest.is_empty());
    for (i, o) in orbs.iter().enumerate() {
        assert!(
            checkpoint_files(o).is_empty(),
            "no unfinished save survives"
        );
        let job = c.dispatch("spawn", &format!("amp-{}", i + 1), &[]);
        assert_ok(&job, "spawn after a cut-short drain");
        let before = counts(o);
        let ((_, n), _) = wait_progress(o, before);
        assert!(n < max_before[i], "a cold boot restarts the counter");
    }
}

/// The marker an orb's disk reported on its last boot: (created on this boot, id).
fn marker(orb: &Path) -> Option<(bool, String)> {
    printed(orb).lines().rev().find_map(|l| {
        let (created, id) = l
            .strip_prefix("marker created ")
            .map(|id| (true, id))
            .or_else(|| l.strip_prefix("marker present ").map(|id| (false, id)))?;
        // Lines garbled by interleaved console output do not count.
        (id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| (created, id.to_owned()))
    })
}

fn wait_marker(orb: &Path) -> (bool, String) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(m) = marker(orb) {
            return m;
        }
        assert!(Instant::now() < deadline, "no marker on {}", orb.display());
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// A pause with ORB_SNAPSHOT_ID publishes the disk as a project snapshot; spawning new
/// orbs with that id boots them from it (the first orb's disk marker is present),
/// whether the coordinator learned of it from the pause result or from the agent's
/// Hello after a restart. A snapshot that has vanished from the host falls back to
/// the spawn's image instead of wedging the orb.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn spawn_boots_from_project_snapshot() {
    // Disk is reserved per orb for life: room for five.
    let mut c = cluster(5);
    let _vms = Vms(c.root().to_owned());
    c.start_all();
    let snap = [("ORB_SNAPSHOT_ID", "snap-1")];
    let new_orb = |c: &Cluster, before: &[PathBuf]| -> PathBuf {
        orb_dirs(c)
            .into_iter()
            .find(|d| !before.contains(d))
            .expect("a new orb")
    };

    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn 1");
    let first = orb_dir(&c);
    let (created, id) = wait_marker(&first);
    assert!(created);
    eprintln!("amp-1 disk marker created {id}");
    assert_ok(&c.dispatch("pause", "amp-1", &snap), "pause with snapshot");

    // Known from the pause result.
    let before = orb_dirs(&c);
    assert_ok(&c.dispatch("spawn", "amp-2", &snap), "spawn from snapshot");
    let second = new_orb(&c, &before);
    assert_eq!(
        wait_marker(&second),
        (false, id.clone()),
        "booted from the snapshot"
    );
    // A jailed QEMU reads through to the project snapshot.
    assert_isolated(&c, &second);
    eprintln!("amp-2 (snapshot known from the pause result): marker present {id}");
    // A snapshot of an orb that started from a snapshot carries the same lineage.
    let snap2 = [("ORB_SNAPSHOT_ID", "snap-2")];
    assert_ok(
        &c.dispatch("pause", "amp-2", &snap2),
        "pause 2 with snapshot",
    );
    let lineages: Vec<serde_json::Value> = std::fs::read_dir(state(&c).join("projects"))
        .unwrap()
        .map(|e| {
            let m: serde_json::Value = serde_json::from_slice(
                &std::fs::read(e.unwrap().path().join("meta.json")).unwrap(),
            )
            .unwrap();
            m["lineage"].clone()
        })
        .collect();
    assert_eq!(lineages.len(), 2, "snap-1 and snap-2: {lineages:?}");
    assert!(
        lineages[0].is_string() && lineages[0] == lineages[1],
        "{lineages:?}"
    );

    // Known from the agent's Hello after a restart.
    c.kill_agent("agent-a");
    start_again(&mut c, "");
    let before = orb_dirs(&c);
    assert_ok(
        &c.dispatch("spawn", "amp-3", &snap2),
        "spawn from the second snapshot after restart",
    );
    let third = new_orb(&c, &before);
    assert_eq!(wait_marker(&third), (false, id.clone()));
    eprintln!(
        "amp-3 (second snapshot known from Hello after an agent restart): marker present {id}"
    );
    assert_ok(&c.dispatch("pause", "amp-3", &[]), "pause 3");

    // Built on another image lineage (another Debian release or guest integration): the
    // orb starts from the image instead.
    for e in std::fs::read_dir(state(&c).join("projects")).unwrap() {
        let meta = e.unwrap().path().join("meta.json");
        let mut m: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&meta).unwrap()).unwrap();
        assert!(m["lineage"].is_string(), "lineage recorded: {m}");
        m["lineage"] = "an-older-image".into();
        std::fs::write(&meta, m.to_string()).unwrap();
    }
    let before = orb_dirs(&c);
    let job = c.dispatch("spawn", "amp-older", &snap);
    assert_ok(&job, "spawn from a snapshot of an older image");
    assert!(
        job.stdout.contains("built on another image lineage")
            || job.stderr.contains("built on another image lineage")
    );
    let (created, other) = wait_marker(&new_orb(&c, &before));
    assert!(created && other != id, "a fresh disk from the image");
    eprintln!("amp-older (snapshot of an older image): marker created {other}");
    assert_ok(&c.dispatch("pause", "amp-older", &[]), "pause older");

    // Gone from the host: the orb starts from the image.
    for e in std::fs::read_dir(state(&c).join("projects")).unwrap() {
        std::fs::remove_dir_all(e.unwrap().path()).unwrap();
    }
    let before = orb_dirs(&c);
    let job = c.dispatch("spawn", "amp-4", &snap);
    assert_ok(&job, "spawn with a vanished snapshot");
    assert!(
        job.stdout.contains("is not on this host") || job.stderr.contains("is not on this host")
    );
    let fourth = new_orb(&c, &before);
    let (created, other) = wait_marker(&fourth);
    assert!(created && other != id, "a fresh disk from the image");
    eprintln!("amp-4 (snapshot gone from the host): marker created {other}");
}

/// The agent before the switch in [`carry_over`].
enum Before {
    /// The previous release's `orbd` (the binary alone: it runs with this tree's VMMs,
    /// kernel and image), with orbs whose disk holds that release's `orbd-guest`.
    PreviousRelease { agent: PathBuf, guest: PathBuf },
    /// This agent with `ORBD_VMM_JAIL=off`.
    JailOff,
}

/// An upgrade from the previous release keeps every orb (see [`carry_over`]). Needs
/// `ORBD_KVM_PREVIOUS_AGENT` and `ORBD_KVM_PREVIOUS_GUEST`, that release's `orbd` and
/// `orbd-guest`; `ORBD_KVM_PREVIOUS_AGENT=skip` skips it.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn upgrade_from_the_previous_release_keeps_every_orb() {
    let agent = std::env::var_os("ORBD_KVM_PREVIOUS_AGENT")
        .expect("set ORBD_KVM_PREVIOUS_AGENT (the previous release's orbd, or `skip`)");
    if agent == "skip" {
        eprintln!("NOTICE: ORBD_KVM_PREVIOUS_AGENT=skip: upgrade gate SKIPPED");
        return;
    }
    let guest = std::env::var_os("ORBD_KVM_PREVIOUS_GUEST")
        .expect("set ORBD_KVM_PREVIOUS_GUEST (the previous release's orbd-guest)");
    carry_over(Before::PreviousRelease {
        agent: agent.into(),
        guest: guest.into(),
    });
}

/// Turning the jail on keeps every orb an agent ran with `ORBD_VMM_JAIL=off`: a VMM it
/// left running is adopted unjailed, and each orb moves into its jail (its files and
/// TAP handed to its uid) at its next start.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn turning_the_jail_on_keeps_every_orb() {
    carry_over(Before::JailOff);
}

/// Two orbs started under `before` carry over to this agent: one asleep wakes from the
/// checkpoint `before` took, and a VMM `before` left running when it died is adopted.
/// Graceful stops then go both ways (a downgrade, then an upgrade again), each agent
/// restoring what the other checkpointed. Every counter continues, each orb keeps its
/// jail, uid and network, and a delete under this agent leaves nothing of the orb.
fn carry_over(before: Before) {
    let rootfs = tempfile::tempdir().unwrap();
    let mut c = match &before {
        Before::PreviousRelease { agent, guest } => {
            eprintln!(
                "previous agent {}, guest {}",
                agent.display(),
                guest.display()
            );
            let path = rootfs.path().join("rootfs.ext4");
            with_guest(guest, &path);
            cluster_on(2, &path.display().to_string())
        }
        Before::JailOff => cluster(2),
    };
    // amp-2 is a restricted orb (egress: {}), so its egress chain is carried over too.
    let path = c.root().join("coordinator.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap();
    let (_, block) = yaml.split_once("offerings:\n").unwrap();
    let restricted = block
        .trim_end()
        .replace(&format!("id: {}", c.offering), "id: restricted");
    let yaml = format!("{}\n{restricted}\n    egress: {{}}\n", yaml.trim_end());
    std::fs::write(&path, yaml).unwrap();
    let jailed_before = matches!(before, Before::PreviousRelease { .. });
    let set = |c: &mut Cluster, earlier: bool| match &before {
        Before::PreviousRelease { agent, .. } => c.agent_bin = earlier.then(|| agent.clone()),
        Before::JailOff if earlier => c.agent_env.push(("ORBD_VMM_JAIL".into(), "off".into())),
        Before::JailOff => c.agent_env.retain(|(k, _)| k != "ORBD_VMM_JAIL"),
    };
    let _vms = Vms(c.root().to_owned());

    set(&mut c, true);
    c.start_all();
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn 1 (before)");
    assert_ok(
        &c.dispatch("spawn", "amp-2", &[("ORBD_OFFERING_ID", "restricted")]),
        "spawn 2, restricted (before)",
    );
    let orbs = orb_dirs(&c);
    let mut first = Vec::new();
    for o in &orbs {
        wait_progress(o, (0, 0));
        first.push(match jailed_before {
            true => assert_isolated(&c, o),
            false => unjailed_vmm(o),
        });
    }
    let asleep = counts(&orbs[1]);
    assert_ok(&c.dispatch("pause", "amp-2", &[]), "pause 2 (before)");

    // The earlier agent dies with amp-1 running: this one adopts its VMM as it is.
    let running = counts(&orbs[0]);
    #[cfg(target_os = "linux")]
    let pid = vmm_pid(&orbs[0]);
    c.kill_agent("agent-a");
    set(&mut c, false);
    start_again(&mut c, "");
    assert_ok(
        &c.dispatch("spawn", "amp-1", &[]),
        "spawn adopts the running VMM",
    );
    #[cfg(target_os = "linux")]
    assert_eq!(vmm_pid(&orbs[0]), pid, "the VMM adopted, not restarted");
    wait_progress(&orbs[0], running);
    assert_continuous(&orbs[0]);
    if jailed_before {
        assert_eq!(
            assert_isolated(&c, &orbs[0]),
            first[0],
            "adopted in its jail"
        );
    } else {
        unjailed_vmm(&orbs[0]);
        let log = std::fs::read_to_string(c.root().join("agent-agent-a.log")).unwrap();
        assert!(
            !cfg!(target_os = "linux") || log.contains("adopted a VMM that runs unjailed"),
            "the unjailed VMM is reported"
        );
    }

    // Asleep under the earlier agent: woken from its checkpoint, in its jail.
    assert_ok(
        &c.dispatch("spawn", "amp-2", &[]),
        "wake 2 from the earlier agent's checkpoint",
    );
    wait_progress(&orbs[1], asleep);
    assert_continuous(&orbs[1]);
    let uid2 = assert_isolated(&c, &orbs[1]);
    if jailed_before {
        assert_eq!(uid2, first[1], "each orb keeps its uid");
    } else {
        // The adopted VMM moves into its jail at its next start.
        let progress = counts(&orbs[0]);
        assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause the adopted VMM");
        assert_ok(&c.dispatch("spawn", "amp-1", &[]), "wake it in its jail");
        wait_progress(&orbs[0], progress);
        assert_continuous(&orbs[0]);
    }
    let uids: Vec<u32> = orbs.iter().map(|o| assert_isolated(&c, o)).collect();
    if cfg!(target_os = "linux") {
        assert_ne!(uids[0], uids[1], "each orb's VMM has its own uid");
    }

    // Graceful stops both ways: each agent restores what the other checkpointed.
    for earlier in [true, false] {
        let progress: Vec<(usize, usize)> = orbs.iter().map(|o| counts(o)).collect();
        assert!(
            c.terminate_agent("agent-a", Duration::from_secs(300))
                .success()
        );
        assert!(vmm_pids(c.root()).is_empty(), "drained orbs hold no VMM");
        for o in &orbs {
            assert_eq!(checkpoint_files(o).len(), 1, "one checkpoint per orb");
        }
        set(&mut c, earlier);
        start_again(&mut c, "");
        assert_eq!(vmm_pids(c.root()).len(), 2, "both orbs restored");
        for (i, o) in orbs.iter().enumerate() {
            wait_progress(o, progress[i]);
            assert_continuous(o);
        }
    }
    for o in &orbs {
        assert!(
            checkpoint_files(o).is_empty(),
            "restored checkpoints are discarded"
        );
    }
    let now: Vec<u32> = orbs.iter().map(|o| assert_isolated(&c, o)).collect();
    assert_eq!(now, uids, "each orb keeps its uid");
    assert_deleted(&c, "amp-2", &orbs[1]);
}

/// A copy of the test root disk (`ORBD_KVM_ROOTFS`) at `out` with `guest` as its
/// `orbd-guest`.
fn with_guest(guest: &Path, out: &Path) {
    let rootfs = std::env::var("ORBD_KVM_ROOTFS").expect("set ORBD_KVM_ROOTFS");
    let ok = |c: &mut std::process::Command| assert!(c.status().unwrap().success(), "{c:?}");
    ok(std::process::Command::new("cp")
        .arg("--sparse=always")
        .arg(&rootfs)
        .arg(out));
    ok(std::process::Command::new("chmod").arg("644").arg(out));
    let path = format!("/{}", orbd::image::GUEST_HELPER_PATH);
    for req in [
        format!("rm {path}"),
        format!("write {} {path}", guest.display()),
        format!("sif {path} mode 0100755"),
        format!("sif {path} uid 0"),
        format!("sif {path} gid 0"),
    ] {
        ok(std::process::Command::new("debugfs")
            .args(["-w", "-R", &req])
            .arg(out)
            .stdout(std::process::Stdio::null()));
    }
    // debugfs exits 0 whether its request worked or not: read the helper back.
    let back = out.with_extension("guest");
    ok(std::process::Command::new("debugfs")
        .args(["-R", &format!("dump {path} {}", back.display())])
        .arg(out)
        .stdout(std::process::Stdio::null()));
    use sha2::{Digest, Sha256};
    let sum = |p: &Path| Sha256::digest(std::fs::read(p).unwrap_or_default());
    assert_eq!(
        sum(&back),
        sum(guest),
        "{path} in {} is {}",
        out.display(),
        guest.display()
    );
    let _ = std::fs::remove_file(back);
}

/// On Linux the orb's VMM runs unjailed, as root (started by an agent with
/// `ORBD_VMM_JAIL=off`); returns its uid.
fn unjailed_vmm(orb: &Path) -> u32 {
    #[cfg(target_os = "linux")]
    {
        let pid = vmm_pid(orb).expect("the orb's VMM runs");
        let uid: u32 = status(pid, "Uid:")[0].parse().unwrap();
        assert_eq!(uid, 0, "VMM {pid} runs unjailed");
        uid
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = orb;
        0
    }
}

/// Deletes the restricted orb `amp_id` (at `orb`) and checks that nothing of it is left
/// on the host: its directory, network namespace, veth, network index and jail uid
/// claims, and its egress chain.
fn assert_deleted(c: &Cluster, amp_id: &str, orb: &Path) {
    let id = orb.file_name().unwrap().to_string_lossy().into_owned();
    let claim = |kind: &str| {
        std::fs::read_dir(state(c).join(kind))
            .into_iter()
            .flatten()
            .flatten()
            .find(|e| std::fs::read_to_string(e.path()).is_ok_and(|o| o.trim() == id))
            .map(|e| e.file_name().to_string_lossy().into_owned())
    };
    let index = cfg!(target_os = "linux").then(|| claim("net").expect("a network index"));
    let table = || {
        let out = std::process::Command::new("nft")
            .args(["list", "table", "inet", "orbd"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    if let Some(i) = &index {
        let t = table();
        assert!(
            t.contains(&format!("chain egress{i} {{")),
            "egress{i} exists:\n{t}"
        );
    }
    assert_ok(&c.dispatch("delete", amp_id, &[]), "delete");
    assert!(!orb.exists(), "{} is gone", orb.display());
    assert_eq!(
        (claim("net"), claim("uids")),
        (None, None),
        "claims released"
    );
    if let Some(i) = index {
        assert!(
            !Path::new(&format!("/run/netns/orbd-{id}")).exists(),
            "netns gone"
        );
        let link = std::process::Command::new("ip")
            .args(["link", "show", &format!("orbd{i}")])
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!link.success(), "veth orbd{i} gone");
        let t = table();
        assert!(
            !t.contains(&format!("egress{i} ")) && !t.contains(&format!("\"orbd{i}\"")),
            "egress{i} and its map entry are gone:\n{t}"
        );
    }
}

/// A QEMU recipe on QEMU's unfiltered user-mode network is refused on Linux with one
/// clear error, starts nothing, and can be deleted.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn qemu_user_network_recipes_are_refused() {
    if runtime() != "qemu" || !cfg!(target_os = "linux") {
        eprintln!("NOTICE: Linux QEMU only: skipped");
        return;
    }
    let mut c = cluster(1);
    let _vms = Vms(c.root().to_owned());
    c.start_all();
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn");
    let orb = orb_dir(&c);
    wait_progress(&orb, (0, 0));
    assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause");
    let recipe = orb.join("vm.json");
    let mut r: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&recipe).unwrap()).unwrap();
    r["net"]["backend"] = serde_json::json!({ "kind": "user" });
    std::fs::write(&recipe, r.to_string()).unwrap();
    let job = c.dispatch("spawn", "amp-1", &[]);
    let out = format!("{}\n{}", job.stdout, job.stderr);
    assert_ne!(job.code, 0, "{out}");
    assert!(out.contains("unfiltered user-mode network"), "{out}");
    assert!(vmm_pids(c.root()).is_empty(), "nothing was started");
    assert_ok(
        &c.dispatch("delete", "amp-1", &[]),
        "a refused orb is deleted",
    );
    assert!(
        std::fs::read_dir(state(&c).join("orbs"))
            .unwrap()
            .next()
            .is_none()
    );
}

/// An agent started with `ORBD_NESTED_KVM=false` gets no new orb with `/dev/kvm`, and
/// refuses to start its own sleeping one when the coordinator sends a spawn for it to its
/// recorded host anyway, but still deletes it. Only amd64 QEMU orbs have `/dev/kvm`.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn nested_kvm_off_refuses_kvm_orbs() {
    if runtime() != "qemu" || cfg!(target_arch = "aarch64") {
        eprintln!("NOTICE: only amd64 QEMU orbs have /dev/kvm: skipped");
        return;
    }
    let mut c = cluster(2);
    let _vms = Vms(c.root().to_owned());
    c.start_all();
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn");
    wait_progress(&orb_dir(&c), (0, 0));
    assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause");

    c.kill_agent("agent-a");
    c.agent_env.push(("ORBD_NESTED_KVM".into(), "false".into()));
    start_again(&mut c, "");
    let job = c.dispatch("spawn", "amp-2", &[]);
    assert_ne!(
        job.code, 0,
        "a new kvm orb was placed on an agent without nested KVM"
    );
    let job = c.dispatch("spawn", "amp-1", &[]);
    assert_ne!(
        job.code, 0,
        "an orb with /dev/kvm woke on an agent without nested KVM"
    );
    let out = format!("{}{}", job.stdout, job.stderr);
    assert!(out.contains("ORBD_NESTED_KVM=false"), "{out}");
    assert!(vmm_pids(c.root()).is_empty(), "no VMM may have started");
    assert_ok(&c.dispatch("delete", "amp-1", &[]), "delete");
    assert!(orb_dirs(&c).is_empty());
}

/// `ORBD_FLOW_LOG`: the agent logs each new connection an orb in orbd's network
/// namespaces starts as one `orbd::flow` event (JSON with `ORBD_LOG_JSON`) naming the
/// orb, its Amp orb and thread, the destination and the egress policy's verdict; the
/// retransmissions of a connection are one event. Without it the table logs nothing.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn flow_log_records_orb_connections() {
    if cfg!(target_os = "macos") {
        eprintln!("NOTICE: only orbs in orbd's network namespaces (Linux) are logged: skipped");
        return;
    }
    let mut c = cluster(1);
    let _vms = Vms(c.root().to_owned());
    c.agent_env.push(("ORBD_FLOW_LOG".into(), "true".into()));
    c.agent_env.push(("ORBD_LOG_JSON".into(), "true".into()));
    c.start_all();
    let table = || {
        let out = std::process::Command::new("nft")
            .args(["list", "table", "inet", "orbd"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert!(table().contains("chain flowlog"), "{}", table());

    // The internet is allowed (whether it answers or not); documentation addresses are
    // private, so dropped.
    let (allowed, dropped) = ("1.1.1.1:53", "192.0.2.1:9");
    let env = [
        ("E2E_PROBE", format!("{allowed} {dropped}")),
        (
            "ORB_ENVS",
            "AMP_URL ORB_TOKEN AMP_THREAD_ID AMP_SANDBOX_ID E2E_PROBE".into(),
        ),
    ];
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_ok(&c.dispatch("spawn", "amp-1", &env), "spawn");
    let orb = orb_dir(&c);
    wait_until(Duration::from_secs(90), "the orb's probes", || {
        printed(&orb).contains(&format!("probe {dropped} "))
    });
    let log = c.root().join("agent-agent-a.log");
    let flows = |dst: &str| -> Vec<serde_json::Value> {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["target"] == "orbd::flow" && v["fields"]["message"] == "orb flow")
            .filter(|v| v["fields"]["dst"] == dst)
            .collect()
    };
    // Batched by the kernel for up to 0.1 s.
    wait_until(Duration::from_secs(5), "flow events", || {
        !flows(allowed).is_empty() && !flows(dropped).is_empty()
    });
    // Past the dropped connection's retransmissions (the probe waits 5 s).
    std::thread::sleep(Duration::from_secs(3));
    let orb_id = orb.file_name().unwrap().to_string_lossy().into_owned();
    for (dst, verdict) in [(allowed, "accept"), (dropped, "drop")] {
        let events = flows(dst);
        assert_eq!(events.len(), 1, "one event per connection: {events:#?}");
        let f = &events[0]["fields"];
        assert_eq!(f["verdict"], verdict, "{f}");
        assert_eq!(f["proto"], "tcp", "{f}");
        assert_eq!(f["orb"], orb_id.as_str(), "{f}");
        assert_eq!(f["amp_orb_id"], "amp-1", "{f}");
        assert_eq!(f["thread_id"], "T-1", "{f}");
        assert!(f["src_port"].as_u64().is_some(), "{f}");
        eprintln!("flow: {f}");
    }

    // Off again: the agent's table logs nothing.
    c.kill_agent("agent-a");
    c.agent_env.retain(|(k, _)| k != "ORBD_FLOW_LOG");
    start_again(&mut c, "");
    let t = table();
    assert!(
        t.contains("chain forward") && !t.contains("log ") && !t.contains("flowlog"),
        "{t}"
    );
}

/// A DNS server for the agent's egress proxy to resolve with (`ORBD_DNS`): fixed
/// answers, NXDOMAIN for every other name; it records the names it is asked.
#[cfg(target_os = "linux")]
mod upstream {
    use orbd::runtime::vm::dns::{self, Answer, AnswerData};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex, OnceLock};

    pub const ADDR: &str = "127.53.0.1";

    pub struct Upstream {
        pub asked: Mutex<Vec<String>>,
        records: Mutex<HashMap<String, Vec<Answer>>>,
    }

    pub fn a(name: &str, ip: [u8; 4]) -> Answer {
        Answer {
            name: name.into(),
            ttl: 60,
            data: AnswerData::A(Ipv4Addr::from(ip)),
        }
    }

    pub fn cname(name: &str, target: &str) -> Answer {
        Answer {
            name: name.into(),
            ttl: 300,
            data: AnswerData::Cname(target.into()),
        }
    }

    /// Serves `records` (by queried name) on [`ADDR`] port 53.
    pub fn start(records: Vec<(&str, Vec<Answer>)>) -> Arc<Upstream> {
        static UP: OnceLock<Arc<Upstream>> = OnceLock::new();
        let up = UP
            .get_or_init(|| {
                let up = Arc::new(Upstream {
                    asked: Mutex::new(Vec::new()),
                    records: Mutex::new(HashMap::new()),
                });
                let sock =
                    std::net::UdpSocket::bind((ADDR, 53)).expect("binding the fake upstream");
                let u = up.clone();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        let Ok((n, src)) = sock.recv_from(&mut buf) else {
                            continue;
                        };
                        let Ok(q) = dns::parse_query(&buf[..n]) else {
                            continue;
                        };
                        let name = q.question.name.text().unwrap_or_default();
                        u.asked.lock().unwrap().push(name.clone());
                        let answers = u.records.lock().unwrap().get(&name).cloned();
                        let reply = match answers {
                            Some(a) if q.question.qtype == dns::TYPE_A => {
                                dns::build_response(&q, dns::NOERROR, &a, 1232)
                            }
                            Some(_) => dns::build_response(&q, dns::NOERROR, &[], 1232),
                            None => dns::build_response(&q, dns::NXDOMAIN, &[], 1232),
                        };
                        let _ = sock.send_to(&reply, src);
                    }
                });
                up
            })
            .clone();
        *up.records.lock().unwrap() = records
            .into_iter()
            .map(|(n, a)| (n.to_owned(), a))
            .collect();
        up.asked.lock().unwrap().clear();
        up
    }
}

/// `probe <target> <result>` lines the guest printed after console offset `from`, for
/// each of `targets`, waiting for them (a dropped probe takes 5 s).
#[cfg(target_os = "linux")]
fn probes(orb: &Path, from: usize, targets: &[&str]) -> std::collections::HashMap<String, String> {
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        let text = console(orb);
        let new = without_kernel_messages(since(&text, from));
        let found: std::collections::HashMap<String, String> = targets
            .iter()
            .filter_map(|t| {
                new.lines().rev().find_map(|l| {
                    l.strip_prefix(&format!("probe {t} "))
                        .map(|r| (t.to_string(), r.trim().to_owned()))
                })
            })
            .collect();
        if found.len() == targets.len() {
            for (t, r) in &found {
                eprintln!("guest probe {t}: {r}");
            }
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "the guest did not probe {targets:?}; console tail:\n{}",
            tail(&text)
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Restricted egress (an orb type's `egress`): the orb's DNS is the agent's proxy, which
/// resolves only allowlisted names (a CNAME chain as returned for one too, and answers
/// too big for UDP over TCP) and never asks upstream about the rest; the orb reaches
/// what they resolved to on the policy's ports and its `allow` rules, nothing else: not
/// other internet addresses, not DNS servers directly, and not private, link-local or
/// metadata addresses even when an allowlisted name resolves to one, not an opened
/// address on a port the policy does not list (TCP or UDP), and no IPv6. The flow log
/// shows each connection with the restricted verdict. An unrestricted orb beside it does
/// not reach the DNS proxy; another restricted orb does not reach the first one's
/// addresses. An agent restart keeps the orbs restricted with their open addresses, and
/// an edit of the orb type's list reaches the orb at its next launch.
#[test]
#[ignore = "needs KVM; see the module docs"]
fn restricted_egress_reaches_only_its_allowlist() {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("NOTICE: restricted egress needs Linux VM orbs: skipped");
    }
    #[cfg(target_os = "linux")]
    {
        use upstream::{a, cname};
        let private = private_targets()
            .first()
            .map(|t| t.trim_end_matches(":1").to_owned());
        let private_ip: [u8; 4] = private
            .as_deref()
            .unwrap_or("10.255.255.1")
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .octets();
        let many: Vec<_> = (1..=40)
            .map(|i| a("many.orbd.test", [104, 16, 0, i]))
            .collect();
        let up = upstream::start(vec![
            (
                "allowed.orbd.test",
                vec![a("allowed.orbd.test", [1, 0, 0, 1])],
            ),
            (
                "www.cdn.orbd.test",
                vec![
                    cname("www.cdn.orbd.test", "edge.elsewhere.test"),
                    a("edge.elsewhere.test", [8, 8, 4, 4]),
                ],
            ),
            (
                "private.orbd.test",
                vec![a("private.orbd.test", private_ip)],
            ),
            (
                "meta.orbd.test",
                vec![a("meta.orbd.test", [169, 254, 169, 254])],
            ),
            (
                "denied.orbd.test",
                vec![a("denied.orbd.test", [1, 1, 1, 1])],
            ),
            ("many.orbd.test", many),
        ]);

        let mut c = cluster(3);
        let _vms = Vms(c.root().to_owned());
        // The cluster's offering, restricted, and the same without `egress` (`plain`).
        let path = c.root().join("coordinator.yaml");
        let yaml = std::fs::read_to_string(&path).unwrap();
        let (head, block) = yaml.split_once("offerings:\n").unwrap();
        let (head, block) = (head.to_owned(), block.trim_end().to_owned());
        let plain = block.replace(&format!("id: {}", c.offering), "id: plain");
        let set_egress = |policy: &str| {
            std::fs::write(
                &path,
                format!("{head}offerings:\n{block}\n    egress: {policy}\n{plain}\n"),
            )
            .unwrap();
        };
        set_egress(
            r#"{ domains: [allowed.orbd.test, "*.cdn.orbd.test", private.orbd.test, meta.orbd.test, many.orbd.test], ports: ["tcp:443", "tcp:1"], allow: ["tcp:9.9.9.9:443"] }"#,
        );
        for (k, v) in [
            ("ORBD_DNS", upstream::ADDR),
            ("ORBD_FLOW_LOG", "true"),
            ("ORBD_LOG_JSON", "true"),
        ] {
            c.agent_env.push((k.into(), v.into()));
        }
        c.start_all();
        let mut targets = vec![
            "allowed.orbd.test:443",
            "www.cdn.orbd.test:443",
            "9.9.9.9:443",
            "1.1.1.1:443",
            "1.1.1.1:53",
            "allowed.orbd.test:80",
            "denied.orbd.test:443",
            "meta.orbd.test:443",
            "private.orbd.test:1",
        ];
        let direct = private.as_ref().map(|p| format!("{p}:1"));
        if let Some(d) = &direct {
            targets.push(d);
        } else {
            eprintln!("NOTICE: no private address answers this agent: rebinding only by name");
        }
        let spawn = |c: &Cluster, orb: &str, env: &[(&str, &str)]| {
            let mut e: Vec<(&str, &str)> = env.to_vec();
            e.push((
                "ORB_ENVS",
                "AMP_URL ORB_TOKEN AMP_THREAD_ID AMP_SANDBOX_ID E2E_PROBE E2E_RESOLVE E2E_UDP E2E_PROBE6",
            ));
            assert_ok(&c.dispatch("spawn", orb, &e), orb);
        };
        let probe_all = targets.join(" ");
        spawn(
            &c,
            "amp-1",
            &[
                ("E2E_PROBE", &probe_all),
                ("E2E_RESOLVE", "many.orbd.test"),
                ("E2E_UDP", "1.1.1.1:53 allowed.orbd.test:443"),
                ("E2E_PROBE6", "2606:4700:4700::1111/443"),
            ],
        );
        let orb = orb_dir(&c);
        let got = probes(&orb, 0, &targets);
        let want = |t: &str| -> &str {
            match t {
                "allowed.orbd.test:443" | "www.cdn.orbd.test:443" | "9.9.9.9:443" => "open",
                "denied.orbd.test:443" | "meta.orbd.test:443" | "private.orbd.test:1" => {
                    "unresolved"
                }
                _ => "dropped",
            }
        };
        for t in &targets {
            assert_eq!(
                got[*t],
                want(t),
                "{t}; console tail:\n{}",
                tail(&console(&orb))
            );
        }
        // 40 addresses do not fit a UDP answer: the guest asked again over TCP.
        let line = |prefix: &str| {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(l) = printed(&orb)
                    .lines()
                    .rev()
                    .find_map(|l| l.strip_prefix(prefix).map(str::to_owned))
                {
                    break l;
                }
                assert!(Instant::now() < deadline, "no {prefix:?} in the console");
                std::thread::sleep(Duration::from_millis(500));
            }
        };
        let resolved = line("resolve many.orbd.test ");
        assert_eq!(resolved.split_whitespace().count(), 40, "{resolved}");
        // No IPv6 at all.
        let v6 = line("probe6 2606:4700:4700::1111/443 ");
        assert_ne!(v6.trim(), "open", "IPv6 reached the internet");
        eprintln!("guest probe6: {v6}");
        line("udp allowed.orbd.test:443 ");
        // Never asked upstream about names off the list; asked about the listed ones
        // whatever they resolve to.
        let asked = up.asked.lock().unwrap().clone();
        assert!(!asked.iter().any(|n| n == "denied.orbd.test"), "{asked:?}");
        for n in ["allowed.orbd.test", "private.orbd.test", "meta.orbd.test"] {
            assert!(asked.iter().any(|a| a == n), "{n}: {asked:?}");
        }

        // The flow log: every connection the orb started, with the restricted verdict
        // (UDP too, and to the agent itself); none to the addresses no name opened.
        let log = c.root().join("agent-agent-a.log");
        let flows = |dst: &str, proto: &str| -> Vec<serde_json::Value> {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .filter(|v| v["target"] == "orbd::flow" && v["fields"]["message"] == "orb flow")
                .filter(|v| v["fields"]["dst"] == dst && v["fields"]["proto"] == proto)
                .collect()
        };
        let mut expect = vec![
            ("1.0.0.1:443", "tcp", "accept"),
            ("8.8.4.4:443", "tcp", "accept"),
            ("9.9.9.9:443", "tcp", "accept"),
            ("1.1.1.1:443", "tcp", "drop"),
            ("1.1.1.1:53", "tcp", "drop"),
            ("1.1.1.1:53", "udp", "drop"),
            ("1.0.0.1:80", "tcp", "drop"),
            ("1.0.0.1:443", "udp", "drop"),
        ];
        if let Some(d) = &direct {
            expect.push((d, "tcp", "drop"));
        }
        wait_until(Duration::from_secs(10), "flow events", || {
            expect.iter().all(|(d, p, _)| !flows(d, p).is_empty())
        });
        for (dst, proto, verdict) in &expect {
            let f = &flows(dst, proto)[0]["fields"];
            assert_eq!(f["verdict"], *verdict, "{dst}: {f}");
            assert_eq!(f["egress"], "restricted", "{dst}: {f}");
            assert_eq!(f["amp_orb_id"], "amp-1", "{f}");
            eprintln!("flow: {f}");
        }
        assert!(flows("169.254.169.254:443", "tcp").is_empty());
        if let Some(p) = &private {
            assert!(
                flows(&format!("{p}:1"), "tcp").len() <= 1,
                "only the direct probe reached the filter"
            );
        }
        let refused = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("not on the orb type's egress list");
        assert!(refused, "the agent logs refused names");

        // Other orbs on the agent: an unrestricted one reaches the internet as always,
        // not the DNS proxy; another restricted one none of the first one's addresses.
        let before = orb_dirs(&c);
        let restricted_offering = std::mem::replace(&mut c.offering, "plain".into());
        spawn(&c, "amp-2", &[("E2E_PROBE", "169.254.0.1:53 1.1.1.1:443")]);
        let plain_orb = orb_dirs(&c)
            .into_iter()
            .find(|d| !before.contains(d))
            .unwrap();
        c.offering = restricted_offering;
        let before = orb_dirs(&c);
        spawn(
            &c,
            "amp-3",
            &[("E2E_PROBE", "1.0.0.1:443 8.8.4.4:443 9.9.9.9:443")],
        );
        let other = orb_dirs(&c)
            .into_iter()
            .find(|d| !before.contains(d))
            .unwrap();
        let got = probes(&plain_orb, 0, &["169.254.0.1:53", "1.1.1.1:443"]);
        assert_eq!(
            got["169.254.0.1:53"], "dropped",
            "an unrestricted orb reached the proxy"
        );
        assert_eq!(
            got["1.1.1.1:443"], "open",
            "unrestricted orbs reach the internet"
        );
        let got = probes(&other, 0, &["1.0.0.1:443", "8.8.4.4:443", "9.9.9.9:443"]);
        assert_eq!(
            got["1.0.0.1:443"], "dropped",
            "another orb's opened address"
        );
        assert_eq!(
            got["8.8.4.4:443"], "dropped",
            "another orb's opened address"
        );
        assert_eq!(got["9.9.9.9:443"], "open", "its own allow rule");

        // An agent killed outright leaves the table as it was; the next one renders the
        // orbs' chains again from their recorded policies before anything else, with
        // the addresses they had open: the running orbs are never unrestricted.
        let table = || {
            let out = std::process::Command::new("nft")
                .args(["list", "table", "inet", "orbd"])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        assert!(table().contains(": goto egress"), "{}", table());
        c.kill_agent("agent-a");
        assert!(table().contains(": goto egress"), "{}", table());
        start_again(&mut c, "");
        let t = table();
        assert_eq!(t.matches(": goto egress").count(), 2, "{t}");
        assert!(t.contains("1.0.0.1 timeout"), "opened addresses kept: {t}");
        let from = console(&orb).len();
        spawn(
            &c,
            "amp-1",
            &[("E2E_PROBE", "1.1.1.1:443 allowed.orbd.test:443")],
        );
        let got = probes(&orb, from, &["1.1.1.1:443", "allowed.orbd.test:443"]);
        assert_eq!(got["1.1.1.1:443"], "dropped");
        assert_eq!(got["allowed.orbd.test:443"], "open");

        // The operator edits the list: the sleeping orb keeps its policy until its next
        // launch (here a memory restore), which applies the new one.
        assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause");
        set_egress(
            r#"{ domains: [denied.orbd.test, "*.cdn.orbd.test"], allow: ["tcp:9.9.9.9:443"] }"#,
        );
        c.kill_coordinator();
        c.start_coordinator("");
        c.wait_connected(1);
        let recorded = || std::fs::read_to_string(orb.join("egress.json")).unwrap();
        assert!(recorded().contains("allowed.orbd.test"), "{}", recorded());
        let from = console(&orb).len();
        spawn(
            &c,
            "amp-1",
            &[(
                "E2E_PROBE",
                "denied.orbd.test:443 allowed.orbd.test:443 www.cdn.orbd.test:443",
            )],
        );
        let got = probes(
            &orb,
            from,
            &[
                "denied.orbd.test:443",
                "allowed.orbd.test:443",
                "www.cdn.orbd.test:443",
            ],
        );
        assert_eq!(got["denied.orbd.test:443"], "open", "now listed");
        assert_eq!(
            got["allowed.orbd.test:443"], "unresolved",
            "no longer listed"
        );
        assert_eq!(got["www.cdn.orbd.test:443"], "open");
        assert!(recorded().contains("denied.orbd.test"), "{}", recorded());
        for o in ["amp-1", "amp-2", "amp-3"] {
            assert_ok(&c.dispatch("delete", o, &[]), "delete");
        }
        assert!(!table().contains(": goto egress"), "{}", table());
    }
}
