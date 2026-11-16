//! VMM process supervision: a one-shot launcher (fork → new session → optional cgroup
//! move → optional network namespace → exec of a foreground VMM), durable launch
//! records, and validated adoption of VMMs that outlived an earlier supervisor process.
//!
//! A VMM is never daemonized and never a long-lived child that the supervisor must keep
//! reaping: the spawned `Child` handle is dropped at once (reaped in the background if
//! it exits while the supervisor lives) and every later wait goes through a pidfd, the
//! same for launched and adopted processes. A process is accepted as a VM's VMM only if
//! the host boot id, `/proc/<pid>` start time and the launch marker in its argv match
//! the launch record (and the VMM's own API then reports the same marker).
//!
//! On macOS (no pidfds, no `/proc`) a process is held by pid and start time instead:
//! every check and signal first confirms the pid still has the start time it had when
//! it was opened, and exits are polled. Cgroups and network namespaces are Linux-only.
//!
//! Production placement: VMMs must not live in the supervisor service's cgroup, or a
//! service stop kills every VM. Under systemd use `KillMode=process` or pass a
//! delegated cgroup v2 directory as [`Spawn::cgroup`]; the launcher moves the VMM into
//! it before exec.

use crate::fsutil::{read_json, write_json_atomic};
use nix::libc;
use serde::{Deserialize, Serialize};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Binary of a VMM (recorded in manifests; restore requires the same binary).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmmIdentity {
    pub path: PathBuf,
    pub version: String,
    pub sha256: String,
}

/// Host CPU as the guest sees it (restore requires the same model and flags).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuIdentity {
    pub model: String,
    pub flags_sha256: String,
}

impl CpuIdentity {
    pub fn host() -> Self {
        let (model, flags) = sys::cpu();
        use sha2::{Digest, Sha256};
        Self {
            model,
            flags_sha256: hex::encode(Sha256::digest(flags.as_bytes())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelIdentity {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LaunchKind {
    /// Boots the kernel; the guest runs from the first instruction.
    Boot,
    /// Loads this checkpoint generation with vCPUs stopped.
    Restore { generation: u64 },
}

/// Durable pre-launch intent (a `launch.json` per VM), written before exec and
/// completed with pid and start time after it. `config` is the guest-visible machine
/// definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LaunchRecord<C> {
    pub nonce: String,
    pub boot_id: String,
    pub kind: LaunchKind,
    pub config: C,
    pub pid: Option<i32>,
    pub start_time: Option<u64>,
}

impl<C> LaunchRecord<C> {
    pub fn new(kind: LaunchKind, config: C) -> Self {
        Self {
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            boot_id: host_boot_id(),
            kind,
            config,
            pid: None,
            start_time: None,
        }
    }
}

pub fn read_record<C: serde::de::DeserializeOwned>(path: &Path) -> Option<LaunchRecord<C>> {
    read_json(path).ok().flatten()
}

/// This boot of the host (Linux `boot_id`, macOS `kern.bootsessionuuid`).
pub fn host_boot_id() -> String {
    sys::boot_id()
}

/// Start time of `pid` (Linux: clock ticks since boot from `/proc/<pid>/stat`; macOS:
/// microseconds since the epoch).
pub fn start_time(pid: i32) -> Option<u64> {
    sys::start_time(pid)
}

/// A validated, live VMM process, held through a pidfd on Linux (no pid-reuse races)
/// and by pid and start time on macOS.
pub struct Process {
    pub pid: i32,
    handle: sys::Handle,
}

impl Process {
    fn open(pid: i32) -> Option<Self> {
        Some(Self {
            pid,
            handle: sys::Handle::open(pid)?,
        })
    }

    /// Adopts the VMM described by `record` and recognised by `marker` (a unique
    /// string in its argv), if it is still the same process. Without a recorded pid
    /// (the supervisor died right after exec) the pid comes from `pidfile` or a `/proc` scan.
    pub fn adopt<C>(
        record: &LaunchRecord<C>,
        marker: &str,
        pidfile: Option<&Path>,
    ) -> Option<Self> {
        if record.boot_id != host_boot_id() {
            return None;
        }
        let pid = record
            .pid
            .or_else(|| {
                std::fs::read_to_string(pidfile?)
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
            })
            .or_else(|| find_by_marker(marker))?;
        let p = Self::open(pid)?;
        // Validate after opening the pidfd, so the checks are about this process.
        if !has_marker(pid, marker) {
            return None;
        }
        if let Some(st) = record.start_time
            && start_time(pid) != Some(st)
        {
            return None;
        }
        p.is_alive().then_some(p)
    }

    pub fn is_alive(&self) -> bool {
        self.handle.is_alive()
    }

    /// Waits until the process exits or `deadline` passes; true if it exited.
    pub async fn wait_exit(&self, deadline: Instant) -> bool {
        self.handle.wait_exit(deadline).await
    }

    pub fn kill(&self) {
        self.handle.kill();
    }

    /// SIGKILL and wait (bounded) for the exit.
    pub async fn kill_and_wait(&self, timeout: Duration) -> bool {
        self.kill();
        self.wait_exit(Instant::now() + timeout).await
    }
}

fn has_marker(pid: i32, marker: &str) -> bool {
    sys::cmdline(pid).is_some_and(|cmdline| {
        cmdline
            .split(|b| *b == 0)
            .any(|a| String::from_utf8_lossy(a).contains(marker))
    })
}

fn find_by_marker(marker: &str) -> Option<i32> {
    sys::pids().into_iter().find(|pid| has_marker(*pid, marker))
}

pub struct Spawn<'a, C> {
    pub program: &'a Path,
    pub args: Vec<String>,
    /// Receives the VMM's stdout.
    pub stdout: &'a Path,
    pub stderr: &'a Path,
    pub record_path: &'a Path,
    pub record: LaunchRecord<C>,
    /// Cgroup v2 directory to move the VMM into before exec.
    pub cgroup: Option<PathBuf>,
    /// Network namespace (`/run/netns/<name>`) the VMM runs in.
    pub netns: Option<PathBuf>,
}

/// Records the launch intent, then forks and execs the VMM in its own session. Returns
/// once the process exists (not once it is ready).
pub fn spawn<C: Serialize>(s: Spawn<'_, C>) -> std::io::Result<(Process, LaunchRecord<C>)> {
    let mut record = s.record;
    write_json_atomic(s.record_path, &record)?;
    let open_log = |p: &Path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
    };
    let stdout = open_log(s.stdout)?;
    let stderr = open_log(s.stderr)?;
    let procs = match &s.cgroup {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(dir.join("cgroup.procs"))?,
            )
        }
        None => None,
    };
    let netns = s.netns.as_deref().map(std::fs::File::open).transpose()?;
    if cfg!(not(target_os = "linux")) && (procs.is_some() || netns.is_some()) {
        return Err(std::io::Error::other(
            "cgroups and network namespaces need Linux",
        ));
    }
    let procs_fd = procs.as_ref().map(|f| f.as_raw_fd());
    let netns_fd = netns.as_ref().map(|f| f.as_raw_fd());
    let mut cmd = std::process::Command::new(s.program);
    cmd.args(&s.args)
        .stdin(std::process::Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    // SAFETY: only async-signal-safe calls (setsid, write, setns) between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(fd) = procs_fd
                && libc::write(fd, b"0\n".as_ptr().cast(), 2) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            if let Some(fd) = netns_fd
                && libc::setns(fd, libc::CLONE_NEWNET) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(not(target_os = "linux"))]
            let _ = netns_fd;
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let pid = child.id() as i32;
    fail::fail_point!("vm::launch::after_exec", |_| std::process::abort());
    let Some(proc) = Process::open(pid) else {
        // It already exited (macOS cannot open a zombie): reap it and say how it ended.
        let status = child.wait()?;
        return Err(std::io::Error::other(format!("exited at once ({status})")));
    };
    // Not waited here: a std Child never reaps on drop, so reap it on a detached thread
    // only while this supervisor lives; afterwards init (or the subreaper) does.
    std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
    record.pid = Some(pid);
    record.start_time = start_time(pid);
    write_json_atomic(s.record_path, &record)?;
    Ok((proc, record))
}

#[cfg(target_os = "linux")]
mod sys {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Instant;

    pub fn cpu() -> (String, String) {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let field = |name: &str| {
            cpuinfo
                .lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_owned())
                .unwrap_or_default()
        };
        (field("model name"), field("flags"))
    }

    pub fn boot_id() -> String {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_owned())
            .unwrap_or_default()
    }

    pub fn start_time(pid: i32) -> Option<u64> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = &stat[stat.rfind(')')? + 1..];
        // Fields after the comm: state is field 3; starttime is field 22.
        rest.split_whitespace().nth(19)?.parse().ok()
    }

    pub fn cmdline(pid: i32) -> Option<Vec<u8>> {
        std::fs::read(format!("/proc/{pid}/cmdline")).ok()
    }

    pub fn pids() -> Vec<i32> {
        std::fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
            .collect()
    }

    pub struct Handle {
        pidfd: OwnedFd,
    }

    impl Handle {
        pub fn open(pid: i32) -> Option<Self> {
            // SAFETY: plain syscall; a valid fd is owned below.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if fd < 0 {
                return None;
            }
            Some(Self {
                // SAFETY: the kernel returned a new fd that nothing else owns.
                pidfd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
            })
        }

        pub fn is_alive(&self) -> bool {
            let mut pfd = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd, zero timeout.
            let r = unsafe { libc::poll(&mut pfd, 1, 0) };
            r == 0
        }

        pub async fn wait_exit(&self, deadline: Instant) -> bool {
            let Ok(fd) = self.pidfd.try_clone() else {
                return !self.is_alive();
            };
            // SAFETY: the AsyncFd owns `fd`, which stays open (and the same pidfd) until it drops.
            let registered = unsafe {
                tokio::io::unix::AsyncFd::register_with_interest(fd, tokio::io::Interest::READABLE)
            };
            let Ok(afd) = registered else {
                return !self.is_alive();
            };
            tokio::select! {
                _ = afd.readable() => true,
                _ = tokio::time::sleep_until(deadline.into()) => !self.is_alive(),
            }
        }

        pub fn kill(&self) {
            // SAFETY: signals exactly the process behind the pidfd.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use crate::sysctl;
    use nix::libc;
    use std::time::{Duration, Instant};

    /// `proc_bsdinfo.pbi_status` of a zombie (`SZOMB` in `sys/proc.h`).
    const SZOMB: u32 = 5;
    const EXIT_POLL: Duration = Duration::from_millis(20);

    pub fn cpu() -> (String, String) {
        // The guest gets `-cpu host` under Hypervisor.framework: the CPU family pins the
        // features it sees.
        let flags = format!(
            "cpufamily={:?} cpusubfamily={:?}",
            sysctl::u64("hw.cpufamily"),
            sysctl::u64("hw.cpusubfamily")
        );
        (sysctl::string("machdep.cpu.brand_string"), flags)
    }

    pub fn boot_id() -> String {
        sysctl::string("kern.bootsessionuuid")
    }

    fn bsdinfo(pid: i32) -> Option<libc::proc_bsdinfo> {
        // SAFETY: proc_bsdinfo is plain data; the kernel fills at most its size.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: `info` is a valid buffer of `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        (n == size).then_some(info)
    }

    fn started(i: &libc::proc_bsdinfo) -> u64 {
        i.pbi_start_tvsec * 1_000_000 + i.pbi_start_tvusec
    }

    pub fn start_time(pid: i32) -> Option<u64> {
        bsdinfo(pid).map(|i| started(&i))
    }

    /// The process's argv, NUL-terminated (like Linux's `/proc/<pid>/cmdline`).
    pub fn cmdline(pid: i32) -> Option<Vec<u8>> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut len: usize = 0;
        // SAFETY: size query with a null buffer.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        let mut buf = vec![0u8; len];
        // SAFETY: `buf` holds `len` bytes.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        buf.truncate(len);
        // KERN_PROCARGS2: argc, exec path, NUL padding, argv, environment.
        let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
        let rest = &buf[4..];
        let path_end = rest.iter().position(|b| *b == 0)?;
        let argv = &rest[path_end + rest[path_end..].iter().position(|b| *b != 0)?..];
        let mut end = 0;
        for _ in 0..argc {
            end += argv.get(end..)?.iter().position(|b| *b == 0)? + 1;
        }
        Some(argv[..end].to_vec())
    }

    pub fn pids() -> Vec<i32> {
        // SAFETY: size query with a null buffer.
        let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if n <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0i32; n as usize + 64];
        let bytes = (pids.len() * std::mem::size_of::<i32>()) as libc::c_int;
        // SAFETY: `pids` holds `bytes` bytes.
        let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        pids.truncate(n.max(0) as usize);
        pids.retain(|p| *p > 0);
        pids
    }

    /// A process held by pid and start time: once the start time differs (or the pid is
    /// gone or a zombie), it has exited.
    pub struct Handle {
        pid: i32,
        start: u64,
    }

    impl Handle {
        pub fn open(pid: i32) -> Option<Self> {
            let start = start_time(pid)?;
            let h = Self { pid, start };
            h.is_alive().then_some(h)
        }

        pub fn is_alive(&self) -> bool {
            bsdinfo(self.pid).is_some_and(|i| i.pbi_status != SZOMB && started(&i) == self.start)
        }

        pub async fn wait_exit(&self, deadline: Instant) -> bool {
            loop {
                if !self.is_alive() {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(EXIT_POLL.min(deadline - Instant::now())).await;
            }
        }

        pub fn kill(&self) {
            if self.is_alive() {
                // SAFETY: plain syscall on a pid just confirmed to be this process.
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                }
            }
        }
    }
}
