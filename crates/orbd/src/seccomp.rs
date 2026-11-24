//! Seccomp filters (Linux), as classic BPF programs built here:
//!
//! * the agent's ([`harden_agent`]): it and every process it starts (VMMs, the image and
//!   disk tools, `nft`, `ip`) lose the system calls that act on the whole kernel rather
//!   than on their own namespaces: eBPF and perf events (both trace or change the whole
//!   kernel), loading modules, kexec, file handles (which open any file of a mounted
//!   filesystem, past every mount namespace), reboot, swap, process accounting and
//!   setting the clock, fanotify (which watches whole filesystems) and the kernel log.
//!   Nothing orbd runs uses them. They fail with `EPERM`;
//! * the DNS proxy's codec's ([`codec_allowlist`]): only reading and writing its socket,
//!   memory, signalling itself and exiting; anything else kills it.
//!
//! Both refuse every other ABI than the native one (i386 and x32 on x86_64, arm32 on
//! arm64), whose call numbers differ.

#[cfg(target_os = "linux")]
pub use orbd_vm::seccomp::install;
pub use orbd_vm::seccomp::{
    AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64, Abi, Action, Insn, NATIVE, X32_SYSCALL_BIT, evaluate,
    program, ret_of,
};

/// The calls the agent and its children are refused, by name and number.
#[cfg(target_os = "linux")]
pub fn agent_denied() -> Vec<(&'static str, u32)> {
    use nix::libc;
    #[cfg(target_arch = "x86_64")]
    const KEXEC_FILE_LOAD: libc::c_long = 320;
    // asm-generic numbering (not in libc for every arm64 target).
    #[cfg(target_arch = "aarch64")]
    const KEXEC_FILE_LOAD: libc::c_long = 294;
    #[cfg(target_arch = "x86_64")]
    let port_io = [("iopl", libc::SYS_iopl), ("ioperm", libc::SYS_ioperm)];
    #[cfg(not(target_arch = "x86_64"))]
    let port_io: [(&'static str, libc::c_long); 0] = [];
    let v: Vec<(&'static str, libc::c_long)> = vec![
        ("bpf", libc::SYS_bpf),
        ("perf_event_open", libc::SYS_perf_event_open),
        ("init_module", libc::SYS_init_module),
        ("finit_module", libc::SYS_finit_module),
        ("delete_module", libc::SYS_delete_module),
        ("kexec_load", libc::SYS_kexec_load),
        ("kexec_file_load", KEXEC_FILE_LOAD),
        ("open_by_handle_at", libc::SYS_open_by_handle_at),
        ("reboot", libc::SYS_reboot),
        ("swapon", libc::SYS_swapon),
        ("swapoff", libc::SYS_swapoff),
        ("acct", libc::SYS_acct),
        ("settimeofday", libc::SYS_settimeofday),
        ("clock_settime", libc::SYS_clock_settime),
        ("fanotify_init", libc::SYS_fanotify_init),
        ("syslog", libc::SYS_syslog),
    ];
    v.into_iter()
        .chain(port_io)
        .map(|(n, nr)| (n, nr as u32))
        .collect()
}

/// The agent's filter: [`agent_denied`] fail with `EPERM`, as does every call of another
/// ABI.
#[cfg(target_os = "linux")]
pub fn agent_filter() -> Vec<Insn> {
    let eperm = Action::Errno(nix::libc::EPERM as u16);
    let nrs: Vec<u32> = agent_denied().iter().map(|(_, nr)| *nr).collect();
    program(NATIVE, &nrs, &[], eperm, Action::Allow, eperm)
}

/// What the DNS codec, process `pid` (single-threaded), may call once it serves: its
/// socket (stdin) and stderr, memory, futexes and signals for the runtime and a panic
/// (signalling only itself), the clock, and exiting.
#[cfg(target_os = "linux")]
pub fn codec_allowlist(pid: u32) -> Vec<Insn> {
    use nix::libc;
    let mut nrs: Vec<libc::c_long> = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_sched_yield,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigaction,
        libc::SYS_sigaltstack,
        libc::SYS_restart_syscall,
        libc::SYS_clock_gettime,
        libc::SYS_getrandom,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    nrs.sort_unstable();
    let nrs: Vec<u32> = nrs.into_iter().map(|n| n as u32).collect();
    // abort() signals its own thread (glibc tgkill, musl tkill), the process's only one;
    // other codecs run as the same uid.
    let pinned = [
        (libc::SYS_tgkill as u32, pid),
        (libc::SYS_tkill as u32, pid),
    ];
    program(
        NATIVE,
        &nrs,
        &pinned,
        Action::Allow,
        Action::KillProcess,
        Action::KillProcess,
    )
}

/// How [`harden_agent`] went.
#[derive(Debug, PartialEq, Eq)]
pub enum Hardened {
    /// The filter is installed (`no_new_privs`: the agent had to give up privilege gains
    /// for it, having no `CAP_SYS_ADMIN`).
    Filtered { no_new_privs: bool },
    /// The agent has no capability at all (an unprivileged user): the kernel takes a
    /// filter from it only with `no_new_privs`, which would break the `sudo` a
    /// development agent runs image tools with, and refuses it these calls itself.
    Unprivileged,
    /// Not Linux.
    Unsupported,
}

/// This process's `Seccomp_filters` (Linux 5.9 and later).
#[cfg(target_os = "linux")]
fn filters() -> Option<u32> {
    let s = std::fs::read_to_string("/proc/thread-self/status").ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("Seccomp_filters:"))?
        .trim()
        .parse()
        .ok()
}

/// Whether this process is root or holds any capability (effective, or permitted to
/// become so).
#[cfg(target_os = "linux")]
fn privileged() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let caps = |field: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(field))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
    };
    nix::unistd::geteuid().is_root() || caps("CapEff:") != Some(0) || caps("CapPrm:") != Some(0)
}

/// Installs the agent's filter ([`agent_filter`]) on every thread of this process (run
/// before the agent starts any), so every process it starts inherits it, and checks the
/// process holds one more filter. Without `CAP_SYS_ADMIN` the kernel takes it only with
/// `no_new_privs`: a root agent, or one with any capability, sets that; one with none
/// runs without the filter. Fails, so the agent does not start, where it could not be
/// installed.
#[cfg(target_os = "linux")]
pub fn harden_agent() -> Result<Hardened, String> {
    use nix::libc;
    let fail = |e: std::io::Error| {
        format!(
            "installing the agent's seccomp filter: {e} (it refuses bpf, perf_event_open, \
             module loading, kexec and other kernel-wide calls to the agent and everything it \
             starts)"
        )
    };
    let before = filters();
    // With CAP_SYS_ADMIN (every VM agent) no no_new_privs: it would change what the
    // processes the agent starts may do (setuid programs, file capabilities, LSM
    // transitions).
    let no_new_privs = match install(&agent_filter(), true) {
        Ok(()) => false,
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
            if !privileged() {
                return Ok(Hardened::Unprivileged);
            }
            // SAFETY: plain prctl.
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                return Err(fail(std::io::Error::last_os_error()));
            }
            install(&agent_filter(), true).map_err(fail)?;
            true
        }
        Err(e) => return Err(fail(e)),
    };
    if let (Some(b), Some(a)) = (before, filters())
        && a != b + 1
    {
        return Err(format!(
            "the agent's seccomp filter is not in effect: {a} filters, {b} before"
        ));
    }
    Ok(Hardened::Filtered { no_new_privs })
}

#[cfg(not(target_os = "linux"))]
pub fn harden_agent() -> Result<Hardened, String> {
    Ok(Hardened::Unsupported)
}

/// Logs how [`harden_agent`] went (once logging is set up).
pub fn log(h: &Hardened) {
    match h {
        #[cfg(target_os = "linux")]
        Hardened::Filtered { no_new_privs } => {
            let names: Vec<&str> = agent_denied().iter().map(|(n, _)| *n).collect();
            tracing::info!(
                refused = %names.join(","),
                no_new_privs,
                "seccomp: the agent and every process it starts are refused kernel-wide calls"
            );
        }
        #[cfg(not(target_os = "linux"))]
        Hardened::Filtered { .. } => {}
        Hardened::Unprivileged => tracing::warn!(
            "seccomp: no filter: the agent has no capabilities (what it runs through sudo \
             is not filtered)"
        ),
        Hardened::Unsupported => {}
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const FOREIGN: u32 = 0x4000_0003; // AUDIT_ARCH_I386

    #[cfg(target_os = "linux")]
    #[test]
    fn the_agent_and_codec_filters() {
        use nix::libc;
        let agent = agent_filter();
        let eperm = ret_of(Action::Errno(libc::EPERM as u16));
        let allow = ret_of(Action::Allow);
        let at = |p: &[Insn], nr: libc::c_long, arg: u32| evaluate(p, NATIVE.arch, nr as u32, arg);
        for (name, nr) in agent_denied() {
            assert_eq!(evaluate(&agent, NATIVE.arch, nr, 0), Ok(eperm), "{name}");
        }
        // What orbd and its children use is allowed, the rest of another ABI is not.
        for nr in [
            libc::SYS_read,
            libc::SYS_mount,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_pivot_root,
            libc::SYS_seccomp,
            libc::SYS_ioctl,
            libc::SYS_userfaultfd,
            libc::SYS_io_uring_setup,
            libc::SYS_clone3,
            libc::SYS_name_to_handle_at,
            libc::SYS_clock_gettime,
            libc::SYS_tgkill,
        ] {
            assert_eq!(at(&agent, nr, 0), Ok(allow), "{nr}");
        }
        assert_eq!(evaluate(&agent, FOREIGN, 1, 0), Ok(eperm));
        if NATIVE.x32 {
            assert_eq!(
                evaluate(
                    &agent,
                    NATIVE.arch,
                    X32_SYSCALL_BIT | libc::SYS_read as u32,
                    0
                ),
                Ok(eperm)
            );
        }
        let codec = codec_allowlist(4242);
        let kill = ret_of(Action::KillProcess);
        for nr in [libc::SYS_read, libc::SYS_write, libc::SYS_exit_group] {
            assert_eq!(at(&codec, nr, 0), Ok(allow));
        }
        // Signals to itself only.
        assert_eq!(at(&codec, libc::SYS_tgkill, 4242), Ok(allow));
        assert_eq!(at(&codec, libc::SYS_tkill, 4242), Ok(allow));
        assert_eq!(at(&codec, libc::SYS_tgkill, 4243), Ok(kill));
        assert_eq!(at(&codec, libc::SYS_tkill, 1), Ok(kill));
        for nr in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_sendto,
            libc::SYS_openat,
            libc::SYS_execve,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_ptrace,
            libc::SYS_kill,
            libc::SYS_ioctl,
            libc::SYS_bpf,
            libc::SYS_seccomp,
            libc::SYS_prctl,
            libc::SYS_recvmsg,
        ] {
            assert_eq!(at(&codec, nr, 4242), Ok(kill), "{nr}");
        }
        assert_eq!(
            evaluate(&codec, FOREIGN, libc::SYS_read as u32, 0),
            Ok(kill)
        );
    }

    /// The filters in the kernel, in forked children (with `no_new_privs`, so any user
    /// may install them, and no core dumps): the agent's list (with an errno nothing
    /// else returns, so an outer filter such as Docker's cannot be mistaken for it)
    /// refuses its calls and other ABIs and leaves the rest alone; the codec's kills a
    /// call it does not list and signals to another process.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_enforces_them() {
        use nix::libc;
        use nix::sys::wait::{WaitStatus, waitpid};
        use std::sync::atomic::{AtomicI32, Ordering};
        const MARK: i32 = libc::EHWPOISON;
        static PARENT: AtomicI32 = AtomicI32::new(0);
        PARENT.store(std::process::id() as i32, Ordering::SeqCst);
        // Everything the child needs exists before the fork: it only makes syscalls
        // (and patches its own pid into a pinned argument, `pin`).
        fn fork_with(prog: &[Insn], pin: bool, body: fn() -> i32) -> WaitStatus {
            let mut filter: Vec<libc::sock_filter> = prog
                .iter()
                .map(|i| libc::sock_filter {
                    code: i.code,
                    jt: i.jt,
                    jf: i.jf,
                    k: i.k,
                })
                .collect();
            let pins: Vec<usize> = (1..filter.len())
                .filter(|&n| {
                    filter[n - 1].code == orbd_vm::seccomp::LD_ABS
                        && filter[n - 1].k == orbd_vm::seccomp::ARG0
                })
                .collect();
            // SAFETY: the child makes only raw syscalls and _exits.
            unsafe {
                let pid = libc::fork();
                assert!(pid >= 0);
                if pid == 0 {
                    if pin {
                        for &n in &pins {
                            filter[n].k = libc::getpid() as u32;
                        }
                    }
                    let fprog = libc::sock_fprog {
                        len: filter.len() as libc::c_ushort,
                        filter: filter.as_mut_ptr(),
                    };
                    let no_core = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0
                        || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        || libc::syscall(
                            libc::SYS_seccomp,
                            libc::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
                            0,
                            &fprog as *const libc::sock_fprog,
                        ) != 0
                    {
                        libc::_exit(100);
                    }
                    libc::_exit(body());
                }
                waitpid(nix::unistd::Pid::from_raw(pid), None).unwrap()
            }
        }
        fn errno() -> i32 {
            // SAFETY: reads this thread's errno.
            unsafe { *libc::__errno_location() }
        }
        fn agent_child() -> i32 {
            // SAFETY: invalid arguments; refused by the filter.
            unsafe {
                let refused = |r: libc::c_long| r == -1 && errno() == MARK;
                if !refused(libc::syscall(
                    libc::SYS_perf_event_open,
                    0usize,
                    0,
                    -1,
                    -1,
                    0,
                )) {
                    return 1;
                }
                if !refused(libc::syscall(libc::SYS_bpf, 5, 0usize, 0)) {
                    return 2;
                }
                if !refused(libc::syscall(libc::SYS_open_by_handle_at, -1, 0usize, 0)) {
                    return 3;
                }
                if !refused(libc::syscall(libc::SYS_fanotify_init, 0, 0)) {
                    return 4;
                }
                #[cfg(target_arch = "x86_64")]
                if !refused(libc::syscall(0x4000_0000 | libc::SYS_getpid)) {
                    return 5;
                }
                // Not refused: getpid works, a bad fd is still EBADF.
                if libc::getpid() <= 0 || libc::close(-1) != -1 || errno() != libc::EBADF {
                    return 6;
                }
            }
            0
        }
        let nrs: Vec<u32> = agent_denied().iter().map(|(_, nr)| *nr).collect();
        let marked = Action::Errno(MARK as u16);
        let agent = program(NATIVE, &nrs, &[], marked, Action::Allow, marked);
        let s = fork_with(&agent, false, agent_child);
        assert!(matches!(s, WaitStatus::Exited(_, 0)), "{s:?}");

        let sys = |s: WaitStatus| match s {
            WaitStatus::Signaled(_, sig, _) => sig == nix::sys::signal::SIGSYS,
            _ => false,
        };
        fn getuid() -> i32 {
            // SAFETY: getuid is not on the codec's list: the process dies.
            unsafe { libc::getuid() as i32 + 50 }
        }
        let codec = codec_allowlist(0);
        let s = fork_with(&codec, true, getuid);
        assert!(sys(s), "the codec's filter let getuid through: {s:?}");
        fn signal_parent() -> i32 {
            let parent = PARENT.load(Ordering::SeqCst);
            // SAFETY: signal 0 (a check only) to another process: the process dies.
            unsafe { libc::syscall(libc::SYS_tgkill, parent, parent, 0) as i32 + 60 }
        }
        let s = fork_with(&codec, true, signal_parent);
        assert!(
            sys(s),
            "the codec's filter let tgkill to another process through: {s:?}"
        );
        fn allowed() -> i32 {
            let msg = b"";
            // SAFETY: an empty write to stderr and signal 0 to itself; allowed.
            unsafe {
                let me = libc::getpid();
                if libc::syscall(libc::SYS_tgkill, me, me, 0) != 0 {
                    return 1;
                }
                libc::write(2, msg.as_ptr().cast(), 0) as i32
            }
        }
        let s = fork_with(&codec, true, allowed);
        assert!(matches!(s, WaitStatus::Exited(_, 0)), "{s:?}");
    }
}
