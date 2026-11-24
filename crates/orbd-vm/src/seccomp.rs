//! Seccomp filters as classic BPF programs: a small builder ([`program`]), an
//! interpreter for tests ([`evaluate`]), installing one ([`install`]), and the filter
//! every jailed process gets ([`no_namespaces`]): jails (and the image sandbox) install it
//! right before exec, under whatever filter the program installs itself.

/// What a filter does with a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allow,
    Errno(u16),
    KillProcess,
}

impl Action {
    fn ret(self) -> u32 {
        match self {
            // SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO | errno, SECCOMP_RET_KILL_PROCESS.
            Action::Allow => 0x7fff_0000,
            Action::Errno(e) => 0x0005_0000 | u32::from(e),
            Action::KillProcess => 0x8000_0000,
        }
    }
}

/// One classic BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// BPF_LD | BPF_W | BPF_ABS, BPF_JMP | BPF_JEQ | BPF_K, BPF_JMP | BPF_JGE | BPF_K,
// BPF_RET | BPF_K.
pub const LD_ABS: u16 = 0x20;
pub const JEQ: u16 = 0x15;
pub const JGE: u16 = 0x35;
pub const RET: u16 = 0x06;
/// BPF_JMP | BPF_JSET | BPF_K.
pub const JSET: u16 = 0x45;
/// Offsets in `struct seccomp_data`: the call's number, its arch, the low 32 bits of its
/// first argument (little-endian, as every arch here is).
pub const NR: u32 = 0;
pub const ARCH: u32 = 4;
pub const ARG0: u32 = 16;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
/// x32 calls on x86_64: the native arch with this bit in the number.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The ABI a filter allows: its arch and whether it must refuse x32 numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Abi {
    pub arch: u32,
    pub x32: bool,
}

/// This build's ABI.
#[cfg(target_arch = "x86_64")]
pub const NATIVE: Abi = Abi {
    arch: AUDIT_ARCH_X86_64,
    x32: true,
};
#[cfg(target_arch = "aarch64")]
pub const NATIVE: Abi = Abi {
    arch: AUDIT_ARCH_AARCH64,
    x32: false,
};

/// A filter: calls in `listed` get `on_listed`, so do calls in `pinned` whose first
/// argument (as an `int`) is the one given there (`otherwise` with another), other calls
/// get `otherwise`, and every call of another ABI `foreign`.
pub fn program(
    abi: Abi,
    listed: &[u32],
    pinned: &[(u32, u32)],
    on_listed: Action,
    otherwise: Action,
    foreign: Action,
) -> Vec<Insn> {
    assert!(listed.len() < 255, "jumps are one byte");
    let i = |code, jt, jf, k| Insn { code, jt, jf, k };
    let mut p = vec![
        i(LD_ABS, 0, 0, ARCH),
        i(JEQ, 1, 0, abi.arch),
        i(RET, 0, 0, foreign.ret()),
        i(LD_ABS, 0, 0, NR),
    ];
    if abi.x32 {
        p.push(i(JGE, 0, 1, X32_SYSCALL_BIT));
        p.push(i(RET, 0, 0, foreign.ret()));
    }
    for &(nr, arg) in pinned {
        // Another call: past this block, with the number still loaded.
        p.push(i(JEQ, 0, 4, nr));
        p.push(i(LD_ABS, 0, 0, ARG0));
        p.push(i(JEQ, 0, 1, arg));
        p.push(i(RET, 0, 0, on_listed.ret()));
        p.push(i(RET, 0, 0, otherwise.ret()));
    }
    let n = listed.len();
    for (at, nr) in listed.iter().enumerate() {
        // Past the rest of the list and the `otherwise` return.
        p.push(i(JEQ, (n - at) as u8, 0, *nr));
    }
    p.push(i(RET, 0, 0, otherwise.ret()));
    p.push(i(RET, 0, 0, on_listed.ret()));
    p
}

/// What `prog` returns for a call `nr` of `arch` with first argument `arg0` (the subset
/// of classic BPF that [`program`] and [`no_namespaces`] emit; anything else, or a jump
/// out of the program, is an error).
pub fn evaluate(prog: &[Insn], arch: u32, nr: u32, arg0: u32) -> Result<u32, String> {
    let mut a = 0u32;
    let mut pc = 0usize;
    loop {
        let insn = prog
            .get(pc)
            .ok_or_else(|| format!("ran off the end at {pc}"))?;
        pc += 1;
        let jump = |taken: bool| -> usize { usize::from(if taken { insn.jt } else { insn.jf }) };
        match insn.code {
            LD_ABS => {
                a = match insn.k {
                    NR => nr,
                    ARCH => arch,
                    ARG0 => arg0,
                    k => return Err(format!("load of offset {k}")),
                }
            }
            JEQ => pc += jump(a == insn.k),
            JGE => pc += jump(a >= insn.k),
            JSET => pc += jump(a & insn.k != 0),
            RET => return Ok(insn.k),
            c => return Err(format!("instruction {c:#x}")),
        }
    }
}

/// The ret value for `action` (to compare with [`evaluate`]).
pub fn ret_of(action: Action) -> u32 {
    action.ret()
}

/// `prog` as the kernel takes it.
#[cfg(target_os = "linux")]
pub fn sock_filters(prog: &[Insn]) -> Vec<nix::libc::sock_filter> {
    prog.iter()
        .map(|i| nix::libc::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect()
}

/// Namespace flags `clone` takes (CLONE_NEWTIME shares its bit with the exit signal there,
/// and only `clone3` and `unshare` take it).
#[cfg(target_os = "linux")]
pub const CLONE_NAMESPACES: u32 = (nix::libc::CLONE_NEWNS
    | nix::libc::CLONE_NEWCGROUP
    | nix::libc::CLONE_NEWUTS
    | nix::libc::CLONE_NEWIPC
    | nix::libc::CLONE_NEWUSER
    | nix::libc::CLONE_NEWPID
    | nix::libc::CLONE_NEWNET) as u32;
/// Namespace flags `unshare` takes.
#[cfg(target_os = "linux")]
pub const UNSHARE_NAMESPACES: u32 = CLONE_NAMESPACES | 0x80; // CLONE_NEWTIME

/// The new mount API's calls (`open_tree`, `move_mount`, `fsopen`, `fsconfig`,
/// `fsmount`, `fspick`, `mount_setattr`, `open_tree_attr`; numbered alike on every
/// arch): `open_tree` and `fsmount` can make mount namespaces of their own.
pub const MOUNT_API: [u32; 8] = [428, 429, 430, 431, 432, 433, 442, 467];

/// The filter of jailed processes: no new namespaces, so no user namespace whose
/// capabilities reach more of the kernel (nftables, mounts) from an escaped VMM or an
/// exploited tool. `unshare` and `clone` with any namespace flag, `setns` and the new
/// mount API ([`MOUNT_API`]) fail with `EPERM`; `clone3`, whose flags are in memory a
/// filter cannot read, fails with `ENOSYS`, so libc falls back to `clone`. Every call of
/// another ABI fails with `EPERM`. Anything else is allowed. The flags are the first
/// argument of both calls on x86_64 and arm64; the kernel reads only their low 32 bits
/// for `clone`, and refuses unknown higher ones for `unshare`.
#[cfg(target_os = "linux")]
pub fn no_namespaces() -> Vec<Insn> {
    use nix::libc;
    let i = |code, jt, jf, k| Insn { code, jt, jf, k };
    let eperm = Action::Errno(libc::EPERM as u16).ret();
    let enosys = Action::Errno(libc::ENOSYS as u16).ret();
    let allow = Action::Allow.ret();
    let mut p = vec![
        i(LD_ABS, 0, 0, ARCH),
        i(JEQ, 1, 0, NATIVE.arch),
        i(RET, 0, 0, eperm),
        i(LD_ABS, 0, 0, NR),
    ];
    if NATIVE.x32 {
        p.push(i(JGE, 0, 1, X32_SYSCALL_BIT));
        p.push(i(RET, 0, 0, eperm));
    }
    // Relative to the dispatch's first instruction: the dispatch (2 + m + 2), then
    // allow, ENOSYS, EPERM, clone's flag check (4), unshare's (4).
    let m = MOUNT_API.len();
    let (allow_at, enosys_at, eperm_at) = (4 + m, 5 + m, 6 + m);
    let (clone_at, unshare_at) = (7 + m, 11 + m);
    let to = |from: usize, target: usize| (target - from - 1) as u8;
    let mut d = vec![
        i(JEQ, to(0, enosys_at), 0, libc::SYS_clone3 as u32),
        i(JEQ, to(1, eperm_at), 0, libc::SYS_setns as u32),
    ];
    for (n, nr) in MOUNT_API.iter().enumerate() {
        d.push(i(JEQ, to(2 + n, eperm_at), 0, *nr));
    }
    d.push(i(JEQ, to(2 + m, clone_at), 0, libc::SYS_clone as u32));
    d.push(i(JEQ, to(3 + m, unshare_at), 0, libc::SYS_unshare as u32));
    assert_eq!(d.len(), allow_at);
    d.extend([
        i(RET, 0, 0, allow),
        i(RET, 0, 0, enosys),
        i(RET, 0, 0, eperm),
        i(LD_ABS, 0, 0, ARG0),
        i(JSET, 0, 1, CLONE_NAMESPACES),
        i(RET, 0, 0, eperm),
        i(RET, 0, 0, allow),
        i(LD_ABS, 0, 0, ARG0),
        i(JSET, 0, 1, UNSHARE_NAMESPACES),
        i(RET, 0, 0, eperm),
        i(RET, 0, 0, allow),
    ]);
    p.extend(d);
    p
}

/// Installs `prog` on the calling thread (every thread with `tsync`).
#[cfg(target_os = "linux")]
pub fn install(prog: &[Insn], tsync: bool) -> std::io::Result<()> {
    use nix::libc;
    let filter = sock_filters(prog);
    let fprog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    let flags = if tsync {
        libc::SECCOMP_FILTER_FLAG_TSYNC
    } else {
        0
    };
    // SAFETY: seccomp(2) reads `fprog` and the filter it points to, both alive here.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
            flags,
            &fprog as *const libc::sock_fprog,
        )
    };
    match r {
        0 => Ok(()),
        // With TSYNC, a positive return names a thread that could not be synchronized.
        r if r > 0 => Err(std::io::Error::other(format!(
            "thread {r} could not take the filter"
        ))),
        _ => Err(std::io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOREIGN: u32 = 0x4000_0003; // AUDIT_ARCH_I386

    #[test]
    fn programs_decide_by_abi_number_and_pinned_argument() {
        let x86 = Abi {
            arch: AUDIT_ARCH_X86_64,
            x32: true,
        };
        let eperm = Action::Errno(1);
        let kill = Action::KillProcess;
        let p = program(x86, &[321, 298, 7], &[], eperm, Action::Allow, kill);
        let ret = |arch, nr| evaluate(&p, arch, nr, 0).unwrap();
        for nr in [321, 298, 7] {
            assert_eq!(ret(AUDIT_ARCH_X86_64, nr), ret_of(eperm), "{nr}");
        }
        for nr in [0, 1, 6, 8, 299, 320, 322, 0x3fff_ffff] {
            assert_eq!(ret(AUDIT_ARCH_X86_64, nr), ret_of(Action::Allow), "{nr}");
        }
        // x32 numbers, listed or not, and another arch.
        for nr in [X32_SYSCALL_BIT | 321, X32_SYSCALL_BIT, u32::MAX] {
            assert_eq!(ret(AUDIT_ARCH_X86_64, nr), ret_of(kill));
        }
        for arch in [FOREIGN, AUDIT_ARCH_AARCH64, 0] {
            assert_eq!(ret(arch, 1), ret_of(kill));
        }
        // arm64 has no x32: every number is decided by the lists.
        let arm = Abi {
            arch: AUDIT_ARCH_AARCH64,
            x32: false,
        };
        let p = program(
            arm,
            &[63],
            &[(131, 4242), (130, 7)],
            Action::Allow,
            kill,
            eperm,
        );
        let ret = |arch, nr, arg| evaluate(&p, arch, nr, arg).unwrap();
        assert_eq!(ret(AUDIT_ARCH_AARCH64, 63, 9), ret_of(Action::Allow));
        assert_eq!(
            ret(AUDIT_ARCH_AARCH64, X32_SYSCALL_BIT | 63, 0),
            ret_of(kill)
        );
        assert_eq!(ret(AUDIT_ARCH_X86_64, 63, 0), ret_of(eperm));
        // Pinned calls: allowed with their argument only; the next pin and the list
        // still decide other calls.
        assert_eq!(ret(AUDIT_ARCH_AARCH64, 131, 4242), ret_of(Action::Allow));
        assert_eq!(ret(AUDIT_ARCH_AARCH64, 131, 4243), ret_of(kill));
        assert_eq!(ret(AUDIT_ARCH_AARCH64, 130, 7), ret_of(Action::Allow));
        assert_eq!(ret(AUDIT_ARCH_AARCH64, 130, 4242), ret_of(kill));
        assert_eq!(ret(AUDIT_ARCH_AARCH64, 132, 4242), ret_of(kill));
        assert_eq!(ret(AUDIT_ARCH_AARCH64, 63, 4242), ret_of(Action::Allow));
        // An empty list: everything native gets `otherwise`.
        let p = program(arm, &[], &[], eperm, Action::Allow, kill);
        assert_eq!(
            evaluate(&p, AUDIT_ARCH_AARCH64, 5, 0),
            Ok(ret_of(Action::Allow))
        );
    }

    /// Namespace flags are refused on `clone` and `unshare`, alone or with others; what
    /// threads, `fork` and `unshare` without them use is not; `clone3` is ENOSYS, `setns`
    /// and other ABIs EPERM.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_namespaces_checks_the_flags() {
        use nix::libc;
        let p = no_namespaces();
        let ret = |nr: libc::c_long, arg: u32| evaluate(&p, NATIVE.arch, nr as u32, arg).unwrap();
        let eperm = ret_of(Action::Errno(libc::EPERM as u16));
        let enosys = ret_of(Action::Errno(libc::ENOSYS as u16));
        let allow = ret_of(Action::Allow);
        let thread = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u32;
        let sigchld = libc::SIGCHLD as u32;
        assert_eq!(ret(libc::SYS_clone, thread), allow, "a thread");
        assert_eq!(ret(libc::SYS_clone, sigchld), allow, "fork");
        assert_eq!(
            ret(
                libc::SYS_clone,
                (libc::CLONE_VM | libc::CLONE_VFORK) as u32 | sigchld
            ),
            allow,
            "vfork"
        );
        assert_eq!(
            ret(
                libc::SYS_unshare,
                (libc::CLONE_FS | libc::CLONE_FILES) as u32
            ),
            allow
        );
        let each = [
            libc::CLONE_NEWNS,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWNET,
        ];
        for f in each {
            let f = f as u32;
            assert_eq!(ret(libc::SYS_clone, f | sigchld), eperm, "clone {f:#x}");
            assert_eq!(
                ret(libc::SYS_clone, f | thread),
                eperm,
                "clone {f:#x} with a thread's"
            );
            assert_eq!(ret(libc::SYS_unshare, f), eperm, "unshare {f:#x}");
            assert_eq!(ret(libc::SYS_unshare, f | libc::CLONE_FS as u32), eperm);
        }
        assert_eq!(ret(libc::SYS_unshare, 0x80), eperm, "CLONE_NEWTIME");
        assert_eq!(ret(libc::SYS_setns, 0), eperm);
        assert_eq!(ret(libc::SYS_clone3, 0), enosys);
        for nr in MOUNT_API {
            assert_eq!(
                evaluate(&p, NATIVE.arch, nr, 0),
                Ok(eperm),
                "mount API {nr}"
            );
        }
        assert_eq!(MOUNT_API[0], libc::SYS_open_tree as u32);
        assert_eq!(MOUNT_API[4], libc::SYS_fsmount as u32);
        for nr in [
            libc::SYS_read,
            libc::SYS_mount,
            libc::SYS_execve,
            libc::SYS_seccomp,
        ] {
            assert_eq!(ret(nr, libc::CLONE_NEWUSER as u32), allow, "{nr}");
        }
        assert_eq!(evaluate(&p, FOREIGN, libc::SYS_read as u32, 0), Ok(eperm));
        if NATIVE.x32 {
            let x32 = X32_SYSCALL_BIT | libc::SYS_unshare as u32;
            assert_eq!(evaluate(&p, NATIVE.arch, x32, 0), Ok(eperm));
        }
    }

    /// The same in the kernel, in a forked child with `no_new_privs`: a user namespace,
    /// `setns` (EPERM, where unfiltered `setns(-1)` is EBADF) and `open_tree` (which needs
    /// no privilege unfiltered) are refused, `clone3` is ENOSYS, a fork and
    /// `unshare(CLONE_FS)` work.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_refuses_new_namespaces() {
        use nix::libc;
        let filter = sock_filters(&no_namespaces());
        // SAFETY: the child makes only raw syscalls on data prepared before the fork.
        let status = unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                let fprog = libc::sock_fprog {
                    len: filter.len() as libc::c_ushort,
                    filter: filter.as_ptr() as *mut libc::sock_filter,
                };
                let no_core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let errno = || *libc::__errno_location();
                let code = if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::syscall(
                        libc::SYS_seccomp,
                        libc::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
                        0,
                        &fprog as *const libc::sock_fprog,
                    ) != 0
                {
                    100
                } else if libc::unshare(libc::CLONE_NEWUSER) != -1 || errno() != libc::EPERM {
                    1
                } else if libc::syscall(
                    libc::SYS_clone,
                    (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_ulong,
                    0usize,
                    0usize,
                    0usize,
                    0usize,
                ) != -1
                    || errno() != libc::EPERM
                {
                    2
                } else if libc::setns(-1, 0) != -1 || errno() != libc::EPERM {
                    3
                } else if libc::syscall(libc::SYS_clone3, 0usize, 0usize) != -1
                    || errno() != libc::ENOSYS
                {
                    4
                } else if libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, c"/".as_ptr(), 0) != -1
                    || errno() != libc::EPERM
                {
                    7
                } else if libc::unshare(libc::CLONE_FS) != 0 {
                    5
                } else {
                    let child = libc::syscall(
                        libc::SYS_clone,
                        libc::SIGCHLD as libc::c_ulong,
                        0usize,
                        0usize,
                        0usize,
                        0usize,
                    );
                    if child == 0 {
                        libc::_exit(0);
                    }
                    let mut st = 0;
                    if child < 0 || libc::waitpid(child as libc::pid_t, &mut st, 0) != child as i32
                    {
                        6
                    } else {
                        0
                    }
                };
                libc::_exit(code);
            }
            let mut st = 0;
            assert_eq!(libc::waitpid(pid, &mut st, 0), pid);
            st
        };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the filtered child failed at step {}",
            libc::WEXITSTATUS(status)
        );
    }
}
