//! Jails for VMM processes (Linux). A jailed VMM runs under its own unprivileged uid and
//! gid with no capabilities and `no_new_privs`, in a private mount namespace whose root
//! is a fresh read-only tmpfs holding only bind mounts of the host paths it needs. Each
//! path is mounted at its original path (or a chosen one, [`Bind::dst`]), so paths in
//! its arguments and in the snapshots it saved stay valid. Mounts are `nosuid`, data is
//! `noexec`, and only device nodes lack `nodev`; there is no `/proc`, `/sys` or `/etc`.
//! It can create no namespaces ([`crate::seccomp::no_namespaces`], installed last,
//! under whatever filter the program installs itself): no user namespace of its own
//! brings capabilities back.
//!
//! The launcher enters the jail between fork and exec ([`crate::process::Spawn::jail`]),
//! after it moved the child into its cgroup and network namespace: every path and buffer
//! is prepared before the fork and only raw syscalls run in the child. A step that fails
//! writes `orbd jail: <step> <path>: errno <n>` to the child's stderr and fails the
//! launch, so nothing runs unjailed. Inherited file descriptors beyond stdio are closed
//! on exec.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

/// How a bind mount may be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Read-only data, not executable.
    Read,
    /// Read-only programs and libraries.
    Exec,
    /// Read-write data, not executable.
    Write,
    /// A device node: read-write, not executable, the only kind without `nodev`.
    Device,
}

/// One host path made visible in a jail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    /// Host path; a symbolic link is followed.
    pub src: PathBuf,
    /// Absolute path in the jail.
    pub dst: PathBuf,
    pub access: Access,
}

impl Bind {
    /// `path` at its own path.
    pub fn at(path: impl Into<PathBuf>, access: Access) -> Self {
        let src = path.into();
        Self {
            dst: src.clone(),
            src,
            access,
        }
    }
}

/// Everything a jail holds, and who runs in it.
#[derive(Clone, Debug)]
pub struct Jail {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups (e.g. `/dev/kvm`'s).
    pub groups: Vec<u32>,
    /// An empty host directory the jail's root is mounted on. The mounts exist only in
    /// the jailed process's mount namespace: on the host it stays empty.
    pub staging: PathBuf,
    pub binds: Vec<Bind>,
    /// Symbolic links `(path in the jail, target)`, e.g. `/lib` → `usr/lib`.
    pub symlinks: Vec<(PathBuf, PathBuf)>,
    /// A network namespace of its own, with nothing but loopback (for a tool; a VMM
    /// joins its orb's namespace through `Spawn::netns` instead).
    pub new_netns: bool,
}

/// Who a jailed process runs as (recorded with its launch).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl Jail {
    pub fn identity(&self) -> JailIdentity {
        JailIdentity {
            uid: self.uid,
            gid: self.gid,
        }
    }
}

/// Where `dst` (absolute, normalized) lands under `staging`.
#[cfg(target_os = "linux")]
fn under(staging: &Path, dst: &Path) -> std::io::Result<PathBuf> {
    use std::path::Component;
    let mut out = staging.to_owned();
    let mut parts = dst.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(invalid(format!("{} is not absolute", dst.display())));
    }
    for c in parts {
        match c {
            Component::Normal(n) => out.push(n),
            _ => return Err(invalid(format!("{} is not normalized", dst.display()))),
        }
    }
    if out == staging {
        return Err(invalid(
            "nothing is mounted or linked over the jail's root".into(),
        ));
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn invalid(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
}

/// A command that runs `program` (an absolute path in the jail) in `jail`, with an empty
/// environment; the caller adds arguments, environment and stdio (and may turn it into
/// a `tokio::process::Command`).
#[cfg(target_os = "linux")]
pub fn command(jail: &Jail, program: &Path) -> std::io::Result<std::process::Command> {
    command_with(jail.prepare()?, program)
}

#[cfg(target_os = "linux")]
fn command_with(
    prepared: linux::Prepared,
    program: &Path,
) -> std::io::Result<std::process::Command> {
    use std::os::unix::process::CommandExt;
    if !program.is_absolute() {
        return Err(invalid(format!("{} is not absolute", program.display())));
    }
    let mut cmd = std::process::Command::new(program);
    cmd.env_clear().stdin(std::process::Stdio::null());
    // SAFETY: `enter` makes only async-signal-safe syscalls on prepared data.
    unsafe {
        cmd.pre_exec(move || prepared.enter());
    }
    Ok(cmd)
}

/// Runs `program` in `jail` and collects its output (e.g. a self-test at startup).
#[cfg(target_os = "linux")]
pub fn run(jail: &Jail, program: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    command(jail, program)?.args(args).output()
}

#[cfg(target_os = "linux")]
pub(crate) use linux::shed_privileges;

#[cfg(target_os = "linux")]
mod linux {
    use super::{Access, Jail, under};
    use nix::libc::{self, c_int, c_ulong};
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null;

    struct PreparedBind {
        /// Directories to create first (ancestors, then the target for a directory).
        dirs: Vec<CString>,
        /// Mount target to create for a non-directory source.
        file: Option<CString>,
        src: CString,
        dst: CString,
        /// `MS_REMOUNT | MS_BIND | ...`: the bind's own flags plus those its source
        /// mount already has (which a remount may not clear).
        flags: c_ulong,
    }

    struct PreparedLink {
        dirs: Vec<CString>,
        target: CString,
        link: CString,
    }

    /// A [`Jail`] with every path, flag and buffer the child needs computed up front.
    pub(crate) struct Prepared {
        staging: CString,
        binds: Vec<PreparedBind>,
        links: Vec<PreparedLink>,
        uid: libc::uid_t,
        gid: libc::gid_t,
        groups: Vec<libc::gid_t>,
        last_cap: u32,
        /// Bound for the fallback that marks inherited fds close-on-exec one by one.
        max_fd: c_int,
        /// Try pivot_root before the move-and-chroot fallback (tests force the latter).
        pivot: bool,
        /// Unshare a network namespace too ([`Jail::new_netns`]).
        new_netns: bool,
        /// [`crate::seccomp::no_namespaces`], as the kernel takes it.
        filter: Vec<libc::sock_filter>,
    }

    fn cstring(p: &Path) -> std::io::Result<CString> {
        CString::new(p.as_os_str().as_bytes())
            .map_err(|_| super::invalid(format!("{} contains NUL", p.display())))
    }

    /// Ancestors of `target` below `staging`, outermost first.
    fn ancestors(staging: &Path, target: &Path) -> std::io::Result<Vec<CString>> {
        let mut dirs: Vec<&Path> = target
            .ancestors()
            .skip(1)
            .take_while(|a| *a != staging)
            .collect();
        dirs.reverse();
        dirs.into_iter().map(cstring).collect()
    }

    /// Flags of the mount holding `path` that a remount of a bind of it must keep.
    fn source_flags(path: &Path) -> std::io::Result<c_ulong> {
        // `statvfs` flags (the kernel's ST_* values, the same on every libc).
        const KEEP: [(c_ulong, c_ulong); 7] = [
            (1, libc::MS_RDONLY),
            (2, libc::MS_NOSUID),
            (4, libc::MS_NODEV),
            (8, libc::MS_NOEXEC),
            (1024, libc::MS_NOATIME),
            (2048, libc::MS_NODIRATIME),
            (4096, libc::MS_RELATIME),
        ];
        let st = nix::sys::statvfs::statvfs(path).map_err(std::io::Error::from)?;
        let bits = st.flags().bits() as c_ulong;
        Ok(KEEP
            .iter()
            .filter(|(st, _)| bits & st != 0)
            .fold(0, |acc, (_, ms)| acc | ms))
    }

    impl Jail {
        /// Checks the jail and computes what entering it needs (before the fork).
        pub(crate) fn prepare(&self) -> std::io::Result<Prepared> {
            self.prepare_with(true)
        }

        /// [`Jail::prepare`]; without `pivot` the root is always entered by the
        /// move-and-chroot fallback (as where seccomp refuses pivot_root).
        pub(crate) fn prepare_with(&self, pivot: bool) -> std::io::Result<Prepared> {
            let bad_id = |id: u32| id == 0 || id == u32::MAX;
            if bad_id(self.uid) || bad_id(self.gid) || self.groups.iter().any(|g| bad_id(*g)) {
                return Err(super::invalid(format!(
                    "jail uid {} / gid {} / groups {:?}: not root, not -1",
                    self.uid, self.gid, self.groups
                )));
            }
            if !self.staging.is_absolute() || !self.staging.is_dir() {
                return Err(super::invalid(format!(
                    "jail staging {} is not an absolute directory",
                    self.staging.display()
                )));
            }
            let mut binds: Vec<&super::Bind> = self.binds.iter().collect();
            // Parents before what is mounted inside them.
            binds.sort_by_key(|b| b.dst.components().count());
            let mut prepared = Vec::with_capacity(binds.len());
            for b in binds {
                let meta = std::fs::metadata(&b.src).map_err(|e| {
                    std::io::Error::new(e.kind(), format!("{}: {e}", b.src.display()))
                })?;
                let target = under(&self.staging, &b.dst)?;
                let mut dirs = ancestors(&self.staging, &target)?;
                let file = if meta.is_dir() {
                    dirs.push(cstring(&target)?);
                    None
                } else {
                    Some(cstring(&target)?)
                };
                let own = match b.access {
                    Access::Read => libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOEXEC,
                    Access::Exec => libc::MS_RDONLY | libc::MS_NODEV,
                    Access::Write => libc::MS_NODEV | libc::MS_NOEXEC,
                    Access::Device => libc::MS_NOEXEC,
                };
                prepared.push(PreparedBind {
                    dirs,
                    file,
                    src: cstring(&b.src)?,
                    dst: cstring(&target)?,
                    flags: libc::MS_REMOUNT
                        | libc::MS_BIND
                        | libc::MS_NOSUID
                        | own
                        | source_flags(&b.src)?,
                });
            }
            let links = self
                .symlinks
                .iter()
                .map(|(path, target)| {
                    let link = under(&self.staging, path)?;
                    Ok(PreparedLink {
                        dirs: ancestors(&self.staging, &link)?,
                        target: cstring(target)?,
                        link: cstring(&link)?,
                    })
                })
                .collect::<std::io::Result<_>>()?;
            let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(63);
            let mut nofile = libc::rlimit {
                rlim_cur: 1 << 16,
                rlim_max: 1 << 16,
            };
            // SAFETY: getrlimit fills a valid struct (left at its default on failure).
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut nofile) };
            let max_fd = nofile.rlim_cur.min(1 << 20) as c_int;
            Ok(Prepared {
                staging: cstring(&self.staging)?,
                binds: prepared,
                links,
                uid: self.uid,
                gid: self.gid,
                groups: self.groups.clone(),
                last_cap,
                max_fd,
                pivot,
                new_netns: self.new_netns,
                filter: crate::seccomp::sock_filters(&crate::seccomp::no_namespaces()),
            })
        }
    }

    /// `_LINUX_CAPABILITY_VERSION_3`.
    const CAP_V3: u32 = 0x2008_0522;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    /// For a forked helper that has switched to `uid` and `gid`: drops every capability
    /// (the kernel does not when the agent runs with `SECBIT_NO_SETUID_FIXUP`), makes
    /// the process undumpable and unable to gain privileges, and reports whether it is
    /// now exactly `uid`/`gid` with no capability left. Async-signal-safe.
    ///
    /// # Safety
    /// Raw syscalls only; call between fork and exit or exec.
    pub(crate) unsafe fn shed_privileges(uid: u32, gid: u32) -> bool {
        // SAFETY: plain syscalls on stack buffers.
        unsafe {
            let header = CapHeader {
                version: CAP_V3,
                pid: 0,
            };
            let none = [CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            if libc::syscall(libc::SYS_capset, &header, none.as_ptr()) != 0 {
                return false;
            }
            let mut now = none;
            if libc::syscall(libc::SYS_capget, &header, now.as_mut_ptr()) != 0
                || now.iter().any(|d| d.effective != 0 || d.permitted != 0)
            {
                return false;
            }
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
                && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::getuid() == uid
                && libc::geteuid() == uid
                && libc::getgid() == gid
                && libc::getegid() == gid
        }
    }

    /// [`report`]s the last OS error.
    fn fail(what: &str, path: Option<&CStr>) -> std::io::Error {
        report(what, path, std::io::Error::last_os_error())
    }

    /// Writes `orbd jail: <what> <path>: errno <n>` to stderr and returns `err`.
    /// Async-signal-safe: no allocation, only `write`.
    fn report(what: &str, path: Option<&CStr>, err: std::io::Error) -> std::io::Error {
        let errno = err.raw_os_error().unwrap_or(0);
        let mut num = [0u8; 12];
        let mut i = num.len();
        let mut n = errno.unsigned_abs();
        loop {
            i -= 1;
            num[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        let out = |b: &[u8]| {
            // SAFETY: write(2) of a valid buffer; a short or failed write is ignored.
            unsafe { libc::write(2, b.as_ptr().cast(), b.len()) };
        };
        out(b"orbd jail: ");
        out(what.as_bytes());
        if let Some(p) = path {
            out(b" ");
            out(p.to_bytes());
        }
        out(b": errno ");
        out(&num[i..]);
        out(b"\n");
        err
    }

    fn check(r: c_int, what: &str, path: Option<&CStr>) -> std::io::Result<()> {
        if r < 0 { Err(fail(what, path)) } else { Ok(()) }
    }

    fn mkdirs(dirs: &[CString]) -> std::io::Result<()> {
        for d in dirs {
            // SAFETY: a NUL-terminated path.
            if unsafe { libc::mkdir(d.as_ptr(), 0o755) } < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
            {
                return Err(fail("mkdir", Some(d)));
            }
        }
        Ok(())
    }

    impl Prepared {
        /// Enters the jail. Runs between fork and exec: only raw syscalls on data
        /// computed by [`Jail::prepare`] (no allocation, no locks).
        pub(crate) fn enter(&self) -> std::io::Result<()> {
            // SAFETY (whole function): plain syscalls with NUL-terminated paths and
            // buffers that live in `self`.
            unsafe {
                let net = if self.new_netns {
                    libc::CLONE_NEWNET
                } else {
                    0
                };
                check(libc::unshare(libc::CLONE_NEWNS | net), "unshare", None)?;
                // The jail's directories and mount points get their modes as written (the
                // agent's umask, e.g. 077, would make them untraversable for the VMM's
                // uid); restored below.
                let umask = libc::umask(0o022);
                // Nothing mounted here reaches the host, nor anything later the jail.
                check(
                    libc::mount(
                        null(),
                        c"/".as_ptr(),
                        null(),
                        libc::MS_REC | libc::MS_PRIVATE,
                        null(),
                    ),
                    "private mounts",
                    None,
                )?;
                check(
                    libc::mount(
                        c"tmpfs".as_ptr(),
                        self.staging.as_ptr(),
                        c"tmpfs".as_ptr(),
                        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                        c"mode=0755,size=1m,nr_inodes=4096".as_ptr().cast(),
                    ),
                    "root tmpfs",
                    Some(&self.staging),
                )?;
                for b in &self.binds {
                    mkdirs(&b.dirs)?;
                    if let Some(f) = &b.file {
                        let fd = libc::open(
                            f.as_ptr(),
                            libc::O_RDONLY | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                            0o644,
                        );
                        if fd < 0 {
                            return Err(fail("creating mount point", Some(f)));
                        }
                        libc::close(fd);
                    }
                    check(
                        libc::mount(
                            b.src.as_ptr(),
                            b.dst.as_ptr(),
                            null(),
                            libc::MS_BIND,
                            null(),
                        ),
                        "bind",
                        Some(&b.src),
                    )?;
                    check(
                        libc::mount(null(), b.dst.as_ptr(), null(), b.flags, null()),
                        "remount",
                        Some(&b.src),
                    )?;
                }
                for l in &self.links {
                    mkdirs(&l.dirs)?;
                    check(
                        libc::symlink(l.target.as_ptr(), l.link.as_ptr()),
                        "symlink",
                        Some(&l.link),
                    )?;
                }
                check(
                    libc::mount(
                        null(),
                        self.staging.as_ptr(),
                        null(),
                        libc::MS_REMOUNT
                            | libc::MS_RDONLY
                            | libc::MS_NOSUID
                            | libc::MS_NODEV
                            | libc::MS_NOEXEC,
                        null(),
                    ),
                    "read-only root",
                    None,
                )?;
                // The tmpfs becomes the root; the old root is stacked on it and detached.
                check(
                    libc::chdir(self.staging.as_ptr()),
                    "chdir",
                    Some(&self.staging),
                )?;
                if self.pivot
                    && libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) == 0
                {
                    check(
                        libc::umount2(c".".as_ptr(), libc::MNT_DETACH),
                        "detaching the old root",
                        None,
                    )?;
                } else if !self.pivot
                    || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
                {
                    // Docker's default seccomp profile refuses pivot_root: move the tmpfs
                    // over the old root and chroot into it, as runc does without
                    // pivot_root. The old root's mounts stay below, unreachable: the VMM
                    // keeps no descriptor there (cwd is in the tmpfs; the rest close on
                    // exec) and loses CAP_SYS_CHROOT and CAP_SYS_ADMIN below.
                    check(
                        libc::mount(c".".as_ptr(), c"/".as_ptr(), null(), libc::MS_MOVE, null()),
                        "moving the root",
                        None,
                    )?;
                    check(libc::chroot(c".".as_ptr()), "chroot", None)?;
                } else {
                    check(-1, "pivot_root", None)?;
                }
                check(libc::chdir(c"/".as_ptr()), "chdir /", None)?;
                libc::umask(umask);

                // Identity: nothing privileged survives the uid change, and exec cannot
                // grant anything back.
                for cap in 0..=self.last_cap {
                    libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
                }
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
                check(
                    libc::setgroups(self.groups.len(), self.groups.as_ptr()),
                    "setgroups",
                    None,
                )?;
                check(
                    libc::setresgid(self.gid, self.gid, self.gid),
                    "setresgid",
                    None,
                )?;
                check(
                    libc::setresuid(self.uid, self.uid, self.uid),
                    "setresuid",
                    None,
                )?;
                let header = CapHeader {
                    version: CAP_V3,
                    pid: 0,
                };
                let none = [CapData {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                }; 2];
                check(
                    libc::syscall(libc::SYS_capset, &header, none.as_ptr()) as c_int,
                    "capset",
                    None,
                )?;
                check(
                    libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
                    "no_new_privs",
                    None,
                )?;
                // No namespaces from here on (the jail's own are made).
                let fprog = libc::sock_fprog {
                    len: self.filter.len() as libc::c_ushort,
                    filter: self.filter.as_ptr() as *mut libc::sock_filter,
                };
                check(
                    libc::syscall(
                        libc::SYS_seccomp,
                        libc::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
                        0,
                        &fprog as *const libc::sock_fprog,
                    ) as c_int,
                    "seccomp",
                    None,
                )?;
                if libc::getuid() == 0
                    || libc::geteuid() == 0
                    || libc::getgid() == 0
                    || libc::getegid() == 0
                {
                    let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
                    return Err(report("still root", None, eperm));
                }
                // Inherited descriptors beyond stdio close on exec (std's own error pipe
                // is close-on-exec already and must stay open until then).
                if libc::syscall(
                    libc::SYS_close_range,
                    3 as libc::c_uint,
                    libc::c_uint::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
                {
                    for fd in 3..self.max_fd {
                        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn destinations_must_be_absolute_and_normalized() {
        let s = Path::new("/run/jail");
        assert_eq!(
            under(s, Path::new("/var/lib/orbd/orbs/x")).unwrap(),
            Path::new("/run/jail/var/lib/orbd/orbs/x")
        );
        // Nothing goes over the jail's root either.
        for bad in ["var/lib", "/var/../etc", "/", "/."] {
            assert!(under(s, Path::new(bad)).is_err(), "{bad}");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;

    fn jail(staging: &Path, binds: Vec<Bind>) -> Jail {
        Jail {
            uid: 1_300_000_000,
            gid: 1_300_000_000,
            groups: vec![],
            staging: staging.to_owned(),
            binds,
            symlinks: vec![],
            new_netns: false,
        }
    }

    #[test]
    fn prepare_refuses_root_missing_sources_and_bad_staging() {
        let dir = tempfile::tempdir().unwrap();
        let ok = jail(dir.path(), vec![Bind::at(dir.path(), Access::Write)]);
        ok.prepare().unwrap();
        let mut root = ok.clone();
        root.uid = 0;
        assert!(root.prepare().is_err());
        let mut minus1 = ok.clone();
        minus1.groups = vec![u32::MAX];
        assert!(minus1.prepare().is_err());
        let missing = jail(
            dir.path(),
            vec![Bind::at(dir.path().join("missing"), Access::Read)],
        );
        let e = missing.prepare().err().unwrap().to_string();
        assert!(e.contains("missing"), "{e}");
        let staging = jail(&dir.path().join("nope"), vec![]);
        assert!(staging.prepare().is_err());
        let over_root = jail(
            dir.path(),
            vec![Bind {
                src: dir.path().to_owned(),
                dst: "/".into(),
                access: Access::Write,
            }],
        );
        assert!(over_root.prepare().is_err(), "a bind over the jail's root");
    }

    /// The real thing, as root (skipped otherwise unless `ORBD_TEST_JAIL=1` requires
    /// it), entered both ways: by pivot_root (where seccomp refuses it, e.g. Docker's
    /// default profile, this takes the fallback too) and by the move-and-chroot fallback.
    /// The program runs as the jail's uid with no capabilities, sees only what is bound
    /// (read-only where asked), and an inherited descriptor is closed.
    #[test]
    fn a_jailed_program_sees_only_its_binds() {
        for pivot in [true, false] {
            jailed_program_sees_only_its_binds(pivot);
        }
    }

    /// Run in a jail by [`a_jailed_program_creates_no_namespaces`] (ignored otherwise):
    /// no user namespace, no `setns` (EPERM, where unfiltered `setns(-1)` is EBADF),
    /// `clone3` ENOSYS, and threads still start (libc falls back to `clone`).
    #[test]
    #[ignore = "run in a jail by a_jailed_program_creates_no_namespaces"]
    fn ns_probe() {
        use nix::libc;
        // SAFETY: raw syscalls with harmless or invalid arguments.
        unsafe {
            let errno = || *libc::__errno_location();
            let unshare = (libc::unshare(libc::CLONE_NEWUSER), errno());
            assert_eq!(unshare, (-1, libc::EPERM), "unshare(CLONE_NEWUSER)");
            let setns = (libc::setns(-1, 0), errno());
            assert_eq!(setns, (-1, libc::EPERM), "setns");
            let clone3 = (libc::syscall(libc::SYS_clone3, 0usize, 0usize), errno());
            assert_eq!(clone3, (-1, libc::ENOSYS), "clone3");
        }
        std::thread::spawn(|| ()).join().unwrap();
        println!("ns-probe ok");
    }

    /// As root (skipped otherwise unless `ORBD_TEST_JAIL=1` requires it): a program in a
    /// jail cannot create namespaces (this test binary, run there as [`ns_probe`]).
    #[test]
    fn a_jailed_program_creates_no_namespaces() {
        if !nix::unistd::geteuid().is_root() {
            assert!(
                std::env::var("ORBD_TEST_JAIL").is_err(),
                "ORBD_TEST_JAIL is set but the test does not run as root"
            );
            eprintln!("skipped: needs root");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut j = jail(
            &staging,
            vec![
                Bind::at("/usr", Access::Exec),
                Bind::at(&exe, Access::Exec),
                Bind::at("/dev/null", Access::Device),
            ],
        );
        for l in ["lib", "lib64", "bin"] {
            let p = Path::new("/").join(l);
            match std::fs::read_link(&p) {
                Ok(t) => j.symlinks.push((p, t)),
                Err(_) if p.is_dir() => j.binds.push(Bind::at(p, Access::Exec)),
                Err(_) => {}
            }
        }
        let out = command(&j, &exe)
            .unwrap()
            .args([
                "--ignored",
                "--exact",
                "jail::linux_tests::ns_probe",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("ns-probe ok"),
            "{}\n{stdout}\n{stderr}",
            out.status
        );
    }

    fn jailed_program_sees_only_its_binds(pivot: bool) {
        if !nix::unistd::geteuid().is_root() {
            assert!(
                std::env::var("ORBD_TEST_JAIL").is_err(),
                "ORBD_TEST_JAIL is set but the test does not run as root"
            );
            eprintln!("skipped: needs root");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        let rw = dir.path().join("rw");
        let ro = dir.path().join("ro");
        for d in [&staging, &rw, &ro] {
            std::fs::create_dir(d).unwrap();
        }
        std::fs::write(ro.join("data"), "x").unwrap();
        std::fs::write(dir.path().join("secret"), "s").unwrap();
        std::os::unix::fs::chown(&rw, Some(1_300_000_000), Some(1_300_000_000)).unwrap();
        let mut j = jail(
            &staging,
            vec![
                Bind::at("/usr", Access::Exec),
                Bind::at(&rw, Access::Write),
                Bind::at(&ro, Access::Read),
                Bind::at("/dev/null", Access::Device),
            ],
        );
        for l in ["lib", "lib64", "bin"] {
            let p = Path::new("/").join(l);
            match std::fs::read_link(&p) {
                Ok(t) => j.symlinks.push((p, t)),
                Err(_) if p.is_dir() => j.binds.push(Bind::at(p, Access::Exec)),
                Err(_) => {}
            }
        }
        // Not close-on-exec: the jail must close it anyway.
        let leaked = std::fs::File::open(dir.path().join("secret")).unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&leaked);
        // SAFETY: clears FD_CLOEXEC on a descriptor this test owns.
        unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) };
        let script = format!(
            "id -u; id -g; grep -E '^CapEff' /proc/self/status 2>/dev/null || echo no-proc; \
             cat {ro}/data; echo; echo w > {rw}/f && echo wrote; \
             (echo w > {ro}/f) 2>/dev/null || echo ro-denied; \
             [ -e {secret} ] && echo secret-visible || echo secret-hidden; \
             (: <&{fd}) 2>/dev/null && echo leaked || echo closed; \
             echo > /dev/null && echo devnull",
            ro = ro.display(),
            rw = rw.display(),
            secret = dir.path().join("secret").display(),
        );
        let out = command_with(j.prepare_with(pivot).unwrap(), Path::new("/usr/bin/bash"))
            .unwrap()
            .args(["-c", &script])
            .output()
            .unwrap();
        drop(leaked);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stdout}\n{stderr}");
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(
            lines,
            [
                "1300000000",
                "1300000000",
                "no-proc",
                "x",
                "wrote",
                "ro-denied",
                "secret-hidden",
                "closed",
                "devnull"
            ],
            "pivot_root first: {pivot}; {stderr}"
        );
        assert!(rw.join("f").exists());
        assert!(!ro.join("f").exists());
        // Failure is reported, not ignored: a missing uid mapping or bad bind fails.
        let mut broken = j.clone();
        broken.binds.push(Bind {
            src: "/usr".into(),
            dst: dir.path().join("ro/data/x"),
            access: Access::Read,
        });
        let out = run(&broken, Path::new("/bin/true"), &[]);
        assert!(
            out.as_ref().is_err() || !out.as_ref().unwrap().status.success(),
            "{out:?}"
        );
    }
}
