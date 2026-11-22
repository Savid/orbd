//! Runs the image pipeline's tools over untrusted image content without real root
//! (Linux agents without a builder image).
//!
//! Each tool runs as root of its own user namespace, whose ids 0..65535 are the host's
//! `base..base+65535` (`ORBD_IMAGE_SANDBOX_UID_BASE`, default
//! [`DEFAULT_IMAGE_SANDBOX_UID_BASE`]; unused on the host), so ownership, modes, xattrs
//! and file capabilities come out as with real root while the tool holds no privilege
//! over anything else on the host. Its other namespaces are new too:
//!
//! * mount: the root is an empty read-only tmpfs holding only the host's `/usr` and
//!   `/lib*` (and the `/bin`, `/sbin` symlinks), `/etc/ld.so.cache`,
//!   `/etc/mke2fs.conf`, `/dev/{null,zero,full,random,urandom}` and the paths the step
//!   names, at their host paths; all nosuid, read-only but for the device nodes and the
//!   step's writable paths. No `/proc`, `/sys`, `/tmp` or other host state. The host's
//!   root is detached (pivot_root), or, where seccomp refuses pivot_root (Docker's
//!   default profile), left unreachable below a chroot;
//! * PID: the tool is PID 1, so when it exits (or the agent dies, or the build is
//!   cancelled) everything it started dies with it;
//! * network (loopback only), IPC, UTS and cgroup.
//!
//! It keeps only the capabilities that handling other users' files needs (CHOWN,
//! DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER, FSETID, SETFCAP; within its user namespace,
//! none on the host), with `no_new_privs`, no supplementary groups and a clean
//! environment.
//!
//! Without `/proc`, umoci does not notice the user namespace and keeps real-root
//! semantics: what a user namespace cannot reproduce fails the unpack instead of being
//! faked. That is device nodes (mknod needs host root; umoci would write empty files
//! instead), xattrs only host root may set (`trusted.*`, `security.*` other than
//! `security.capability`) and owners above 65535. File capabilities are stored as
//! namespaced (v3) capabilities on the staging filesystem and read back by mkfs.ext4,
//! inside the same namespace, as the ordinary v2 ones root's pipeline writes.
//!
//! The agent needs root (CAP_SYS_ADMIN, CAP_SETUID, CAP_SETGID, CAP_CHOWN) and mounts no
//! LSM denies; [`Sandbox::run`] fails with what is missing otherwise.

#[cfg(doc)]
use crate::config::agent::DEFAULT_IMAGE_SANDBOX_UID_BASE;
use std::ffi::OsStr;
use std::path::Path;

/// One path the tool may use, at the same path inside the sandbox.
// Read by the Linux sandbox only (macOS builds in the builder container).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct Bind<'a> {
    pub path: &'a Path,
    pub writable: bool,
}

pub fn ro(path: &Path) -> Bind<'_> {
    Bind {
        path,
        writable: false,
    }
}

pub fn rw(path: &Path) -> Bind<'_> {
    Bind {
        path,
        writable: true,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sandbox {
    uid_base: u32,
}

impl Sandbox {
    pub fn new(uid_base: u32) -> Self {
        Self { uid_base }
    }

    /// The host uid (and gid) of `id` inside the sandbox.
    pub fn host_id(&self, id: u32) -> u32 {
        self.uid_base + id
    }

    /// Runs `program` with `args` in a fresh sandbox that sees `binds`; returns its
    /// stdout, or fails with its stderr's tail (or what kept the sandbox from starting).
    pub async fn run(
        &self,
        program: &Path,
        args: &[&OsStr],
        binds: &[Bind<'_>],
    ) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        return linux::run(self.uid_base, program, args, binds).await;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (program, args, binds);
            Err("the image sandbox needs Linux".into())
        }
    }
}

/// What to do when the sandbox cannot start.
pub const HINT: &str = "the image sandbox needs a root agent with CAP_SYS_ADMIN, CAP_SETUID, \
     CAP_SETGID and CAP_CHOWN whose mounts no LSM denies (in Docker: --cap-add SYS_ADMIN \
     --security-opt apparmor=unconfined, or --privileged); ORBD_IMAGE_SANDBOX=off runs the \
     image tools as real root instead (unsafe)";

#[cfg(target_os = "linux")]
mod linux {
    use super::{Bind, HINT};
    use crate::config::agent::IMAGE_SANDBOX_IDS as IDS;
    use nix::libc::{self, c_char, c_int, c_ulong, c_void};
    use std::ffi::{CStr, CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path, PathBuf};
    use tokio::io::AsyncReadExt;

    /// Host directories every tool gets read-only (symlinks, e.g. merged-/usr `/bin`, are
    /// recreated instead).
    const SYSTEM_DIRS: [&str; 7] = [
        "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
    ];
    /// Where Nix (NixOS) installs tools, each linked against libraries in other store paths.
    const NIX_STORE: &str = "/nix/store";
    /// Host files tools get read-only when present: the dynamic linker's cache, and
    /// mke2fs's defaults (the same filesystem features as root's pipeline).
    const SYSTEM_FILES: [&str; 2] = ["/etc/ld.so.cache", "/etc/mke2fs.conf"];
    const DEVICES: [&str; 5] = [
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
    ];
    const ENV: [&CStr; 4] = [
        c"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        c"LC_ALL=C",
        // No /proc/mounts: mkfs.ext4 then knows its target is not mounted.
        c"EXT2FS_NO_MTAB_OK=1",
        c"HOME=/",
    ];
    /// Capabilities (within the user namespace) the tools keep: ownership, modes, times
    /// and xattrs of files they do not own, and file capabilities.
    const KEEP_CAPS: u64 = 1 << 0 // CAP_CHOWN
        | 1 << 1 // CAP_DAC_OVERRIDE
        | 1 << 2 // CAP_DAC_READ_SEARCH
        | 1 << 3 // CAP_FOWNER
        | 1 << 4 // CAP_FSETID
        | 1 << 31; // CAP_SETFCAP
    /// Output kept per stream (stdout's head, stderr's tail).
    const OUTPUT_LIMIT: usize = 1 << 20;
    const STACK_SIZE: usize = 256 * 1024;

    /// A node the child creates on its root tmpfs (mount points and symlinks).
    enum Node {
        Dir(CString),
        File(CString),
        Symlink { target: CString, path: CString },
    }

    struct MountSpec {
        /// The host path. The child opens it before giving up host root's identity (a
        /// bind source must be in its own mount namespace) and checks it is the file the
        /// parent inspected.
        source: CString,
        nofollow: bool,
        dev: u64,
        ino: u64,
        /// The child's O_PATH descriptor of `source`.
        fd: c_int,
        /// Relative to the sandbox root.
        target: CString,
        /// MS_REMOUNT | MS_BIND | the flags it gets.
        remount: c_ulong,
        display: PathBuf,
    }

    /// Everything the child needs, prepared before clone: the child (a copy of one
    /// thread of a multithreaded process) only makes system calls.
    struct Plan {
        nodes: Vec<Node>,
        mounts: Vec<MountSpec>,
        program: CString,
        _argv: Vec<CString>,
        argv: Vec<*const c_char>,
        envp: Vec<*const c_char>,
        last_cap: u32,
        sync_r: RawFd,
        report_w: RawFd,
        stdin: RawFd,
        stdout: RawFd,
        stderr: RawFd,
        /// Descriptors the child uses; closed in the parent once the child has its copy.
        _child_fds: Vec<OwnedFd>,
    }

    // SAFETY: the raw pointers point into `_argv` and `ENV`, owned or static.
    unsafe impl Send for Plan {}

    /// Setup steps, reported by the child as (step, index, errno).
    #[derive(Clone, Copy)]
    #[repr(u8)]
    enum Step {
        Sync,
        OpenSource,
        Setresgid,
        Setgroups,
        Setresuid,
        Pdeathsig,
        Private,
        OpenOldRoot,
        Tmpfs,
        ChdirNewRoot,
        Node,
        Bind,
        Remount,
        PivotRoot,
        DetachOldRoot,
        RootReadOnly,
        DropBounding,
        ClearAmbient,
        Capset,
        NoNewPrivs,
        Signals,
        Stdio,
        CloseFds,
        Exec,
    }

    impl Step {
        const ALL: [Step; 24] = [
            Step::Sync,
            Step::OpenSource,
            Step::Setresgid,
            Step::Setgroups,
            Step::Setresuid,
            Step::Pdeathsig,
            Step::Private,
            Step::OpenOldRoot,
            Step::Tmpfs,
            Step::ChdirNewRoot,
            Step::Node,
            Step::Bind,
            Step::Remount,
            Step::PivotRoot,
            Step::DetachOldRoot,
            Step::RootReadOnly,
            Step::DropBounding,
            Step::ClearAmbient,
            Step::Capset,
            Step::NoNewPrivs,
            Step::Signals,
            Step::Stdio,
            Step::CloseFds,
            Step::Exec,
        ];

        fn describe(self, index: u16, plan: &PlanInfo) -> String {
            let path = |paths: &[PathBuf]| {
                paths
                    .get(usize::from(index))
                    .map_or("?".into(), |p| p.display().to_string())
            };
            match self {
                Step::Sync => "waiting for the id maps".into(),
                Step::OpenSource => format!("opening {}", path(&plan.mounts)),
                Step::Setresgid => "becoming gid 0".into(),
                Step::Setgroups => "dropping supplementary groups".into(),
                Step::Setresuid => "becoming uid 0".into(),
                Step::Pdeathsig => "setting the parent-death signal".into(),
                Step::Private => "making mounts private".into(),
                Step::OpenOldRoot => "opening /".into(),
                Step::Tmpfs => "mounting the sandbox root (a tmpfs on /tmp)".into(),
                Step::ChdirNewRoot => "entering the sandbox root".into(),
                Step::Node => format!("creating {} in the sandbox root", path(&plan.nodes)),
                Step::Bind => format!("bind-mounting {}", path(&plan.mounts)),
                Step::Remount => format!("restricting the mount of {}", path(&plan.mounts)),
                Step::PivotRoot => "entering the sandbox root (pivot_root, else chroot)".into(),
                Step::DetachOldRoot => "detaching the host's root".into(),
                Step::RootReadOnly => "making the sandbox root read-only".into(),
                Step::DropBounding => format!("dropping capability {index}"),
                Step::ClearAmbient => "clearing ambient capabilities".into(),
                Step::Capset => "setting capabilities".into(),
                Step::NoNewPrivs => "setting no_new_privs".into(),
                Step::Signals => "resetting signals".into(),
                Step::Stdio => "setting up stdio".into(),
                Step::CloseFds => "closing inherited descriptors".into(),
                Step::Exec => format!("executing {}", plan.program.display()),
            }
        }
    }

    /// What the parent keeps to explain a failed setup.
    struct PlanInfo {
        nodes: Vec<PathBuf>,
        mounts: Vec<PathBuf>,
        program: PathBuf,
    }

    fn cstr(p: &Path) -> Result<CString, String> {
        CString::new(p.as_os_str().as_bytes()).map_err(|_| format!("{}: NUL in path", p.display()))
    }

    /// `path` relative to `/`, as a C string; it must be absolute and normal.
    fn relative(path: &Path) -> Result<CString, String> {
        let mut out = PathBuf::new();
        for c in path.components() {
            match c {
                Component::RootDir => {}
                Component::Normal(n) => out.push(n),
                _ => return Err(format!("{}: not a normal absolute path", path.display())),
            }
        }
        if out.as_os_str().is_empty() || !path.is_absolute() {
            return Err(format!("{}: not a normal absolute path", path.display()));
        }
        cstr(&out)
    }

    /// The path a bare program name resolves to on PATH (as `execvp` would).
    fn resolve(program: &Path) -> Result<PathBuf, String> {
        use std::os::unix::fs::PermissionsExt;
        if program.components().count() > 1 || program.is_absolute() {
            return std::path::absolute(program).map_err(|e| format!("{}: {e}", program.display()));
        }
        let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
        std::env::split_paths(&path)
            .filter(|d| d.is_absolute())
            .map(|d| d.join(program))
            .find(|p| {
                std::fs::metadata(p)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
            .ok_or_else(|| format!("{}: not found on PATH", program.display()))
    }

    fn open_path(path: &Path, nofollow: bool) -> Result<OwnedFd, String> {
        let c = cstr(path)?;
        let mut flags = libc::O_PATH | libc::O_CLOEXEC;
        if nofollow {
            flags |= libc::O_NOFOLLOW;
        }
        // SAFETY: plain open(2) of a NUL-terminated path.
        let fd = unsafe { libc::open(c.as_ptr(), flags) };
        if fd < 0 {
            return Err(format!(
                "{}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: a fresh descriptor we own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn pipe() -> Result<(OwnedFd, OwnedFd), String> {
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))
    }

    struct PlanBuilder {
        nodes: Vec<Node>,
        node_paths: Vec<PathBuf>,
        created: std::collections::HashSet<PathBuf>,
        mounts: Vec<MountSpec>,
    }

    impl PlanBuilder {
        /// Creates `path`'s parents (and `path` itself as a directory or file) on the
        /// sandbox root.
        fn mount_point(&mut self, path: &Path, dir: bool) -> Result<(), String> {
            let mut so_far = PathBuf::from("/");
            let parts: Vec<_> = path.components().skip(1).collect();
            for (i, part) in parts.iter().enumerate() {
                so_far.push(part);
                if !self.created.insert(so_far.clone()) {
                    continue;
                }
                let rel = relative(&so_far)?;
                let leaf_file = i + 1 == parts.len() && !dir;
                self.nodes.push(if leaf_file {
                    Node::File(rel)
                } else {
                    Node::Dir(rel)
                });
                self.node_paths.push(so_far.clone());
            }
            Ok(())
        }

        fn symlink(&mut self, path: &Path, target: &Path) -> Result<(), String> {
            if self.created.insert(path.to_owned()) {
                self.nodes.push(Node::Symlink {
                    target: cstr(target)?,
                    path: relative(path)?,
                });
                self.node_paths.push(path.to_owned());
            }
            Ok(())
        }

        /// Bind-mounts host `path` at the same path. Device nodes keep working (no
        /// nodev); everything is nosuid; work paths are noexec.
        fn bind(&mut self, path: &Path, writable: bool, kind: BindKind) -> Result<(), String> {
            // Work paths are never followed through a symlink: the sandbox must get the
            // directory orbd created, not wherever a link points.
            let nofollow = kind == BindKind::Work;
            let fd = open_path(path, nofollow)?;
            let st = nix::sys::stat::fstat(&fd).map_err(|e| format!("{}: {e}", path.display()))?;
            let fmt = nix::sys::stat::SFlag::from_bits_truncate(st.st_mode)
                & nix::sys::stat::SFlag::S_IFMT;
            let dir = fmt == nix::sys::stat::SFlag::S_IFDIR;
            let ok = match kind {
                BindKind::Device => fmt == nix::sys::stat::SFlag::S_IFCHR,
                _ => dir || fmt == nix::sys::stat::SFlag::S_IFREG,
            };
            if !ok {
                return Err(format!("{}: unexpected file type", path.display()));
            }
            // A remount may add restrictions but never lift those of the source mount
            // (they are locked in a user namespace).
            let vfs =
                nix::sys::statvfs::fstatvfs(&fd).map_err(|e| format!("{}: {e}", path.display()))?;
            let src = vfs.flags();
            use nix::sys::statvfs::FsFlags;
            let mut remount = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID;
            if !writable || src.contains(FsFlags::ST_RDONLY) {
                remount |= libc::MS_RDONLY;
            }
            if kind != BindKind::Device || src.contains(FsFlags::ST_NODEV) {
                remount |= libc::MS_NODEV;
            }
            if kind != BindKind::System || src.contains(FsFlags::ST_NOEXEC) {
                remount |= libc::MS_NOEXEC;
            }
            self.mount_point(path, dir)?;
            self.mounts.push(MountSpec {
                source: cstr(path)?,
                nofollow,
                dev: st.st_dev,
                ino: st.st_ino,
                fd: -1,
                target: relative(path)?,
                remount,
                display: path.to_owned(),
            });
            Ok(())
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum BindKind {
        /// Host system files (executable, read-only).
        System,
        Device,
        /// Paths of the build (never executable).
        Work,
    }

    fn plan(
        program: &Path,
        args: &[&OsStr],
        binds: &[Bind<'_>],
    ) -> Result<(Plan, PlanInfo, PlanFds), String> {
        let resolved = resolve(program)?;
        let mut b = PlanBuilder {
            nodes: Vec::new(),
            node_paths: Vec::new(),
            created: Default::default(),
            mounts: Vec::new(),
        };
        let mut visible: Vec<&Path> = Vec::new();
        for d in SYSTEM_DIRS.map(Path::new) {
            match std::fs::symlink_metadata(d) {
                Ok(m) if m.file_type().is_symlink() => {
                    let target =
                        std::fs::read_link(d).map_err(|e| format!("{}: {e}", d.display()))?;
                    b.symlink(d, &target)?;
                    visible.push(d);
                }
                Ok(m) if m.is_dir() => {
                    b.bind(d, false, BindKind::System)?;
                    visible.push(d);
                }
                _ => {}
            }
        }
        for f in SYSTEM_FILES.map(Path::new) {
            if f.exists() {
                b.bind(f, false, BindKind::System)?;
            }
        }
        for d in DEVICES.map(Path::new) {
            if std::fs::metadata(d).is_ok() {
                b.bind(d, true, BindKind::Device)?;
            }
        }
        // A tool outside the system directories gets its own file (not its libraries),
        // except a Nix store tool: its libraries are other store paths, so the whole
        // (read-only, world-readable) store.
        if resolved.starts_with(NIX_STORE) {
            b.bind(Path::new(NIX_STORE), false, BindKind::System)?;
        } else if !visible.iter().any(|d| resolved.starts_with(d)) {
            b.bind(&resolved, false, BindKind::System)?;
        }
        let mut binds: Vec<&Bind<'_>> = binds.iter().collect();
        binds.sort_by_key(|b| b.path.components().count());
        for bind in binds {
            b.bind(bind.path, bind.writable, BindKind::Work)?;
        }

        let argv0 = program.as_os_str();
        let argv: Vec<CString> = std::iter::once(argv0)
            .chain(args.iter().copied())
            .map(|a| CString::new(a.as_bytes()).map_err(|_| "NUL in an argument".to_owned()))
            .collect::<Result<_, _>>()?;
        let mut argv_ptrs: Vec<*const c_char> = argv.iter().map(|a| a.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let mut envp: Vec<*const c_char> = ENV.iter().map(|e| e.as_ptr()).collect();
        envp.push(std::ptr::null());

        let (sync_r, sync_w) = pipe()?;
        let (report_r, report_w) = pipe()?;
        let (stdout_r, stdout_w) = pipe()?;
        let (stderr_r, stderr_w) = pipe()?;
        let stdin = std::fs::File::open("/dev/null").map_err(|e| format!("/dev/null: {e}"))?;
        let stdin = OwnedFd::from(stdin);

        let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(40)
            .min(63);
        let info = PlanInfo {
            nodes: b.node_paths,
            mounts: b.mounts.iter().map(|m| m.display.clone()).collect(),
            program: resolved.clone(),
        };
        let plan = Plan {
            nodes: b.nodes,
            mounts: b.mounts,
            program: cstr(&resolved)?,
            _argv: argv,
            argv: argv_ptrs,
            envp,
            last_cap,
            sync_r: sync_r.as_raw_fd(),
            report_w: report_w.as_raw_fd(),
            stdin: stdin.as_raw_fd(),
            stdout: stdout_w.as_raw_fd(),
            stderr: stderr_w.as_raw_fd(),
            _child_fds: vec![sync_r, report_w, stdin, stdout_w, stderr_w],
        };
        Ok((
            plan,
            info,
            PlanFds {
                sync_w,
                report_r,
                stdout_r,
                stderr_r,
            },
        ))
    }

    /// The parent's ends of the child's pipes.
    struct PlanFds {
        sync_w: OwnedFd,
        report_r: OwnedFd,
        stdout_r: OwnedFd,
        stderr_r: OwnedFd,
    }

    /// Kills the sandbox (its PID 1, and so everything in it) unless it has finished.
    struct KillOnDrop(Option<OwnedFd>);

    impl KillOnDrop {
        fn done(mut self) {
            self.0 = None;
        }
    }

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            if let Some(pidfd) = &self.0 {
                // SAFETY: pidfd_send_signal on a pidfd we own (no pid reuse races).
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<c_void>(),
                        0,
                    );
                }
            }
        }
    }

    pub async fn run(
        uid_base: u32,
        program: &Path,
        args: &[&OsStr],
        binds: &[Bind<'_>],
    ) -> Result<String, String> {
        let (plan, info, fds) =
            plan(program, args, binds).map_err(|e| format!("image sandbox: {e}"))?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        // The thread that clones the child waits for it: the child's parent-death signal
        // fires when that thread ends, i.e. only if the agent dies.
        let wait =
            tokio::task::spawn_blocking(move || spawn_and_wait(plan, uid_base, fds.sync_w, tx));
        let report = tokio::net::unix::pipe::Receiver::from_owned_fd(fds.report_r);
        let stdout = tokio::net::unix::pipe::Receiver::from_owned_fd(fds.stdout_r);
        let stderr = tokio::net::unix::pipe::Receiver::from_owned_fd(fds.stderr_r);
        let (report, stdout, stderr) = match (report, stdout, stderr) {
            (Ok(a), Ok(b), Ok(c)) => (a, b, c),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                return Err(format!("image sandbox: pipe: {e}"));
            }
        };
        let kill = match rx.await {
            Ok(Ok(pidfd)) => KillOnDrop(Some(pidfd)),
            Ok(Err(e)) => return Err(format!("image sandbox: {e} ({HINT})")),
            Err(_) => {
                let e = match wait.await {
                    Ok(Err(e)) => e,
                    _ => "clone failed".into(),
                };
                return Err(format!("image sandbox: {e} ({HINT})"));
            }
        };
        let (report, out, err, status) = tokio::join!(
            read_capped(report, 64, false),
            read_capped(stdout, OUTPUT_LIMIT, false),
            read_capped(stderr, OUTPUT_LIMIT, true),
            wait
        );
        kill.done();
        let status = status
            .map_err(|e| e.to_string())
            .and_then(|s| s)
            .map_err(|e| format!("image sandbox: {e}"))?;
        if report.len() >= 8 {
            let step = Step::ALL.get(usize::from(report[0])).copied();
            let index = u16::from_le_bytes([report[2], report[3]]);
            let errno = i32::from_le_bytes([report[4], report[5], report[6], report[7]]);
            let what = step.map_or("setting up".into(), |s| s.describe(index, &info));
            let err = std::io::Error::from_raw_os_error(errno);
            let hint = match step {
                Some(Step::Exec) => String::new(),
                _ => format!(" ({HINT})"),
            };
            return Err(format!("image sandbox: {what}: {err}{hint}"));
        }
        if !status.success() {
            let err = String::from_utf8_lossy(&err);
            let tail: Vec<&str> = err.lines().rev().take(10).collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            return Err(format!(
                "{} {} failed in the image sandbox ({status}): {}",
                program.display(),
                args.first()
                    .map_or(String::new(), |a| a.to_string_lossy().into_owned()),
                tail.join("\n")
            ));
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Reads a stream to its end, keeping at most `limit` bytes: the head, or the tail.
    async fn read_capped(
        mut rx: tokio::net::unix::pipe::Receiver,
        limit: usize,
        tail: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) if tail => {
                    out.extend_from_slice(&buf[..n]);
                    if out.len() > 2 * limit {
                        out.drain(..out.len() - limit);
                    }
                }
                Ok(n) => {
                    let room = limit.saturating_sub(out.len());
                    out.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        if tail && out.len() > limit {
            out.drain(..out.len() - limit);
        }
        out
    }

    /// Exit status of the sandbox's PID 1.
    pub struct Status(nix::sys::wait::WaitStatus);

    impl Status {
        fn success(&self) -> bool {
            matches!(self.0, nix::sys::wait::WaitStatus::Exited(_, 0))
        }
    }

    impl std::fmt::Display for Status {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            use nix::sys::wait::WaitStatus as W;
            match self.0 {
                W::Exited(_, code) => write!(f, "exit status: {code}"),
                W::Signaled(_, sig, _) => write!(f, "signal: {sig}"),
                other => write!(f, "{other:?}"),
            }
        }
    }

    /// Clones the child into its namespaces, maps its ids, lets it go and waits for it.
    /// Runs on a blocking thread.
    fn spawn_and_wait(
        plan: Plan,
        uid_base: u32,
        sync_w: OwnedFd,
        tx: tokio::sync::oneshot::Sender<Result<OwnedFd, String>>,
    ) -> Result<Status, String> {
        let mut stack = vec![0u8; STACK_SIZE];
        // SAFETY: in bounds; the stack grows down from its 16-byte aligned top.
        let top = unsafe { stack.as_mut_ptr().add(STACK_SIZE) };
        let top = (top as usize & !15) as *mut c_void;
        let flags = libc::CLONE_NEWUSER
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWCGROUP
            | libc::CLONE_PIDFD
            | libc::SIGCHLD;
        let mut pidfd: c_int = -1;
        // SAFETY: `child` only makes system calls on `plan`, which outlives the call (the
        // child has its own copy of this address space).
        let mut plan = plan;
        let pid = unsafe {
            libc::clone(
                child,
                top,
                flags,
                &mut plan as *mut Plan as *mut c_void,
                &mut pidfd as *mut c_int,
            )
        };
        if pid < 0 {
            let e = std::io::Error::last_os_error();
            let _ = tx.send(Err(format!("creating namespaces: {e}")));
            return Err(format!("creating namespaces: {e}"));
        }
        drop(stack);
        // SAFETY: CLONE_PIDFD stored a descriptor we now own.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let kill = || {
            // SAFETY: as in KillOnDrop.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<c_void>(),
                    0,
                );
            }
        };
        let reap = || {
            nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None)
                .map(Status)
                .map_err(|e| format!("waiting for the sandbox: {e}"))
        };
        // The child has its copies now.
        drop(plan);
        let sent = match pidfd.try_clone() {
            Ok(dup) => tx.send(Ok(dup)).is_ok(),
            Err(e) => {
                let _ = tx.send(Err(format!("pidfd: {e}")));
                false
            }
        };
        if !sent {
            // The caller is gone (cancelled) or out of descriptors: do not run the tool.
            kill();
            let _ = reap();
            return Err("cancelled".into());
        }
        let map = format!("0 {uid_base} {IDS}\n");
        for file in ["uid_map", "gid_map"] {
            if let Err(e) = std::fs::write(format!("/proc/{pid}/{file}"), &map) {
                kill();
                let _ = reap();
                return Err(format!("writing {file} ({map:?}): {e} ({HINT})"));
            }
        }
        if nix::unistd::write(&sync_w, b"x").is_err() {
            kill();
        }
        drop(sync_w);
        reap()
    }

    /// The cloned child: PID 1 of its namespaces. Only system calls from here on (the
    /// parent is multithreaded, and glibc's wrappers that sync ids across threads, such as
    /// setresuid, would wait for threads this process does not have).
    extern "C" fn child(arg: *mut c_void) -> c_int {
        // SAFETY: `arg` is the parent's `Plan`, copied with the address space (this
        // process's own copy).
        let p = unsafe { &mut *(arg as *mut Plan) };
        // SAFETY: see `setup`.
        let report_w = p.report_w;
        match unsafe { setup(p) } {
            Ok(never) => match never {},
            Err((step, index)) => {
                // SAFETY: errno of this thread, then write(2) and _exit(2).
                unsafe {
                    let errno = *libc::__errno_location();
                    let i = index.to_le_bytes();
                    let e = errno.to_le_bytes();
                    let msg = [step as u8, 0, i[0], i[1], e[0], e[1], e[2], e[3]];
                    libc::write(report_w, msg.as_ptr().cast(), msg.len());
                    libc::_exit(127)
                }
            }
        }
    }

    enum Never {}

    /// `/proc/self/fd/<fd>` in `buf`, without allocating.
    fn fd_path(fd: c_int, buf: &mut [u8; 32]) -> *const c_char {
        const PREFIX: &[u8; 14] = b"/proc/self/fd/";
        buf[..PREFIX.len()].copy_from_slice(PREFIX);
        let mut digits = [0u8; 10];
        let (mut n, mut len) = (fd.unsigned_abs(), 0);
        while len < digits.len() {
            digits[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
            if n == 0 {
                break;
            }
        }
        for i in 0..len {
            buf[PREFIX.len() + i] = digits[len - 1 - i];
        }
        buf[PREFIX.len() + len] = 0;
        buf.as_ptr().cast()
    }

    /// # Safety
    /// Called only in the cloned child, with `p` valid.
    unsafe fn setup(p: &mut Plan) -> Result<Never, (Step, u16)> {
        let ok = |r: libc::c_long, step: Step| if r < 0 { Err((step, 0)) } else { Ok(()) };
        // SAFETY (whole function): system calls with valid NUL-terminated strings and
        // buffers from `p` or static.
        unsafe {
            // Wait until the parent has mapped our ids.
            let mut byte = 0u8;
            if libc::read(p.sync_r, (&mut byte as *mut u8).cast(), 1) != 1 {
                return Err((Step::Sync, 0));
            }
            // Still host root's uid here (unmapped, but it owns root's directories).
            for (i, m) in p.mounts.iter_mut().enumerate() {
                let mut flags = libc::O_PATH | libc::O_CLOEXEC;
                if m.nofollow {
                    flags |= libc::O_NOFOLLOW;
                }
                m.fd = libc::open(m.source.as_ptr(), flags);
                let mut st: libc::stat = std::mem::zeroed();
                if m.fd < 0 || libc::fstat(m.fd, &mut st) < 0 {
                    return Err((Step::OpenSource, i as u16));
                }
                if st.st_dev != m.dev || st.st_ino != m.ino {
                    *libc::__errno_location() = libc::ESTALE;
                    return Err((Step::OpenSource, i as u16));
                }
            }
            ok(libc::syscall(libc::SYS_setresgid, 0, 0, 0), Step::Setresgid)?;
            ok(
                libc::syscall(libc::SYS_setgroups, 0, std::ptr::null::<libc::gid_t>()),
                Step::Setgroups,
            )?;
            ok(libc::syscall(libc::SYS_setresuid, 0, 0, 0), Step::Setresuid)?;
            // After the id changes, which clear it; kept across exec.
            ok(
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0).into(),
                Step::Pdeathsig,
            )?;

            let null = std::ptr::null::<c_char>();
            ok(
                libc::mount(
                    null,
                    c"/".as_ptr(),
                    null,
                    libc::MS_REC | libc::MS_PRIVATE,
                    null.cast(),
                )
                .into(),
                Step::Private,
            )?;
            let old_root = libc::open(
                c"/".as_ptr(),
                libc::O_DIRECTORY | libc::O_PATH | libc::O_CLOEXEC,
            );
            ok(old_root.into(), Step::OpenOldRoot)?;
            ok(
                libc::mount(
                    c"tmpfs".as_ptr(),
                    c"/tmp".as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    c"mode=0755,size=64k,nr_inodes=4096".as_ptr().cast(),
                )
                .into(),
                Step::Tmpfs,
            )?;
            ok(libc::chdir(c"/tmp".as_ptr()).into(), Step::ChdirNewRoot)?;
            for (i, node) in p.nodes.iter().enumerate() {
                let r = match node {
                    Node::Dir(path) => libc::mkdir(path.as_ptr(), 0o755),
                    Node::File(path) => {
                        let fd = libc::open(
                            path.as_ptr(),
                            libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                            0o644,
                        );
                        if fd >= 0 {
                            libc::close(fd);
                        }
                        fd
                    }
                    Node::Symlink { target, path } => libc::symlink(target.as_ptr(), path.as_ptr()),
                };
                if r < 0 && *libc::__errno_location() != libc::EEXIST {
                    return Err((Step::Node, i as u16));
                }
            }
            let mut source = [0u8; 32];
            for (i, m) in p.mounts.iter().enumerate() {
                if libc::mount(
                    fd_path(m.fd, &mut source),
                    m.target.as_ptr(),
                    null,
                    libc::MS_BIND | libc::MS_REC,
                    null.cast(),
                ) < 0
                {
                    return Err((Step::Bind, i as u16));
                }
                libc::close(m.fd);
                if libc::mount(null, m.target.as_ptr(), null, m.remount, null.cast()) < 0 {
                    return Err((Step::Remount, i as u16));
                }
            }
            if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) == 0 {
                // The host's root is stacked on ours: detach it (and everything under it).
                ok(libc::fchdir(old_root).into(), Step::DetachOldRoot)?;
                ok(
                    libc::umount2(c".".as_ptr(), libc::MNT_DETACH).into(),
                    Step::DetachOldRoot,
                )?;
                ok(libc::chdir(c"/".as_ptr()).into(), Step::DetachOldRoot)?;
            } else {
                // Docker's default seccomp profile refuses pivot_root: move our root over
                // the host's and chroot into it, as runc does without pivot_root. The
                // host's mounts stay below, unreachable: the tool has no descriptor
                // there, no CAP_SYS_CHROOT and no CAP_SYS_ADMIN.
                ok(
                    libc::mount(
                        c".".as_ptr(),
                        c"/".as_ptr(),
                        null,
                        libc::MS_MOVE,
                        null.cast(),
                    )
                    .into(),
                    Step::PivotRoot,
                )?;
                ok(libc::chroot(c".".as_ptr()).into(), Step::PivotRoot)?;
                ok(libc::chdir(c"/".as_ptr()).into(), Step::PivotRoot)?;
            }
            libc::close(old_root);
            ok(
                libc::mount(
                    null,
                    c"/".as_ptr(),
                    null,
                    libc::MS_REMOUNT
                        | libc::MS_BIND
                        | libc::MS_RDONLY
                        | libc::MS_NOSUID
                        | libc::MS_NODEV
                        | libc::MS_NOEXEC,
                    null.cast(),
                )
                .into(),
                Step::RootReadOnly,
            )?;

            for cap in 0..=p.last_cap {
                if KEEP_CAPS & (1 << cap) == 0
                    && libc::prctl(libc::PR_CAPBSET_DROP, cap as c_ulong, 0, 0, 0) < 0
                    && *libc::__errno_location() != libc::EINVAL
                {
                    return Err((Step::DropBounding, cap as u16));
                }
            }
            ok(
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL as c_ulong,
                    0,
                    0,
                    0,
                )
                .into(),
                Step::ClearAmbient,
            )?;
            #[repr(C)]
            struct Header {
                version: u32,
                pid: c_int,
            }
            #[repr(C)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = Header {
                version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
                pid: 0,
            };
            let (lo, hi) = (KEEP_CAPS as u32, (KEEP_CAPS >> 32) as u32);
            let data = [
                Data {
                    effective: lo,
                    permitted: lo,
                    inheritable: 0,
                },
                Data {
                    effective: hi,
                    permitted: hi,
                    inheritable: 0,
                },
            ];
            ok(
                libc::syscall(libc::SYS_capset, &header, data.as_ptr()),
                Step::Capset,
            )?;
            ok(
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).into(),
                Step::NoNewPrivs,
            )?;

            // As std's Command does: default SIGPIPE (Rust ignores it), nothing blocked.
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            ok(
                libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()).into(),
                Step::Signals,
            )?;
            let mut dfl: libc::sigaction = std::mem::zeroed();
            dfl.sa_sigaction = libc::SIG_DFL;
            ok(
                libc::sigaction(libc::SIGPIPE, &dfl, std::ptr::null_mut()).into(),
                Step::Signals,
            )?;

            for (fd, to) in [(p.stdin, 0), (p.stdout, 1), (p.stderr, 2)] {
                let r = if fd == to {
                    libc::fcntl(fd, libc::F_SETFD, 0)
                } else {
                    libc::dup2(fd, to)
                };
                ok(r.into(), Step::Stdio)?;
            }
            // Nothing else of the agent's reaches the tool (the report pipe closes on exec).
            if libc::syscall(
                libc::SYS_close_range,
                3,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) < 0
            {
                for fd in 3..65_536 {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
            }
            libc::execve(p.program.as_ptr(), p.argv.as_ptr(), p.envp.as_ptr());
            Err((Step::Exec, 0))
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// The sandbox's view and privileges: ns root mapped to the base, only the binds,
    /// read-only root, no network, no new privileges, a reduced bounding set; writes in a
    /// writable bind land owned by the base on the host. Needs root and util-linux
    /// (`setpriv`) and iproute2 (`ip`), e.g. in orbd's container image.
    #[tokio::test]
    #[ignore = "needs root (CAP_SYS_ADMIN, CAP_SETUID, CAP_SETGID)"]
    async fn tools_run_as_root_of_their_own_namespaces() {
        let tmp = tempfile::tempdir_in("/var/tmp").unwrap();
        let work = tmp.path().join("work");
        let ro_dir = tmp.path().join("ro");
        std::fs::create_dir(&work).unwrap();
        std::fs::create_dir(&ro_dir).unwrap();
        let sandbox = Sandbox::new(crate::config::agent::DEFAULT_IMAGE_SANDBOX_UID_BASE);
        let base = sandbox.host_id(0);
        nix::unistd::chown(
            &work,
            Some(nix::unistd::Uid::from_raw(base)),
            Some(nix::unistd::Gid::from_raw(base)),
        )
        .unwrap();
        let sh = |script: String| {
            let (work, ro_dir) = (work.clone(), ro_dir.clone());
            async move {
                sandbox
                    .run(
                        Path::new("sh"),
                        &["-c".as_ref(), script.as_ref()],
                        &[rw(&work), ro(&ro_dir)],
                    )
                    .await
            }
        };
        let w = work.display();
        let out = sh(format!(
            "id -u; id -g; ls -A / | tr '\\n' ' '; echo; \
             touch {w}/made && chown 1000:1001 {w}/made && echo wrote; \
             touch {}/x 2>/dev/null || echo ro-bind; touch /x 2>/dev/null || echo ro-root; \
             ls /proc/self 2>/dev/null || echo no-proc; \
             ip -o link | cut -d: -f2 | tr -d ' \\n'; echo; setpriv -d",
            ro_dir.display()
        ))
        .await
        .unwrap();
        println!("{out}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(&lines[..2], ["0", "0"]);
        let top = tmp.path().components().nth(1).unwrap();
        let mut want = vec!["bin", "dev", "etc", "lib", "lib64", "sbin", "usr"];
        let top = top.as_os_str().to_str().unwrap();
        if !want.contains(&top) {
            want.push(top);
            want.sort();
        }
        let mut seen: Vec<&str> = lines[2].split_whitespace().collect();
        seen.sort();
        assert_eq!(seen, want, "only the system directories and the binds");
        assert_eq!(&lines[3..7], ["wrote", "ro-bind", "ro-root", "no-proc"]);
        assert_eq!(lines[7], "lo", "no network but loopback");
        assert!(out.contains("no_new_privs: 1"), "{out}");
        assert!(
            out.contains(
                "Capability bounding set: chown,dac_override,dac_read_search,fowner,fsetid,setfcap"
            ),
            "{out}"
        );
        assert!(out.contains("Supplementary groups: [none]"), "{out}");
        let made = std::fs::symlink_metadata(work.join("made")).unwrap();
        assert_eq!(
            (made.uid(), made.gid()),
            (sandbox.host_id(1000), sandbox.host_id(1001))
        );

        // A failing tool reports its stderr; a missing one, that it is missing.
        let err = sh("echo oops >&2; exit 3".into()).await.unwrap_err();
        assert!(
            err.contains("exit status: 3") && err.contains("oops"),
            "{err}"
        );
        let err = sandbox
            .run(Path::new("no-such-tool-orbd"), &[], &[])
            .await
            .unwrap_err();
        assert!(err.contains("not found on PATH"), "{err}");
        // An owner beyond the mapped ids cannot be set.
        let err = sh(format!("chown 70000 {w}/made")).await.unwrap_err();
        assert!(err.contains("Invalid argument"), "{err}");

        // A cancelled step (its future dropped) leaves nothing of the sandbox running.
        let alive = || {
            std::fs::read_dir("/proc").unwrap().flatten().any(|e| {
                std::fs::read_to_string(e.path().join("status")).is_ok_and(|s| {
                    s.lines().any(|l| {
                        l.starts_with("Uid:")
                            && l.split_whitespace().nth(1) == Some(&base.to_string())
                    })
                })
            })
        };
        let slow = sh("sleep 60 & sleep 60 & wait".into());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), slow)
                .await
                .is_err()
        );
        let t0 = std::time::Instant::now();
        while alive() {
            assert!(
                t0.elapsed().as_secs() < 5,
                "sandbox processes outlived their step"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}
