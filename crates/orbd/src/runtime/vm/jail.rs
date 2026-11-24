//! The jail every VMM runs in on Linux (`ORBD_VMM_JAIL`, on by default for a root
//! agent): a VMM escape lands in an unprivileged process that sees only its own orb.
//!
//! * **Identity.** Each orb gets its own uid and gid, `uid_base + <index>`, claimed
//!   durably on first use in `<state>/uids/<index>` (a file naming the orb) and released
//!   when the orb is deleted. The VMM runs as that uid with only the supplementary
//!   groups the devices it opens need, no capabilities and `no_new_privs`.
//! * **Files.** A private mount namespace whose root is a read-only tmpfs holding, at
//!   their original paths, only: its orb directory (read-write; the disk, logs and
//!   checkpoints), its launch's socket directory, the VMM binary (for QEMU `/usr` and
//!   the root library links), the kernel and QEMU's backing file (read-only), and
//!   `/dev/kvm`, `/dev/net/tun`, `/dev/null`, `/dev/urandom`. No `/proc`, `/sys`, other
//!   orbs, images or agent state. Original paths keep launch arguments, launch records
//!   and the host paths recorded in Firecracker snapshots valid.
//! * **Ownership.** The agent (root) keeps owning the orb's directories: they are
//!   `root:<orb gid> 0710`, so the VMM can reach its files but create, rename or replace
//!   nothing the agent later writes or reads. What the VMM writes is its own (`0600`):
//!   the disk, the log or console it opens itself, a save's memory file. What it only
//!   reads (a checkpoint being restored) is `root:<orb gid> 0640`. Each launch puts this
//!   in place first, so orbs created or saved with the jail off are fixed up on their
//!   first jailed start. Base disks are world-readable files inside root-only
//!   directories.
//! * **Sockets.** The VMM creates its sockets in `<run>/<runtime>/<orb>/vmm/` (its
//!   own), mounted at `<run>/<runtime>/<orb>` in the jail; the run directory itself,
//!   holding the agent's launch record, stays root's, with links to the sockets under
//!   their usual names.
//!
//! A jail that cannot be set up fails the launch: nothing silently runs unjailed. A VMM
//! left running unjailed (by this agent with `ORBD_VMM_JAIL=off`, outside a container
//! that stops it) is adopted as it is and jailed from its next start.

use crate::config::agent::{JailMode, VmmJail};
use crate::model::OrbId;
use orbd_vm::jail::{Access, Bind, Jail};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub use orbd_vm::jail::JailIdentity as Ids;

/// Orbs get indexes 1..=MAX_INDEX above the base; index 0 is the startup self-test's,
/// [`CODEC_INDEX`] the DNS proxy's codec's.
const MAX_INDEX: u32 = 1 << 24;
/// The index of the restricted-egress DNS proxy's codec ([`super::codec`]).
const CODEC_INDEX: u32 = MAX_INDEX + 1;
/// How many ids above the base jails use.
pub const JAIL_IDS: u32 = CODEC_INDEX;
/// Bases below this would collide with system and login users.
const MIN_BASE: u32 = 65_536;

/// Serializes index allocation within this agent.
static ALLOCATION: Mutex<()> = Mutex::new(());

/// Resolves `ORBD_VMM_JAIL` for this agent's VM runtimes: on Linux the jail is on unless
/// turned off (unsafe), and a jailing agent must run as root.
pub fn settings(mode: JailMode, uid_base: u32) -> Result<Option<VmmJail>, String> {
    let root = nix::unistd::geteuid().is_root();
    let s = settings_for(mode, uid_base, cfg!(target_os = "linux"), root)?;
    match s {
        Some(s) => tracing::info!(uid_base = s.uid_base, "VMMs run jailed"),
        None if cfg!(target_os = "linux") => tracing::warn!(
            uid = nix::unistd::geteuid().as_raw(),
            "ORBD_VMM_JAIL=off: VMMs run unjailed as this agent's user, with access to every \
             orb's files and this agent's state (unsafe; for development only)"
        ),
        None => {
            if mode == JailMode::Off {
                tracing::warn!(
                    "ORBD_VMM_JAIL has no effect on macOS: QEMU always runs in its Seatbelt sandbox"
                );
            }
        }
    }
    Ok(s)
}

fn settings_for(
    mode: JailMode,
    uid_base: u32,
    linux: bool,
    root: bool,
) -> Result<Option<VmmJail>, String> {
    if !linux || mode == JailMode::Off {
        return Ok(None);
    }
    if !root {
        return Err(
            "VM runtimes on Linux need an agent running as root, which jails every VMM \
             (ORBD_VMM_JAIL=off runs them unjailed: unsafe, for development only)"
                .into(),
        );
    }
    if uid_base < MIN_BASE || uid_base.checked_add(JAIL_IDS).is_none_or(|t| t == u32::MAX) {
        return Err(format!(
            "ORBD_VMM_JAIL_UID_BASE={uid_base}: must be at least {MIN_BASE} and leave {JAIL_IDS} \
             ids below 4294967295"
        ));
    }
    Ok(Some(VmmJail { uid_base }))
}

/// Builds jails for one runtime's VMMs.
pub struct Jailer {
    base: u32,
    state_dir: PathBuf,
    run_dir: PathBuf,
    /// The empty directory jails' roots are mounted on (`<run>/jail`).
    staging: PathBuf,
    /// Groups that open the devices VMMs use (when not open to everyone).
    device_groups: Vec<u32>,
}

impl Jailer {
    pub fn new(settings: VmmJail, state_dir: &Path, run_dir: &Path) -> Result<Self, String> {
        let staging = run_dir.join("jail");
        super::create_private_dir(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
        let mut device_groups = Vec::new();
        for dev in ["/dev/kvm", "/dev/net/tun"] {
            if let Some(g) = device_group(Path::new(dev))? {
                device_groups.push(g);
            }
        }
        device_groups.dedup();
        Ok(Self {
            base: settings.uid_base,
            state_dir: state_dir.to_owned(),
            run_dir: run_dir.to_owned(),
            staging,
            device_groups,
        })
    }

    /// The orb's uid and gid, claimed durably on first use.
    pub fn ids(&self, orb: OrbId) -> Result<Ids, String> {
        let index = allocate(&self.state_dir.join("uids"), orb)?;
        let id = self.base + index;
        Ok(Ids { uid: id, gid: id })
    }

    /// Kills whatever still runs as the orb's uid: called before each of its jailed
    /// launches and tool runs (no VMM of the orb runs then), so nothing an escaped VMM
    /// left behind outlives it.
    pub fn kill_strays(&self, ids: Ids) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        return orbd_vm::process::kill_uid(ids.uid)
            .map_err(|e| format!("killing the processes of uid {}: {e}", ids.uid));
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ids;
            Ok(())
        }
    }

    /// Releases the orb's uid once no VMM of it runs (its delete): every process left
    /// with that uid is killed, then the claim is removed. Uids are never handed out
    /// again (see [`allocate`]).
    pub fn release(&self, orb: OrbId) {
        if let Some(index) = claimed(&self.state_dir.join("uids"), orb) {
            let id = self.base + index;
            if let Err(e) = self.kill_strays(Ids { uid: id, gid: id }) {
                tracing::warn!(orb = %orb, error = %e, "releasing the orb's jail uid");
            }
        }
        release(&self.state_dir, orb);
    }

    /// A dynamically linked program's system (VMM or disk tool): `/usr` (and the
    /// installation prefix of a program outside it, or the whole Nix store for one in
    /// it: its libraries are other store paths), the root-level library directories or
    /// their links, and the loader cache.
    pub fn system(&self, program: &Path) -> Result<System, String> {
        system(program, &[&self.state_dir, &self.run_dir])
    }

    /// A jail for a tool that reads an orb's disk (no devices but `/dev/null` and
    /// `/dev/urandom`, no supplementary groups): `program`'s system and `files`.
    pub fn tool_jail(&self, ids: Ids, program: &Path, files: Vec<Bind>) -> Result<Jail, String> {
        let (mut binds, symlinks) = self.system(program)?;
        binds.push(Bind::at(program, Access::Exec));
        binds.extend(files);
        binds.extend(
            ["/dev/null", "/dev/urandom"]
                .into_iter()
                .map(|d| Bind::at(d, Access::Device)),
        );
        Ok(Jail {
            uid: ids.uid,
            gid: ids.gid,
            groups: Vec::new(),
            staging: self.staging.clone(),
            binds,
            symlinks,
            // A tool needs no network: an exploited one must not reach the agent's.
            new_netns: true,
        })
    }

    /// The jail of the restricted-egress DNS proxy's codecs: a tool's, as their own uid
    /// above every orb's, with orbd's system and its binary `exe` at
    /// [`super::codec::JAILED_EXE`].
    pub fn codec_jail(&self, exe: &Path) -> Result<Jail, String> {
        let id = self.base + CODEC_INDEX;
        let (mut binds, symlinks) = self.system(exe)?;
        binds.push(Bind {
            src: exe.to_owned(),
            dst: super::codec::JAILED_EXE.into(),
            access: Access::Exec,
        });
        binds.extend(
            ["/dev/null", "/dev/urandom"]
                .into_iter()
                .map(|d| Bind::at(d, Access::Device)),
        );
        Ok(Jail {
            uid: id,
            gid: id,
            groups: Vec::new(),
            staging: self.staging.clone(),
            binds,
            symlinks,
            new_netns: true,
        })
    }

    /// A jail for `ids` holding `binds` and `symlinks`, with `groups` besides the
    /// devices' groups.
    pub fn jail(
        &self,
        ids: Ids,
        binds: Vec<Bind>,
        symlinks: Vec<(PathBuf, PathBuf)>,
        groups: &[u32],
    ) -> Jail {
        let mut all: Vec<u32> = self.device_groups.clone();
        all.extend(groups.iter().copied().filter(|g| *g != ids.gid));
        all.sort_unstable();
        all.dedup();
        Jail {
            uid: ids.uid,
            gid: ids.gid,
            groups: all,
            staging: self.staging.clone(),
            binds,
            symlinks,
            new_netns: false,
        }
    }

    /// Runs `program args` in a jail with `binds` (as the base uid, which no orb has) to
    /// show that jails work on this host before any VMM depends on one.
    #[cfg(target_os = "linux")]
    pub fn probe(
        &self,
        program: &Path,
        args: &[&str],
        binds: Vec<Bind>,
        symlinks: Vec<(PathBuf, PathBuf)>,
    ) -> Result<(), String> {
        let ids = Ids {
            uid: self.base,
            gid: self.base,
        };
        let jail = self.jail(ids, binds, symlinks, &[]);
        let out = orbd_vm::jail::run(&jail, program, args)
            .map_err(|e| format!("{} in a jail: {e}", program.display()))?;
        if !out.status.success() {
            return Err(format!(
                "{} in a jail: {}: {}",
                program.display(),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn probe(
        &self,
        program: &Path,
        _args: &[&str],
        _binds: Vec<Bind>,
        _symlinks: Vec<(PathBuf, PathBuf)>,
    ) -> Result<(), String> {
        Err(format!("{}: VMM jails need Linux", program.display()))
    }
}

/// The group that may open `dev` if others may not; an error if only its owner may.
fn device_group(dev: &Path) -> Result<Option<u32>, String> {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = std::fs::metadata(dev) else {
        // Missing: the VMM's launch fails on it (with the device's name).
        return Ok(None);
    };
    match m.mode() {
        mode if mode & 0o006 == 0o006 => Ok(None),
        mode if mode & 0o060 == 0o060 => Ok(Some(m.gid())),
        mode => Err(format!(
            "{} (mode {:o}) can be opened only by its owner, not by jailed VMMs",
            dev.display(),
            mode & 0o777
        )),
    }
}

/// Removes `orb`'s uid claim (idempotent; once no VMM of the orb runs). With jails on,
/// [`Jailer::release`] also kills what still runs as that uid.
pub fn release(state_dir: &Path, orb: OrbId) {
    let dir = state_dir.join("uids");
    let _g = ALLOCATION.lock().unwrap_or_else(|e| e.into_inner());
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        if std::fs::read_to_string(e.path()).is_ok_and(|o| o.trim() == orb.to_string()) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The index `orb` has claimed in `dir`, if any.
fn claimed(dir: &Path, orb: OrbId) -> Option<u32> {
    let owner = orb.to_string();
    std::fs::read_dir(dir).ok()?.flatten().find_map(|e| {
        let i = e.file_name().to_str()?.parse::<u32>().ok()?;
        std::fs::read_to_string(e.path())
            .is_ok_and(|o| o.trim() == owner)
            .then_some(i)
    })
}

/// Where the next index is recorded, so a released one is never handed out again.
const NEXT: &str = "next";

/// `<dir>/<index>` files name their orb. Returns the orb's index or a new one, durably
/// claimed: one above every index ever handed out (`<dir>/next`), so no orb gets the uid
/// of a deleted orb (whose escaped processes might still run).
fn allocate(dir: &Path, orb: OrbId) -> Result<u32, String> {
    let _g = ALLOCATION.lock().unwrap_or_else(|e| e.into_inner());
    super::create_private_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let owner = orb.to_string();
    let mut next = std::fs::read_to_string(dir.join(NEXT))
        .ok()
        .and_then(|n| n.trim().parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    for e in std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
    {
        let Some(i) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if std::fs::read_to_string(e.path()).is_ok_and(|o| o.trim() == owner) {
            return Ok(i);
        }
        // Also covers a crash between a claim and the counter's update.
        next = next.max(i.saturating_add(1));
    }
    if next > MAX_INDEX {
        return Err(format!(
            "all {MAX_INDEX} VMM uids above ORBD_VMM_JAIL_UID_BASE have been handed out"
        ));
    }
    // The counter first: a crash between the two then only skips an index, never
    // leaves a claimed one to be handed out again after its orb is deleted.
    super::fsutil::write_atomic(&dir.join(NEXT), (next + 1).to_string().as_bytes())
        .map_err(|e| format!("recording the next VMM uid index: {e}"))?;
    super::fsutil::write_atomic(&dir.join(next.to_string()), owner.as_bytes())
        .map_err(|e| format!("claiming VMM uid index {next}: {e}"))?;
    Ok(next)
}

fn not_a_link(path: &Path) -> std::io::Result<std::fs::Metadata> {
    let m = std::fs::symlink_metadata(path)
        .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    if m.file_type().is_symlink() {
        return Err(std::io::Error::other(format!(
            "{} is a symbolic link",
            path.display()
        )));
    }
    Ok(m)
}

fn set(path: &Path, uid: u32, gid: u32, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = not_a_link(path)?;
    let ctx = |e: std::io::Error| std::io::Error::new(e.kind(), format!("{}: {e}", path.display()));
    if m.uid() != uid || m.gid() != gid {
        std::os::unix::fs::lchown(path, Some(uid), Some(gid)).map_err(ctx)?;
    }
    if m.mode() & 0o7777 != mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(ctx)?;
    }
    Ok(())
}

/// A directory of the agent's that the VMM passes through: `root:<gid> 0710`.
pub fn traversable(dir: &Path, ids: Ids) -> std::io::Result<()> {
    set(dir, 0, ids.gid, 0o710)
}

/// A file the VMM writes: its own, `0600`.
pub fn owned(file: &Path, ids: Ids) -> std::io::Result<()> {
    set(file, ids.uid, ids.gid, 0o600)
}

/// A file the VMM reads: its own already (it wrote it), else `root:<gid> 0640`.
pub fn readable(file: &Path, ids: Ids) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = not_a_link(file)?;
    if m.uid() == ids.uid && m.mode() & 0o400 != 0 {
        return Ok(());
    }
    set(file, 0, ids.gid, 0o640)
}

/// Creates `file` (empty) if it is missing, then gives it to the VMM.
pub fn owned_new(file: &Path, ids: Ids) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)
        .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", file.display())))?;
    owned(file, ids)
}

/// A read-only input shared by several orbs (kernel, base disk), which jailed VMMs read
/// as "others": an error if it is not world-readable. `fix` makes it so (for the
/// agent's own base disks, inside root-only directories).
pub fn shared_input(path: &Path, fix: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::metadata(path)
        .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    let mode = m.permissions().mode();
    if mode & 0o004 != 0 {
        return Ok(());
    }
    if fix {
        return std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o444))
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())));
    }
    Err(std::io::Error::other(format!(
        "{} (mode {:o}) is not world-readable, so jailed VMMs cannot read it",
        path.display(),
        mode & 0o7777
    )))
}

/// The launch's socket directory `<run dir>/vmm`, the VMM's own; the run directory
/// links each of `names` into it.
pub fn socket_dir(run_dir: &Path, ids: Ids, names: &[&str]) -> std::io::Result<PathBuf> {
    let dir = run_dir.join("vmm");
    std::fs::create_dir(&dir)
        .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", dir.display())))?;
    set(&dir, ids.uid, ids.gid, 0o700)?;
    for name in names {
        std::os::unix::fs::symlink(Path::new("vmm").join(name), run_dir.join(name))?;
    }
    Ok(dir)
}

/// Device nodes every jailed VMM gets (`/dev/net/tun` with a network namespace).
pub fn devices(tap: bool) -> Vec<Bind> {
    let mut d = vec!["/dev/kvm", "/dev/null", "/dev/urandom"];
    if tap {
        d.push("/dev/net/tun");
    }
    d.into_iter().map(|p| Bind::at(p, Access::Device)).collect()
}

/// A program's system: binds and symbolic links `(path, target)`.
pub type System = (Vec<Bind>, Vec<(PathBuf, PathBuf)>);

/// [`Jailer::system`]. A prefix that is `/` or holds one of `protected` (the agent's
/// state and run directories) is refused.
fn system(program: &Path, protected: &[&Path]) -> Result<System, String> {
    let mut binds = vec![Bind::at("/usr", Access::Exec)];
    let real = std::fs::canonicalize(program).map_err(|e| format!("{}: {e}", program.display()))?;
    if real.starts_with("/nix/store") {
        binds.push(Bind::at("/nix/store", Access::Exec));
    } else if !real.starts_with("/usr") {
        // `<prefix>/bin/<program>`: its libraries and data live under the prefix. A
        // program elsewhere (e.g. `/opt/qemu-system-x86_64`) gets only itself.
        let dir = real.parent().unwrap_or(Path::new("/"));
        if matches!(
            dir.file_name().and_then(|n| n.to_str()),
            Some("bin" | "sbin")
        ) {
            let prefix = dir.parent().unwrap_or(Path::new("/"));
            let holds = |p: &&Path| {
                let p = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
                p.starts_with(prefix)
            };
            if prefix == Path::new("/") {
                // `/bin` or `/sbin` (no merged /usr): the program itself (its caller binds
                // it) and its libraries in `/lib*`, bound below; never all of `/`.
            } else if protected.iter().any(holds) {
                return Err(format!(
                    "{} is installed under {}, which holds this agent's state: install it \
                     elsewhere for jailed VMMs",
                    program.display(),
                    prefix.display()
                ));
            } else {
                binds.push(Bind::at(prefix, Access::Exec));
            }
        }
    }
    let mut links = Vec::new();
    for dir in ["/lib", "/lib64", "/lib32", "/libx32"] {
        let p = Path::new(dir);
        match std::fs::read_link(p) {
            Ok(target) => links.push((p.to_owned(), target)),
            Err(_) if p.is_dir() => binds.push(Bind::at(p, Access::Exec)),
            Err(_) => {}
        }
    }
    if Path::new("/etc/ld.so.cache").is_file() {
        binds.push(Bind::at("/etc/ld.so.cache", Access::Read));
    }
    Ok((binds, links))
}

/// The uid serving a launch's sockets: its jail's (the owner of `<run dir>/vmm`, which
/// the VMM cannot change or replace), or this agent's for an unjailed VMM. The agent
/// checks every connection against it ([`orbd_vm::process::connect_unix`]).
pub fn socket_owner(run_dir: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(run_dir.join("vmm")) {
        Ok(m) if m.is_dir() => Ok(m.uid()),
        Ok(_) => Err(std::io::Error::other(format!(
            "{}/vmm is not a directory",
            run_dir.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(nix::unistd::geteuid().as_raw()),
        Err(e) => Err(e),
    }
}

/// A file a launch's VMM writes itself (e.g. QEMU's pidfile), where it really is: in
/// `vmm/` for a jailed VMM.
pub fn vmm_file(run_dir: &Path, name: &str) -> PathBuf {
    let jailed = run_dir.join("vmm");
    if jailed.is_dir() {
        jailed.join(name)
    } else {
        run_dir.join(name)
    }
}

/// Logs once per orb, and counts (`orbd_vmm_unjailed_adopted_total`), that a jailing
/// agent adopted its VMM running unjailed.
pub fn warn_unjailed(orb: OrbId, pid: i32) {
    static WARNED: Mutex<Option<HashSet<OrbId>>> = Mutex::new(None);
    let mut w = WARNED.lock().unwrap_or_else(|e| e.into_inner());
    if w.get_or_insert_with(HashSet::new).insert(orb) {
        metrics::counter!("orbd_vmm_unjailed_adopted_total").increment(1);
        tracing::warn!(orb = %orb, pid, "adopted a VMM that runs unjailed (started with ORBD_VMM_JAIL=off, or by an older orbd); it is jailed from its next start");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jail_settings() {
        use JailMode::*;
        let on = Some(VmmJail {
            uid_base: 1_300_000_000,
        });
        let base = 1_300_000_000;
        // A Linux VM agent jails, and must run as root to, unless told not to (unsafe).
        assert_eq!(settings_for(On, base, true, true), Ok(on));
        assert!(settings_for(On, base, true, false).is_err());
        assert_eq!(settings_for(Off, base, true, true), Ok(None));
        assert_eq!(settings_for(Off, base, true, false), Ok(None));
        // macOS: Seatbelt instead.
        assert_eq!(settings_for(On, base, false, false), Ok(None));
        // Bases that collide with ordinary users or overflow.
        assert!(settings_for(On, 1000, true, true).is_err());
        assert!(settings_for(On, u32::MAX - 10, true, true).is_err());
        assert!(settings_for(On, u32::MAX - JAIL_IDS, true, true).is_err());
        assert!(settings_for(On, u32::MAX - JAIL_IDS - 1, true, true).is_ok());
        // Never in the image builds' range above 1.4e9 with the default base.
        assert!(base + JAIL_IDS < 1_400_000_000);
    }

    #[test]
    fn uids_are_durable_distinct_and_never_reused() {
        let state = tempfile::tempdir().unwrap();
        let j = Jailer {
            base: 1_300_000_000,
            state_dir: state.path().to_owned(),
            run_dir: state.path().join("run"),
            staging: state.path().join("jail"),
            device_groups: vec![],
        };
        let (a, b, c, d) = (
            OrbId::generate(),
            OrbId::generate(),
            OrbId::generate(),
            OrbId::generate(),
        );
        let ia = j.ids(a).unwrap();
        let ib = j.ids(b).unwrap();
        assert_eq!(ia.uid, 1_300_000_001);
        assert_eq!(ia.uid, ia.gid);
        assert_eq!(ib.uid, 1_300_000_002);
        assert_eq!(j.ids(a).unwrap(), ia, "the same orb keeps its uid");
        release(state.path(), b);
        release(state.path(), b);
        // A deleted orb's uid (here the highest) is not handed out again.
        let ic = j.ids(c).unwrap();
        assert_eq!(ic.uid, 1_300_000_003, "a released uid is not reused");
        assert_eq!(j.ids(a).unwrap(), ia);
        // Nor after a crash that lost the counter's update: claims count too.
        std::fs::remove_file(state.path().join("uids").join(NEXT)).unwrap();
        assert_eq!(j.ids(d).unwrap().uid, 1_300_000_004);
        let jail = j.jail(ib, vec![], vec![], &[ib.gid, 7, 7]);
        assert_eq!(jail.groups, [7], "no duplicates, not the primary gid");
    }

    /// A program's installation prefix is bound only below `/` and away from the
    /// agent's state.
    #[test]
    fn install_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let bin = dir.path().join("opt/qemu/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let vmm = bin.join("qemu-system-x86_64");
        std::fs::write(&vmm, "").unwrap();
        let prefixes = |p: &Path, protected: &[&Path]| -> Result<Vec<PathBuf>, String> {
            let (binds, _) = system(p, protected)?;
            Ok(binds
                .into_iter()
                .map(|b| b.dst)
                .filter(|d| d != Path::new("/usr") && !d.starts_with("/lib"))
                .filter(|d| d != Path::new("/etc/ld.so.cache"))
                .collect())
        };
        let prefix = std::fs::canonicalize(dir.path().join("opt/qemu")).unwrap();
        assert_eq!(
            prefixes(&vmm, &[&state]).unwrap(),
            std::slice::from_ref(&prefix)
        );
        // Through a relative path or a link, the real location counts.
        let link = dir.path().join("qemu");
        std::os::unix::fs::symlink(&vmm, &link).unwrap();
        assert_eq!(prefixes(&link, &[&state]).unwrap(), [prefix]);
        // Not in a bin directory: only the program itself.
        let loose = dir.path().join("opt/qemu-system-x86_64");
        std::fs::write(&loose, "").unwrap();
        assert!(prefixes(&loose, &[&state]).unwrap().is_empty());
        // A prefix holding the agent's state is refused.
        let inside = dir.path().join("opt/qemu/state");
        std::fs::create_dir_all(&inside).unwrap();
        assert!(prefixes(&vmm, &[&inside]).is_err());
        assert!(prefixes(&dir.path().join("missing"), &[]).is_err());
    }

    #[test]
    fn ownership_fixups() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let me = Ids {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        };
        let f = dir.path().join("f");
        std::fs::write(&f, "").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o444)).unwrap();
        owned(&f, me).unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o7777, 0o600);
        owned_new(&dir.path().join("new"), me).unwrap();
        assert_eq!(
            std::fs::metadata(dir.path().join("new")).unwrap().mode() & 0o7777,
            0o600
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(owned(&link, me).is_err(), "links are refused, not followed");
        readable(&f, me).unwrap();
        // Shared inputs must be world-readable; the agent's own are made so.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(shared_input(&f, false).is_err());
        shared_input(&f, true).unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o7777, 0o644);
        let run = dir.path().join("run");
        std::fs::create_dir(&run).unwrap();
        let sockets = socket_dir(&run, me, &["api.sock"]).unwrap();
        assert_eq!(
            std::fs::read_link(run.join("api.sock")).unwrap(),
            Path::new("vmm/api.sock")
        );
        assert_eq!(std::fs::metadata(&sockets).unwrap().mode() & 0o7777, 0o700);
    }

    /// As root with QEMU (skipped otherwise unless `ORBD_TEST_JAIL=1` requires it): a
    /// jailed VMM's socket is reached through the run directory's link and must be
    /// served by its uid; once the VMM points its socket at one the agent (root) serves
    /// instead, as an escaped VMM could, the agent refuses it before sending anything.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn vmm_sockets_must_be_served_by_the_vmm() {
        let qemu = crate::runtime::vm::on_path(Path::new(orbd_qemu::probe::QEMU_SYSTEM));
        let (true, Some(qemu)) = (nix::unistd::geteuid().is_root(), qemu) else {
            assert!(
                std::env::var("ORBD_TEST_JAIL").is_err(),
                "ORBD_TEST_JAIL is set but the test does not run as root with QEMU"
            );
            eprintln!("skipped: needs root and QEMU");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let (state, run) = (dir.path().join("state"), dir.path().join("run"));
        let orb_run = run.join("qemu/orb");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&orb_run).unwrap();
        let jailer = Jailer::new(
            VmmJail {
                uid_base: 1_300_200_000,
            },
            &state,
            &run,
        )
        .unwrap();
        let ids = jailer.ids(OrbId::generate()).unwrap();
        let vmm = socket_dir(&orb_run, ids, &["qmp.sock"]).unwrap();
        assert_eq!(socket_owner(&orb_run).unwrap(), ids.uid);
        let (mut binds, links) = jailer.system(&qemu).unwrap();
        binds.push(Bind::at(&qemu, Access::Exec));
        binds.push(Bind {
            src: vmm.clone(),
            dst: orb_run.clone(),
            access: Access::Write,
        });
        binds.push(Bind::at("/dev/null", Access::Device));
        let jail = jailer.jail(ids, binds, links, &[]);
        let qmp = orb_run.join("qmp.sock");
        let mut child = orbd_vm::jail::command(&jail, &qemu)
            .unwrap()
            .args([
                "-machine",
                "none",
                "-nodefaults",
                "-display",
                "none",
                "-qmp",
            ])
            .arg(format!("unix:{},server=on,wait=off", qmp.display()))
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !vmm.join("qmp.sock").exists() {
            assert!(std::time::Instant::now() < deadline, "QEMU did not listen");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let timeout = std::time::Duration::from_secs(5);
        let q = orbd_qemu::qmp::Qmp::connect(&qmp, Some(ids.uid), timeout).await;
        assert!(q.is_ok(), "{:?}", q.err());
        drop(q);
        assert!(
            orbd_qemu::qmp::Qmp::connect(&qmp, Some(0), timeout)
                .await
                .is_err(),
            "not root's"
        );
        // The VMM replaces its socket with a link to one root serves.
        let root_sock = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&root_sock).unwrap();
        std::fs::remove_file(vmm.join("qmp.sock")).unwrap();
        std::os::unix::fs::symlink(&root_sock, vmm.join("qmp.sock")).unwrap();
        let err = orbd_vm::process::connect_unix(&qmp, ids.uid)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut s, &mut buf)
            .await
            .unwrap();
        assert!(buf.is_empty(), "nothing was sent");
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
