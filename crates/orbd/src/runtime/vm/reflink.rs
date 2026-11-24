//! Reflinks: disks made from a base (a prepared image, a project snapshot, an orb's disk
//! for a snapshot) are clones that share the base's blocks where the state directory's
//! filesystem can clone files (XFS, btrfs), and full sparse copies elsewhere (ext4).
//!
//! The agent probes the state directory once at startup and says which it got. On btrfs
//! a clone also needs both files to agree on the No_COW attribute, so a state directory
//! whose `images/`, `projects/`, `orbs/` and `staging/` disagree on it silently gets full
//! copies: that is warned about too. A clone that fails where the probe succeeded is
//! logged and counted (`orbd_agent_disk_copies_total{method="copy"}`).

use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

const UNKNOWN: u8 = 0;
const SUPPORTED: u8 = 1;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const UNSUPPORTED: u8 = 2;

/// What the startup probe found (see [`probe`]).
static PROBED: AtomicU8 = AtomicU8::new(UNKNOWN);

/// Whether the startup probe could clone a file in the state directory.
pub fn expected() -> bool {
    PROBED.load(Ordering::Relaxed) == SUPPORTED
}

/// Makes `to` a clone of `from` (sharing its blocks), replacing what `to` held.
#[cfg(target_os = "linux")]
pub fn clone_file(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let src = std::fs::File::open(from)?;
    let dst = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(to)?;
    // SAFETY: FICLONE takes the source descriptor as its argument; both stay open.
    let r = unsafe { nix::libc::ioctl(dst.as_raw_fd(), nix::libc::FICLONE, src.as_raw_fd()) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    dst.sync_all()
}

#[cfg(not(target_os = "linux"))]
pub fn clone_file(_from: &Path, _to: &Path) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// The filesystem holding `dir`, by name where orbd cares.
#[cfg(target_os = "linux")]
fn fs_name(dir: &Path) -> String {
    // statfs(2) magic numbers (nix names them on glibc only).
    match nix::sys::statfs::statfs(dir) {
        Ok(s) => match s.filesystem_type().0 as u64 {
            0x5846_5342 => "xfs".into(),
            0x9123_683e => "btrfs".into(),
            0xef53 => "ext4".into(),
            0x0102_1994 => "tmpfs".into(),
            0x794c_7630 => "overlayfs".into(),
            t => format!("{t:#x}"),
        },
        Err(e) => format!("unknown ({e})"),
    }
}

/// btrfs's No_COW inode attribute (`chattr +C`), `FS_NOCOW_FL`.
#[cfg(target_os = "linux")]
const FS_NOCOW_FL: nix::libc::c_long = 0x0080_0000;

/// Whether `path` has the No_COW attribute; None if it cannot be read.
#[cfg(target_os = "linux")]
fn nocow(path: &Path) -> Option<bool> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(path).ok()?;
    let mut flags: nix::libc::c_long = 0;
    // SAFETY: FS_IOC_GETFLAGS writes one long into `flags`.
    let r = unsafe {
        nix::libc::ioctl(
            f.as_raw_fd(),
            nix::libc::FS_IOC_GETFLAGS,
            &mut flags as *mut nix::libc::c_long,
        )
    };
    (r == 0).then_some(flags & FS_NOCOW_FL != 0)
}

/// Probes `state_dir` (its `staging/`) for clones once at startup, records the result
/// for [`expected`] and logs it; on btrfs also checks that the directories clones go
/// between agree on No_COW.
#[cfg(target_os = "linux")]
pub fn probe(state_dir: &Path) {
    let staging = state_dir.join("staging");
    let _ = std::fs::create_dir_all(&staging);
    let fs = fs_name(state_dir);
    let a = staging.join(format!("reflink-probe-{}", uuid::Uuid::new_v4().simple()));
    let b = a.with_extension("clone");
    let cloned = std::fs::write(&a, [0x5a_u8; 4096]).and_then(|()| clone_file(&a, &b));
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    match cloned {
        Ok(()) => {
            PROBED.store(SUPPORTED, Ordering::Relaxed);
            tracing::info!(filesystem = %fs, state_dir = %state_dir.display(), "reflinks work in the state directory: orb disks and project snapshots share their base's blocks");
        }
        Err(e) => {
            PROBED.store(UNSUPPORTED, Ordering::Relaxed);
            tracing::info!(filesystem = %fs, state_dir = %state_dir.display(), reason = %e, "no reflinks in the state directory: every orb disk and project snapshot is a full copy (XFS or btrfs would share blocks; see the README's host setup)");
        }
    }
    if fs == "btrfs" {
        let dirs = ["images", "projects", "orbs", "staging"];
        let found: Vec<(&str, Option<bool>)> = dirs
            .iter()
            .map(|d| (*d, nocow(&state_dir.join(d))))
            .filter(|(d, _)| state_dir.join(d).is_dir())
            .collect();
        let set: std::collections::HashSet<Option<bool>> = found.iter().map(|(_, n)| *n).collect();
        if set.len() > 1 {
            let detail: Vec<String> = found
                .iter()
                .map(|(d, n)| match n {
                    Some(true) => format!("{d}: No_COW"),
                    Some(false) => format!("{d}: COW"),
                    None => format!("{d}: unknown"),
                })
                .collect();
            tracing::warn!(
                detail = %detail.join(", "),
                "btrfs refuses reflinks between No_COW and COW files, so disks copied across these \
                 directories are full copies: give the whole state directory one setting \
                 (`chattr +C` on it while empty, before anything is written)"
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe(_state_dir: &Path) {}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// A clone holds the source's bytes and replaces what the destination held; where
    /// the filesystem cannot clone, it fails rather than copying.
    #[test]
    fn clones_replace_the_destination_or_fail() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, b"source bytes").unwrap();
        std::fs::write(&b, b"a much longer destination that must not survive").unwrap();
        match clone_file(&a, &b) {
            Ok(()) => assert_eq!(std::fs::read(&b).unwrap(), b"source bytes"),
            Err(e) => {
                let code = e.raw_os_error();
                assert!(
                    matches!(
                        code,
                        Some(nix::libc::EOPNOTSUPP | nix::libc::EXDEV | nix::libc::EINVAL)
                    ),
                    "{e}"
                );
            }
        }
    }
}
