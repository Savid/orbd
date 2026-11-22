//! The tools that read an orb's disk when it becomes a project snapshot: `qemu-img
//! convert` of a QEMU orb's qcow2 overlay (whose header the VMM can write) and e2fsck,
//! resize2fs and dumpe2fs of the copy (whose filesystem the guest wrote). With jails
//! (`ORBD_VMM_JAIL`) none of them runs as root: each runs in the orb's own jail, as its
//! uid, and sees only the files it works on, at their paths: its inputs read-only, its
//! output lent to it (owned by the orb's uid while it runs, then taken back: still the
//! file the agent created, owned by root again). The qcow2's backing file is pinned to
//! the orb's base and an external data file is refused, so the header names no other
//! file either.

use super::jail::{Ids, Jailer};
use super::{OpContext, RuntimeError, bounded, io_err, on_path};
use orbd_vm::jail::{Access, Bind};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Where the tools run: in an orb's jail, or (VMMs unjailed) as the agent.
pub struct DiskTools<'a> {
    jail: Option<(&'a Jailer, Ids)>,
}

/// A file lent to the tools: what it was when lent.
pub struct Lent {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

/// Opens `path` itself (no link), a regular file.
fn open_file(path: &Path, write: bool) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(f)
}

impl<'a> DiskTools<'a> {
    /// Tools in the jail of the orb with `ids` (from `jailer`), or as the agent.
    pub fn new(jail: Option<(&'a Jailer, Ids)>) -> Self {
        Self { jail }
    }

    /// Lends the agent's file `path` to the tools, which write it.
    pub fn lend(&self, path: &Path) -> std::io::Result<Lent> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let f = open_file(path, false)?;
        if let Some((_, ids)) = self.jail {
            std::os::unix::fs::fchown(&f, Some(ids.uid), Some(ids.gid))?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let m = f.metadata()?;
        Ok(Lent {
            path: path.to_owned(),
            dev: m.dev(),
            ino: m.ino(),
        })
    }

    /// Kills every process of the orb's uid (with a jail): nothing an escaped VMM or a
    /// tool left behind may change a file once checked or taken back.
    pub fn kill_strays(&self) -> std::io::Result<()> {
        match self.jail {
            Some((jailer, ids)) => jailer.kill_strays(ids).map_err(std::io::Error::other),
            None => Ok(()),
        }
    }

    /// Takes a lent file back: still the file that was lent, root's again, and no
    /// process of the orb's uid left to hold it open. Returns it open for writing.
    pub fn take_back(&self, lent: Lent) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // A tool's child could outlive it with the file open for writing.
        self.kill_strays()?;
        let f = open_file(&lent.path, true)?;
        let m = f.metadata()?;
        if (m.dev(), m.ino()) != (lent.dev, lent.ino) {
            return Err(std::io::Error::other(format!(
                "{} was replaced while the disk tools ran",
                lent.path.display()
            )));
        }
        if self.jail.is_some() {
            std::os::unix::fs::fchown(&f, Some(0), Some(0))?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(f)
    }

    /// Runs the tool `program` (looked up on PATH) with `args`, seeing `files` (in a
    /// jail); bounded by the context. Returns its exit code and stdout.
    async fn run(
        &self,
        ctx: &OpContext,
        program: &str,
        args: &[OsString],
        files: &[(&Path, Access)],
    ) -> Result<(Option<i32>, String), RuntimeError> {
        let path = on_path(Path::new(program))
            .ok_or_else(|| RuntimeError::Other(format!("{program} not found")))?;
        let jailed = |e: String| RuntimeError::Other(format!("{program} in the orb's jail: {e}"));
        let mut cmd = match self.jail {
            Some((jailer, ids)) => {
                // Nothing an escaped VMM left behind may meet the tool.
                jailer.kill_strays(ids).map_err(jailed)?;
                let binds = files.iter().map(|(p, a)| Bind::at(*p, *a)).collect();
                let jail = jailer.tool_jail(ids, &path, binds).map_err(jailed)?;
                jailed_command(&jail, &path).map_err(|e| jailed(e.to_string()))?
            }
            None => tokio::process::Command::new(&path),
        };
        // Parsed output in English; no /proc/mounts in a jail, and the disk is no
        // mounted filesystem.
        cmd.args(args)
            .env("LC_ALL", "C")
            .env("EXT2FS_NO_MTAB_OK", "1")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let out = bounded(ctx, cmd.output())
            .await?
            .map_err(|e| RuntimeError::Other(format!("{program}: {e}")))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() && out.status.code().is_none_or(|c| c > 1) {
            let err = String::from_utf8_lossy(&out.stderr);
            let msg = format!("{program}: {} {}", out.status, err.trim());
            return Err(if err.contains("No space left") {
                RuntimeError::InsufficientDisk(msg)
            } else {
                RuntimeError::Other(msg)
            });
        }
        Ok((out.status.code(), stdout))
    }
}

/// `program` in `jail`, with a plain PATH.
#[cfg(target_os = "linux")]
fn jailed_command(
    jail: &orbd_vm::jail::Jail,
    program: &Path,
) -> std::io::Result<tokio::process::Command> {
    let mut cmd = tokio::process::Command::from(orbd_vm::jail::command(jail, program)?);
    cmd.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    Ok(cmd)
}

#[cfg(not(target_os = "linux"))]
fn jailed_command(
    _jail: &orbd_vm::jail::Jail,
    _program: &Path,
) -> std::io::Result<tokio::process::Command> {
    Err(std::io::Error::other("jails need Linux"))
}

/// `qcow2` incompatible feature: the guest's data lives in an external file the
/// header names.
const QCOW2_EXTERNAL_DATA_FILE: u64 = 1 << 2;

/// Refuses a qcow2 image whose header names an external data file (or is no qcow2).
fn check_qcow2(disk: &Path) -> std::io::Result<()> {
    use std::io::Read;
    let mut header = [0u8; 80];
    open_file(disk, false)?.read_exact(&mut header)?;
    let be32 = |o: usize| u32::from_be_bytes(header[o..o + 4].try_into().expect("4 bytes"));
    let be64 = |o: usize| u64::from_be_bytes(header[o..o + 8].try_into().expect("8 bytes"));
    let bad = |why: String| Err(std::io::Error::other(format!("{}: {why}", disk.display())));
    if be32(0) != 0x5146_49fb {
        return bad("not a qcow2 image".into());
    }
    match be32(4) {
        2 => Ok(()),
        3 if be64(72) & QCOW2_EXTERNAL_DATA_FILE != 0 => {
            bad("the qcow2 header names an external data file".into())
        }
        3 => Ok(()),
        v => bad(format!("qcow2 version {v}")),
    }
}

/// Escapes a path for a QEMU option string.
fn opt(path: &Path) -> String {
    path.display().to_string().replace(',', ",,")
}

/// Converts a QEMU orb's qcow2 overlay `disk` into the standalone raw disk `out` (lent,
/// as large as the disk), reading through to `base` (the orb's, whatever the header
/// says) and nothing else.
pub async fn qcow2_to_raw(
    tools: &DiskTools<'_>,
    ctx: &OpContext,
    qemu_img: &Path,
    disk: &Path,
    base: &Path,
    out: &Path,
) -> Result<(), RuntimeError> {
    // Checked with nothing of the orb's uid left to change the header after.
    tools
        .kill_strays()
        .and_then(|()| check_qcow2(disk))
        .map_err(|e| RuntimeError::Other(format!("project snapshot: {e}")))?;
    let image = format!(
        "driver=qcow2,file.driver=file,file.filename={},backing.driver=raw,\
         backing.file.driver=file,backing.file.filename={}",
        opt(disk),
        opt(base)
    );
    let args: Vec<OsString> = vec![
        "convert".into(),
        "-q".into(),
        // Into the agent's (lent) file, which is new and all zeros.
        "-n".into(),
        "--target-is-zero".into(),
        "--image-opts".into(),
        image.into(),
        "-O".into(),
        "raw".into(),
        out.into(),
    ];
    let program = qemu_img.to_string_lossy();
    let (code, _) = tools
        .run(
            ctx,
            &program,
            &args,
            &[
                (disk, Access::Read),
                (base, Access::Read),
                (out, Access::Write),
            ],
        )
        .await?;
    if code != Some(0) {
        return Err(RuntimeError::Other(format!(
            "{program} convert: exit {code:?}"
        )));
    }
    Ok(())
}

/// Shrinks the raw ext4 disk `raw` (lent) to the blocks its files use, so a snapshot
/// of a big orb fits any offering (the guest grows its root filesystem to its disk at
/// boot). Returns the filesystem's new size: the caller truncates the file to it once
/// it took the file back.
pub async fn shrink_ext4(
    tools: &DiskTools<'_>,
    ctx: &OpContext,
    raw: &Path,
) -> Result<u64, RuntimeError> {
    let file = [(raw, Access::Write)];
    // resize2fs wants a freshly checked filesystem. Exit 1 means e2fsck fixed something,
    // such as replaying the journal of this crash-consistent copy.
    tools
        .run(
            ctx,
            "e2fsck",
            &["-f".into(), "-y".into(), raw.into()],
            &file,
        )
        .await?;
    let (code, _) = tools
        .run(ctx, "resize2fs", &["-M".into(), raw.into()], &file)
        .await?;
    if code != Some(0) {
        return Err(RuntimeError::Other(format!("resize2fs: exit {code:?}")));
    }
    let (_, header) = tools
        .run(
            ctx,
            "dumpe2fs",
            &["-h".into(), raw.into()],
            &[(raw, Access::Read)],
        )
        .await?;
    let field = |name: &str| {
        header
            .lines()
            .find_map(|l| l.strip_prefix(name)?.trim().parse::<u64>().ok())
            .ok_or_else(|| {
                RuntimeError::Other(format!("dumpe2fs: no {name:?} in {}", raw.display()))
            })
    };
    field("Block count:")?
        .checked_mul(field("Block size:")?)
        .ok_or_else(|| RuntimeError::Other("dumpe2fs: filesystem size overflows".into()))
}

/// Truncates the taken-back `raw` to the filesystem's `bytes`, which must fit in it.
pub fn truncate(raw: &std::fs::File, path: &Path, bytes: u64) -> Result<(), RuntimeError> {
    let len = raw.metadata().map_err(io_err)?.len();
    if bytes == 0 || bytes > len {
        return Err(RuntimeError::Other(format!(
            "{}: its filesystem claims {bytes} bytes of {len}",
            path.display()
        )));
    }
    raw.set_len(bytes).map_err(io_err)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn external_data_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("disk.qcow2");
        let mut header = vec![0u8; 104];
        header[..4].copy_from_slice(&0x5146_49fbu32.to_be_bytes());
        header[4..8].copy_from_slice(&3u32.to_be_bytes());
        std::fs::write(&disk, &header).unwrap();
        check_qcow2(&disk).unwrap();
        header[72..80].copy_from_slice(&QCOW2_EXTERNAL_DATA_FILE.to_be_bytes());
        std::fs::write(&disk, &header).unwrap();
        assert!(check_qcow2(&disk).is_err());
        std::fs::write(
            &disk,
            b"not a qcow2 image at all, but long enough to read a header from it ok",
        )
        .unwrap();
        assert!(check_qcow2(&disk).is_err());
        let link = dir.path().join("link.qcow2");
        std::os::unix::fs::symlink(&disk, &link).unwrap();
        assert!(check_qcow2(&link).is_err(), "not through a link");
    }

    fn ctx() -> OpContext {
        let (log, _rx) = tokio::sync::mpsc::channel(16);
        let later = std::time::Instant::now() + std::time::Duration::from_secs(120);
        OpContext {
            operation_id: crate::model::OperationId::generate(),
            generation: 1,
            work_deadline: later,
            cleanup_deadline: later,
            cancel: Default::default(),
            log,
        }
    }

    fn sh(cmd: &str) {
        let out = std::process::Command::new("sh")
            .args(["-c", cmd])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{cmd}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn contains(file: &Path, needle: &[u8]) -> bool {
        std::fs::read(file)
            .unwrap()
            .windows(needle.len())
            .any(|w| w == needle)
    }

    /// As root with qemu-img and e2fsprogs (skipped otherwise unless `ORBD_TEST_JAIL=1`
    /// requires it): a QEMU orb's overlay whose header was rewritten to read through to
    /// another file (`qemu-img rebase -u`) is converted from the orb's real base, every
    /// tool runs as the orb's uid (never root), and one with an external data file is
    /// refused.
    #[tokio::test]
    async fn snapshots_read_only_the_orbs_own_disk_and_not_as_root() {
        let tools_there = ["qemu-img", "mkfs.ext4", "e2fsck", "resize2fs", "dumpe2fs"]
            .iter()
            .all(|t| on_path(Path::new(t)).is_some());
        if !nix::unistd::geteuid().is_root() || !tools_there {
            assert!(
                std::env::var("ORBD_TEST_JAIL").is_err(),
                "ORBD_TEST_JAIL is set but the test does not run as root with qemu-img and \
                 e2fsprogs"
            );
            eprintln!("skipped: needs root, qemu-img and e2fsprogs");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (state, run) = (d.join("state"), d.join("run"));
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        // The orb's base: an ext4 holding a marker. Another file (root's secret) holds
        // another marker the snapshot must never contain.
        std::fs::create_dir_all(d.join("content")).unwrap();
        std::fs::write(d.join("content/base-file"), "BASE-MARKER-0123456789").unwrap();
        let (base, secret) = (d.join("base.raw"), d.join("secret.raw"));
        sh(&format!(
            "mkfs.ext4 -q -F -d {} {} 32M && chmod 0444 {1}",
            d.join("content").display(),
            base.display()
        ));
        sh(&format!(
            "yes SECRET-MARKER-0123456789 | head -c 33554432 > {0} && chmod 0600 {0}",
            secret.display()
        ));
        let disk = d.join("disk.qcow2");
        sh(&format!(
            "qemu-img create -q -f qcow2 -F raw -b {} {} 32M && \
             qemu-img rebase -u -F raw -b {} {1}",
            base.display(),
            disk.display(),
            secret.display()
        ));
        let jailer = Jailer::new(
            crate::config::agent::VmmJail {
                uid_base: 1_300_100_000,
            },
            &state,
            &run,
        )
        .unwrap();
        let ids = jailer.ids(crate::model::OrbId::generate()).unwrap();
        super::super::jail::owned(&disk, ids).unwrap();
        let tools = DiskTools::new(Some((&jailer, ids)));
        let ctx = ctx();

        let (_, uid) = tools.run(&ctx, "id", &["-u".into()], &[]).await.unwrap();
        assert_eq!(
            uid.trim(),
            ids.uid.to_string(),
            "the tools run as the orb's uid"
        );

        let out = d.join("out.raw");
        std::fs::File::create(&out)
            .unwrap()
            .set_len(32 << 20)
            .unwrap();
        let lent = tools.lend(&out).unwrap();
        qcow2_to_raw(&tools, &ctx, Path::new("qemu-img"), &disk, &base, &out)
            .await
            .unwrap();
        let bytes = shrink_ext4(&tools, &ctx, &out).await.unwrap();
        let f = tools.take_back(lent).unwrap();
        truncate(&f, &out, bytes).unwrap();
        drop(f);
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&out).unwrap().uid(), 0, "root's again");
        assert!(
            contains(&out, b"BASE-MARKER-0123456789"),
            "from the orb's base"
        );
        assert!(
            !contains(&out, b"SECRET-MARKER-0123456789"),
            "the header's backing file was not read"
        );

        // An overlay keeping its data in another file is refused before any tool runs.
        let external = d.join("external.qcow2");
        sh(&format!(
            "qemu-img create -q -f qcow2 -o data_file={},data_file_raw=on {} 32M",
            d.join("external.raw").display(),
            external.display()
        ));
        let out2 = d.join("out2.raw");
        std::fs::File::create(&out2)
            .unwrap()
            .set_len(32 << 20)
            .unwrap();
        let err = qcow2_to_raw(&tools, &ctx, Path::new("qemu-img"), &external, &base, &out2)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("external data file"), "{err}");
        assert!(!contains(&out2, b"SECRET-MARKER-0123456789"));
        assert_eq!(std::fs::read(&secret).unwrap().len(), 32 << 20, "untouched");
    }
}
