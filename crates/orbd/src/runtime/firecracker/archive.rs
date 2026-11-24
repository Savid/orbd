//! Archived disks: the disk of an orb stopped long enough (no VMM, no memory checkpoint)
//! is compressed in place with `zstd`, and restored before its next cold boot.
//!
//! ```text
//! <orb>/disk.raw                the disk (absent while archived)
//! <orb>/disk.raw.zst            the archive (complete once renamed from its .tmp)
//! <orb>/archive.json            sizes and time of the archive
//! <orb>/disk.raw.zst.tmp        an archive being written (the disk is still there)
//! <orb>/disk.raw.<job>.tmp      a restore being written (the archive is still there)
//! ```
//!
//! One of `disk.raw` and `disk.raw.zst` is always complete: an archive is written,
//! fsynced, checked (`zstd -t`) and renamed into place before the disk is removed; a
//! restore the same way round. With both present the disk wins (the archive, written
//! from it, is removed). Leftover `.tmp` files are removed when the runtime starts,
//! before anything can be writing them. `zstd` only reads and writes bytes (it never
//! interprets the guest's filesystem), so it runs as the agent; an archive runs at idle
//! CPU and I/O priority.
//!
//! Neither takes the filesystem below the agent's disk reserve: an archive is stopped
//! (the disk left as it was) when the free space would go below it or when it would not
//! shrink the disk below [`WORTH`] of its allocation; a restore starts only if what it
//! writes fits above the reserve after the restores already running ([`Restores`]).
//!
//! On a filesystem with reflinks an orb's disk shares its base's blocks, so archiving
//! frees only the orb's own and a restore writes a full, unshared copy: there an orb is
//! archived only once its base (prepared image or project snapshot) is gone.
//!
//! An archive runs under the orb's lock and stops promptly when cancelled (a command for
//! the orb arrived). A restore can take minutes for a big disk, longer than an
//! operation may: it runs in the background, without the lock; the spawn that started it
//! waits for it as long as its deadline allows and otherwise fails as retryable
//! (`DiskNotReady`), and the next spawn waits for the same restore.

use super::FirecrackerRuntime;
use crate::model::{GIB, OrbId, unix_ms_now};
use crate::runtime::vm::fsutil::{fsync_dir, read_json, write_json_atomic};
use crate::runtime::vm::{bounded, io_err, log, on_path};
use crate::runtime::{ArchiveInfo, OpContext, RuntimeError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const ARCHIVE: &str = "disk.raw.zst";
const ARCHIVE_TMP: &str = "disk.raw.zst.tmp";
const ARCHIVE_META: &str = "archive.json";
/// What a spawn keeps from its deadline for booting and bootstrapping after a restore.
const BOOT_RESERVE: Duration = Duration::from_secs(90);
/// How long a delete waits for a cancelled restore to stop.
const CANCEL_WAIT: Duration = Duration::from_secs(10);
/// zstd's level: fast (about 1 GB/s per thread), and it shrinks an orb's disk about 3x.
const LEVEL: &str = "-1";
/// An archive larger than this share of the disk's allocation is not worth keeping.
pub(super) const WORTH: f64 = 0.8;
/// Free space kept beyond the reserve while archiving or restoring.
const MARGIN: u64 = GIB;
/// How often a running archive checks its size and the free space.
const POLL: Duration = Duration::from_secs(2);

/// Restores running in the background, by orb, with what each still writes. A restore
/// removes itself when it ends; whoever waits on it holds the job and sees its result.
pub(super) type Restores = Arc<std::sync::Mutex<std::collections::HashMap<OrbId, Arc<RestoreJob>>>>;

/// A restore running in the background.
pub(super) struct RestoreJob {
    cancel: CancellationToken,
    done: tokio::sync::watch::Receiver<Option<Result<(), String>>>,
    tmp: PathBuf,
    disk_bytes: u64,
    /// What it writes in all (the disk's allocation when archived).
    allocated_bytes: u64,
}

impl RestoreJob {
    fn written(&self) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&self.tmp).map_or(0, |m| m.blocks().saturating_mul(512))
    }

    fn progress(&self) -> String {
        let gib = |b: u64| b as f64 / GIB as f64;
        let at = std::fs::metadata(&self.tmp).map_or(0, |m| m.len());
        format!(
            "restoring the orb's archived disk ({:.1} of {:.1} GiB); try again shortly",
            gib(at.min(self.disk_bytes)),
            gib(self.disk_bytes)
        )
    }
}

/// Removes what interrupted archives and restores left in every orb directory under
/// `state_dir`; with both a disk and an archive, the archive. Only when nothing can be
/// writing them: as the runtime starts.
pub(super) fn recover(state_dir: &Path) {
    for e in std::fs::read_dir(state_dir.join("orbs"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let dir = e.path();
        let mut changed = false;
        for f in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = f.file_name().to_string_lossy().into_owned();
            if name.starts_with("disk.raw.") && name.ends_with(".tmp") {
                tracing::info!(dir = %dir.display(), file = %name, "removed an interrupted archive or restore");
                changed |= std::fs::remove_file(f.path()).is_ok();
            }
        }
        if dir.join("disk.raw").is_file() {
            for f in [ARCHIVE, ARCHIVE_META] {
                changed |= std::fs::remove_file(dir.join(f)).is_ok();
            }
        }
        if changed {
            let _ = fsync_dir(&dir);
        }
    }
}

/// Lowers the calling process's CPU and I/O priority to idle (in a child, before exec).
fn idle_priority() -> std::io::Result<()> {
    // SAFETY: plain syscalls on the calling process; failures leave the priority as is.
    #[cfg(target_os = "linux")]
    unsafe {
        nix::libc::setpriority(nix::libc::PRIO_PROCESS, 0, 19);
        // ioprio_set(IOPRIO_WHO_PROCESS, self, IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT).
        nix::libc::syscall(nix::libc::SYS_ioprio_set, 1, 0, 3 << 13);
    }
    Ok(())
}

/// Runs blocking file work (fsyncs, renames of GiB files) off the async workers.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T, RuntimeError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| RuntimeError::Other(e.to_string()))?
        .map_err(io_err)
}

impl FirecrackerRuntime {
    fn zstd(&self) -> Result<PathBuf, RuntimeError> {
        on_path(Path::new("zstd"))
            .ok_or_else(|| RuntimeError::Unsupported("zstd is not installed".into()))
    }

    /// The orb's archive, if its disk is archived (an archive and no disk).
    pub(super) fn archive_info(&self, orb: OrbId) -> Option<ArchiveInfo> {
        let dir = self.orb_paths(orb).dir;
        if dir.join("disk.raw").exists() || !dir.join(ARCHIVE).is_file() {
            return None;
        }
        let mut info: ArchiveInfo = read_json(&dir.join(ARCHIVE_META)).ok().flatten()?;
        info.restoring = self
            .restores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&orb);
        Some(info)
    }

    /// What the restores running still write.
    pub(super) fn restoring_bytes(&self) -> u64 {
        self.restores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|j| j.allocated_bytes.saturating_sub(j.written()))
            .sum()
    }

    /// Whether the orb's disk was made from a base that is still on this host (so on a
    /// filesystem with reflinks the two share blocks).
    fn base_present(&self, orb: OrbId) -> bool {
        let Ok(recipe) = self.read_recipe(orb) else {
            return false;
        };
        let dir = match &recipe.source {
            super::DiskSource::Image { key, .. } => self.state_dir.join("images").join(key),
            super::DiskSource::ProjectSnapshot { key } => {
                self.state_dir.join("projects").join(key.as_str())
            }
        };
        dir.is_dir()
    }

    /// Compresses the disk of the stopped orb (no VMM, no checkpoint), the caller
    /// holding the orb's lock. None if it is not worth it or not possible now (see the
    /// module docs).
    pub(super) async fn archive_locked(
        &self,
        orb: OrbId,
        ctx: &OpContext,
    ) -> Result<Option<ArchiveInfo>, RuntimeError> {
        let dir = self.orb_paths(orb).dir;
        let disk = dir.join("disk.raw");
        if !disk.is_file()
            || self
                .restores
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&orb)
        {
            return Ok(None);
        }
        if crate::runtime::vm::reflink::expected() && self.base_present(orb) {
            tracing::debug!(%orb, "not archived: its disk shares blocks with its base");
            return Ok(None);
        }
        let zstd = self.zstd()?;
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&disk).map_err(io_err)?;
        let (disk_bytes, allocated) = (m.len(), m.blocks().saturating_mul(512));
        let floor = self.config.disk_reserve + MARGIN;
        let free = crate::runtime::vm::fsutil::free_bytes(&dir).map_err(io_err)?;
        // The archive is written before the disk is removed: about a third of it, at
        // most WORTH of it (beyond that it is stopped).
        if free < floor + allocated / 3 {
            return Err(RuntimeError::InsufficientDisk(format!(
                "archiving needs about {} MiB above the reserve, {} MiB free",
                (allocated / 3) >> 20,
                free.saturating_sub(self.config.disk_reserve) >> 20
            )));
        }
        let tmp = dir.join(ARCHIVE_TMP);
        let _ = std::fs::remove_file(&tmp);
        let started = Instant::now();
        log(
            ctx,
            &format!("archiving the disk ({} MiB)", allocated >> 20),
        );
        let limit = (allocated as f64 * WORTH) as u64;
        let written = compress(&zstd, &disk, &tmp, limit, floor, ctx).await;
        let compressed = match written {
            Ok(n) if !ctx.cancel.is_cancelled() => n,
            Ok(_) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(RuntimeError::Cancelled);
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        };
        let info = ArchiveInfo {
            archived_unix_ms: unix_ms_now(),
            compressed_bytes: compressed,
            allocated_bytes: allocated,
            disk_bytes,
            restoring: false,
        };
        let (d, t) = (dir.clone(), tmp.clone());
        let published = blocking(move || {
            write_json_atomic(&d.join(ARCHIVE_META), &info)?;
            std::fs::rename(&t, d.join(ARCHIVE))?;
            fsync_dir(&d)
        })
        .await;
        if let Err(e) = published {
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(dir.join(ARCHIVE_META));
            return Err(e);
        }
        crate::crash_point!("firecracker::archive::after_rename");
        let d = dir.clone();
        blocking(move || {
            std::fs::remove_file(d.join("disk.raw"))?;
            fsync_dir(&d)
        })
        .await?;
        log(
            ctx,
            &format!(
                "disk archived: {} MiB into {} MiB in {} s",
                allocated >> 20,
                compressed >> 20,
                started.elapsed().as_secs()
            ),
        );
        Ok(Some(info))
    }

    /// Makes sure the orb's disk is there, the caller holding the orb's lock: restores
    /// an archived one (see the module docs), waiting as long as `ctx` allows.
    pub(super) async fn ensure_disk(
        &self,
        orb: OrbId,
        ctx: &OpContext,
    ) -> Result<(), RuntimeError> {
        let dir = self.orb_paths(orb).dir;
        if dir.join("disk.raw").is_file() || !dir.join(ARCHIVE).is_file() {
            return Ok(());
        }
        let job = self.restore_job(orb)?;
        let wait_until = ctx
            .work_deadline
            .checked_sub(BOOT_RESERVE)
            .unwrap_or_else(Instant::now)
            .max(Instant::now() + Duration::from_secs(5))
            .min(ctx.work_deadline);
        let mut done = job.done.clone();
        let finished = async {
            loop {
                if let Some(r) = done.borrow_and_update().clone() {
                    return r;
                }
                if done.changed().await.is_err() {
                    return Err("the restore stopped".into());
                }
            }
        };
        let r = tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => return Err(RuntimeError::Cancelled),
            r = finished => r,
            _ = tokio::time::sleep_until(wait_until.into()) => {
                return Err(RuntimeError::DiskNotReady(job.progress()));
            }
        };
        match r {
            Ok(()) => {
                log(ctx, "archived disk restored");
                Ok(())
            }
            Err(e) => Err(RuntimeError::Other(format!(
                "restoring the archived disk: {e}"
            ))),
        }
    }

    /// The orb's running restore, or a new one if what it writes fits above the reserve
    /// after the restores already running.
    fn restore_job(&self, orb: OrbId) -> Result<Arc<RestoreJob>, RuntimeError> {
        if let Some(j) = self
            .restores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&orb)
        {
            return Ok(j.clone());
        }
        let zstd = self.zstd()?;
        let dir = self.orb_paths(orb).dir;
        let info: ArchiveInfo = read_json(&dir.join(ARCHIVE_META))
            .map_err(io_err)?
            .ok_or_else(|| RuntimeError::Other("the archive has no archive.json".into()))?;
        let free = crate::runtime::vm::fsutil::free_bytes(&dir).map_err(io_err)?;
        let committed = self.restoring_bytes();
        let need = info.allocated_bytes + self.config.disk_reserve + MARGIN + committed;
        if free < need {
            return Err(RuntimeError::InsufficientDisk(format!(
                "restoring the archived disk writes {} MiB; {} MiB free above the reserve \
                 and other restores",
                info.allocated_bytes >> 20,
                free.saturating_sub(need - info.allocated_bytes) >> 20
            )));
        }
        let mut jobs = self.restores.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(j) = jobs.get(&orb) {
            return Ok(j.clone());
        }
        let (tx, rx) = tokio::sync::watch::channel(None);
        let cancel = CancellationToken::new();
        let tmp = dir.join(format!("disk.raw.{}.tmp", uuid::Uuid::new_v4().simple()));
        let job = Arc::new(RestoreJob {
            cancel: cancel.clone(),
            done: rx,
            tmp: tmp.clone(),
            disk_bytes: info.disk_bytes,
            allocated_bytes: info.allocated_bytes,
        });
        jobs.insert(orb, job.clone());
        drop(jobs);
        tracing::info!(%orb, allocated_bytes = info.allocated_bytes, "restoring an archived disk");
        let (restores, this) = (self.restores.clone(), job.clone());
        tokio::spawn(async move {
            let started = Instant::now();
            let r = restore_files(&zstd, &dir, &tmp, info.disk_bytes, &cancel).await;
            match &r {
                Ok(()) => {
                    metrics::counter!("orbd_agent_disk_restores_total").increment(1);
                    tracing::info!(%orb, secs = started.elapsed().as_secs(), "archived disk restored");
                }
                Err(e) => tracing::warn!(%orb, error = %e, "restoring an archived disk failed"),
            }
            // Only this job removes itself, once nothing of it writes any more.
            {
                let mut jobs = restores.lock().unwrap_or_else(|e| e.into_inner());
                if jobs.get(&orb).is_some_and(|j| Arc::ptr_eq(j, &this)) {
                    jobs.remove(&orb);
                }
            }
            let _ = tx.send(Some(r));
        });
        Ok(job)
    }

    /// Stops the orb's restore, if any, and waits for it to end (before a delete).
    pub(super) async fn cancel_restore(&self, orb: OrbId) {
        let job = self
            .restores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&orb)
            .cloned();
        if let Some(job) = job {
            job.cancel.cancel();
            let mut done = job.done.clone();
            let _ = tokio::time::timeout(CANCEL_WAIT, done.wait_for(|d| d.is_some())).await;
        }
    }
}

/// Compresses `disk` into the new file `tmp` at idle priority, then checks it
/// (`zstd -t`); returns its size. Stops (killing zstd) when `ctx` is cancelled, when
/// the archive passes `limit` bytes (not worth it) or when the filesystem's free space
/// falls below `floor`.
async fn compress(
    zstd: &Path,
    disk: &Path,
    tmp: &Path,
    limit: u64,
    floor: u64,
    ctx: &OpContext,
) -> Result<u64, RuntimeError> {
    use std::os::unix::fs::OpenOptionsExt;
    let input = std::fs::File::open(disk).map_err(io_err)?;
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .map_err(io_err)?;
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(4));
    let mut cmd = tokio::process::Command::new(zstd);
    cmd.args([LEVEL, &format!("-T{threads}"), "-q", "-c"])
        .stdin(input)
        .stdout(output.try_clone().map_err(io_err)?)
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    // SAFETY: idle_priority only makes syscalls on the child itself.
    unsafe { cmd.pre_exec(idle_priority) };
    // Not `output()`: it would pipe stdout (the archive) into memory.
    let child = cmd
        .spawn()
        .map_err(|e| RuntimeError::Other(format!("zstd: {e}")))?;
    let dir = tmp.parent().unwrap_or(Path::new("/")).to_owned();
    let watch = async {
        loop {
            tokio::time::sleep(POLL).await;
            let size = std::fs::metadata(tmp).map_or(0, |m| m.len());
            if size > limit {
                return RuntimeError::Unsupported(format!(
                    "not worth archiving: past {} MiB, {:.0}% of the disk's allocation",
                    size >> 20,
                    WORTH * 100.0
                ));
            }
            if crate::runtime::vm::fsutil::free_bytes(&dir).is_ok_and(|f| f < floor) {
                return RuntimeError::InsufficientDisk(
                    "archiving stopped: the filesystem reached the agent's disk reserve".into(),
                );
            }
        }
    };
    let out = tokio::select! {
        out = bounded(ctx, child.wait_with_output()) => out?,
        stop = watch => return Err(stop),
    }
    .map_err(|e| RuntimeError::Other(format!("zstd: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(if err.contains("No space left") {
            RuntimeError::InsufficientDisk(format!("zstd: {}", err.trim()))
        } else {
            RuntimeError::Other(format!("zstd: {} {}", out.status, err.trim()))
        });
    }
    let size = blocking(move || {
        output.sync_all()?;
        Ok(output.metadata()?.len())
    })
    .await?;
    // Read back before the disk goes: the archive must decompress, checksums and all.
    let check = tokio::process::Command::new(zstd)
        .args(["-t", "-q"])
        .arg(tmp)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| RuntimeError::Other(format!("zstd -t: {e}")))?;
    let checked = bounded(ctx, check.wait_with_output())
        .await?
        .map_err(|e| RuntimeError::Other(format!("zstd -t: {e}")))?;
    if !checked.status.success() {
        return Err(RuntimeError::Other(format!(
            "zstd -t: the archive does not check: {}",
            String::from_utf8_lossy(&checked.stderr).trim()
        )));
    }
    Ok(size)
}

/// Decompresses `dir`'s archive into the sparse file `tmp`, then renames it into place
/// as the disk (unless cancelled first) and removes the archive.
async fn restore_files(
    zstd: &Path,
    dir: &Path,
    tmp: &Path,
    disk_bytes: u64,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let (archive, disk) = (dir.join(ARCHIVE), dir.join("disk.raw"));
    let _ = std::fs::remove_file(tmp);
    let input = std::fs::File::open(&archive).map_err(|e| e.to_string())?;
    let child = tokio::process::Command::new(zstd)
        .args(["-d", "-q", "-f", "--sparse", "-o"])
        .arg(tmp)
        .stdin(input)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("zstd: {e}"))?
        .wait_with_output();
    let out = tokio::select! {
        _ = cancel.cancelled() => {
            let _ = std::fs::remove_file(tmp);
            return Err("cancelled".into());
        }
        o = child => o.map_err(|e| format!("zstd: {e}"))?,
    };
    let (t, d, c) = (tmp.to_owned(), dir.to_owned(), cancel.clone());
    let finished = tokio::task::spawn_blocking(move || {
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "zstd: {} {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        use std::os::unix::fs::PermissionsExt;
        let f = std::fs::OpenOptions::new().write(true).open(&t)?;
        let len = f.metadata()?.len();
        if len > disk_bytes {
            return Err(std::io::Error::other(format!(
                "the restored disk has {len} bytes, the archive says {disk_bytes}"
            )));
        }
        // A trailing run of zeros is a hole zstd may not extend the file over.
        f.set_len(disk_bytes)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.sync_all()?;
        if c.is_cancelled() {
            return Err(std::io::Error::other("cancelled"));
        }
        std::fs::rename(&t, d.join("disk.raw"))?;
        fsync_dir(&d)
    })
    .await
    .map_err(|e| e.to_string())?;
    if let Err(e) = finished {
        let _ = std::fs::remove_file(tmp);
        return Err(e.to_string());
    }
    let _ = disk;
    crate::crash_point!("firecracker::restore_disk::after_rename");
    for f in [ARCHIVE, ARCHIVE_META] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    let _ = fsync_dir(dir);
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// A restore leaves the disk as it was archived: same bytes, same size, sparse
    /// where the disk was zero; and a cancelled one leaves the archive and no disk.
    #[tokio::test]
    async fn restores_are_exact_sparse_and_cancellable() {
        let Some(zstd) = on_path(Path::new("zstd")) else {
            eprintln!("skipped: no zstd");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // 64 MiB with data at both ends and a hole between.
        let disk = d.join("disk.raw");
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::File::create(&disk).unwrap();
            f.write_all(&[7u8; 1 << 20]).unwrap();
            f.seek(SeekFrom::Start(48 << 20)).unwrap();
            f.write_all(b"end of the data").unwrap();
            f.set_len(64 << 20).unwrap();
        }
        let want = std::fs::read(&disk).unwrap();
        let st = std::process::Command::new(&zstd)
            .args(["-q", "-1", "-o"])
            .arg(d.join(ARCHIVE))
            .arg(&disk)
            .status()
            .unwrap();
        assert!(st.success());
        std::fs::remove_file(&disk).unwrap();
        restore_files(
            &zstd,
            d,
            &d.join("disk.raw.t.tmp"),
            64 << 20,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&disk).unwrap(), want);
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&disk).unwrap();
        assert!(
            m.blocks() * 512 < 16 << 20,
            "sparse: {} bytes",
            m.blocks() * 512
        );
        assert!(!d.join(ARCHIVE).exists() && !d.join("disk.raw.t.tmp").exists());

        // Cancelled before it starts: nothing replaces the archive.
        std::fs::remove_file(&disk).unwrap();
        std::fs::write(d.join(ARCHIVE), b"not used").unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            restore_files(&zstd, d, &d.join("disk.raw.t.tmp"), 64 << 20, &cancel)
                .await
                .is_err()
        );
        assert!(d.join(ARCHIVE).exists() && !disk.exists() && !d.join("disk.raw.t.tmp").exists());
    }

    fn ctx() -> OpContext {
        let (log, _) = tokio::sync::mpsc::channel(16);
        OpContext {
            operation_id: crate::model::OperationId::generate(),
            generation: 1,
            work_deadline: Instant::now() + Duration::from_secs(60),
            cleanup_deadline: Instant::now() + Duration::from_secs(60),
            cancel: CancellationToken::new(),
            log,
        }
    }

    /// What `compress` writes, `restore_files` turns back into the same disk; a
    /// cancelled compression stops.
    #[tokio::test]
    async fn compressed_disks_restore_byte_for_byte() {
        let Some(zstd) = on_path(Path::new("zstd")) else {
            eprintln!("skipped: no zstd");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let disk = d.join("disk.raw");
        // 32 MiB: text that compresses, then a hole, then random bytes.
        let mut data: Vec<u8> = (0..(8u32 << 20))
            .map(|i| b"orbd disk "[(i % 10) as usize])
            .collect();
        data.resize(24 << 20, 0);
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        data.extend((0..(8u32 << 20)).map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        }));
        std::fs::write(&disk, &data).unwrap();
        let n = compress(&zstd, &disk, &d.join(ARCHIVE), u64::MAX, 0, &ctx())
            .await
            .unwrap();
        // The random part does not compress; the rest nearly vanishes.
        assert!(n > 8 << 20 && n < 9 << 20, "compressed to {n} bytes");
        std::fs::remove_file(&disk).unwrap();
        restore_files(
            &zstd,
            d,
            &d.join("disk.raw.t.tmp"),
            data.len() as u64,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(
            std::fs::read(&disk).unwrap() == data,
            "restored byte for byte"
        );

        let cancelled = ctx();
        cancelled.cancel.cancel();
        let tmp = d.join(ARCHIVE_TMP);
        assert!(matches!(
            compress(&zstd, &disk, &tmp, u64::MAX, 0, &cancelled).await,
            Err(RuntimeError::Cancelled)
        ));
    }

    /// Startup recovery: leftover temporaries go, and so does an archive beside its disk.
    #[test]
    fn recovery_keeps_one_complete_copy() {
        let state = tempfile::tempdir().unwrap();
        let (a, b) = (state.path().join("orbs/a"), state.path().join("orbs/b"));
        for d in [&a, &b] {
            std::fs::create_dir_all(d).unwrap();
        }
        for f in ["disk.raw", ARCHIVE, ARCHIVE_META, ARCHIVE_TMP] {
            std::fs::write(a.join(f), b"x").unwrap();
        }
        for f in [ARCHIVE, ARCHIVE_META, "disk.raw.0123.tmp"] {
            std::fs::write(b.join(f), b"x").unwrap();
        }
        recover(state.path());
        let names = |d: &Path| {
            let mut v: Vec<String> = std::fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        };
        assert_eq!(names(&a), ["disk.raw"]);
        assert_eq!(names(&b), [ARCHIVE_META, ARCHIVE]);
    }
}
