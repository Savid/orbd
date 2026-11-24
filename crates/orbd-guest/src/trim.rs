//! Returns the root filesystem's free blocks to the host before a sleep (`FITRIM`, as
//! `fstrim /` does): on a VM whose disk supports discard, the host punches them out of
//! the disk file, so space the guest freed (deleted build output, caches) stops holding
//! host disk, and the host's SSD learns those blocks are free. ext4 trims only block
//! groups with frees since its last trim, so after the first trim of a boot it is quick.
//!
//! Bounded: the host waits on the sleep, so the trim runs on its own thread and the
//! sleep goes on after [`WAIT`] whether or not it finished (an unfinished trim simply
//! continues after the wake). At most one runs at a time.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// The longest a sleep waits for the trim.
pub const WAIT: Duration = Duration::from_secs(5);

/// `FITRIM`: `_IOWR('X', 121, struct fstrim_range)`.
const FITRIM: libc::c_ulong = 0xC018_5879;

#[repr(C)]
struct FstrimRange {
    start: u64,
    len: u64,
    minlen: u64,
}

static RUNNING: AtomicBool = AtomicBool::new(false);

/// Trims `/`, waiting at most `wait` (and [`WAIT`]). Returns what to log, and whether
/// the trim finished.
pub fn root(wait: Duration) -> (String, bool) {
    trim("/", wait.min(WAIT))
}

fn trim(path: &'static str, wait: Duration) -> (String, bool) {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return ("a trim is still running".into(), false);
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = fitrim(path);
        RUNNING.store(false, Ordering::SeqCst);
        let _ = tx.send(r);
    });
    match rx.recv_timeout(wait) {
        Ok(Ok(bytes)) => (format!("trimmed {} MiB", bytes >> 20), true),
        Ok(Err(e)) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            ("the disk does not support discard".into(), true)
        }
        Ok(Err(e)) => (format!("trim failed: {e}"), true),
        Err(_) => (
            format!("trim still running after {}s", wait.as_secs()),
            false,
        ),
    }
}

/// Trims the filesystem holding `path`; returns the bytes the filesystem discarded.
fn fitrim(path: &str) -> std::io::Result<u64> {
    use std::os::fd::AsRawFd;
    let dir = std::fs::File::open(path)?;
    let mut range = FstrimRange {
        start: 0,
        len: u64::MAX,
        minlen: 0,
    };
    // SAFETY: FITRIM reads and writes one fstrim_range, which outlives the call.
    let r = unsafe { libc::ioctl(dir.as_raw_fd(), FITRIM as _, &mut range as *mut FstrimRange) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(range.len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trim of a filesystem that cannot be trimmed (or that this test may not trim)
    /// reports why instead of failing the sleep, and never blocks past its wait.
    #[test]
    fn a_trim_reports_and_never_blocks_the_sleep() {
        let started = std::time::Instant::now();
        let (msg, _) = trim("/proc", Duration::from_secs(2));
        assert!(started.elapsed() < Duration::from_secs(3), "{msg}");
        assert!(!msg.is_empty());
        assert!(!RUNNING.load(Ordering::SeqCst) || msg.contains("still running"));
    }
}
