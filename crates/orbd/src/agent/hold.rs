//! Sleeps held in RAM (`ORBD_SLEEP_HOLD_MINUTES`, on by default; see
//! `runtime::firecracker::hold`). A pause the executor lets hold leaves the orb's VM
//! paused with its memory, reported asleep: a wake within the hold resumes it in place
//! and writes nothing, where a sleep otherwise writes the orb's whole memory to disk.
//!
//! A pause holds only if ([`may_hold`]) the guest synced its disk, the host would still
//! fit another orb of its size, the held sleeps' checkpoints would still fit on disk
//! above the reserve, and all held memory stays within what a graceful stop can write
//! ([`max_held`]), counting the holds other pauses are about to make ([`reserve`]). Held memory counts against the agent's capacity at admission, and
//! held checkpoints count as committed disk (not free) for admission and placement.
//!
//! A held sleep's checkpoint is written (the hold "flushed"), each on the orb's actor so
//! it never races the orb's own commands:
//!
//! * when the hold has lasted the setting (checked every [`EVERY`]; with the setting 0,
//!   at once, as for holds adopted after a restart with it turned off), unless a command
//!   for the orb is under way or its last write failed lately ([`BACKOFF`]);
//! * when the host's available memory, less its reserve, would not fit the largest orb
//!   it runs or holds: oldest holds first;
//! * when an orb being admitted needs the memory or capacity ([`make_room`]);
//! * on a graceful stop, in one queue with the running orbs' saves, smallest first.
//!
//! A write that cannot fit on disk, or fails during a graceful stop, drops the hold
//! instead (the VMM is killed; the guest synced its disk before the pause): the orb is
//! recorded stopped without a checkpoint. A held VMM that ended (killed, the host's OOM
//! killer, which prefers held VMMs) lost only RAM and is recorded the same way.

use super::maintenance::{Outcome, Task};
use super::{Shared, db, executor, session};
use crate::model::{
    GIB, OrbDefinition, OrbId, OrbState, SleepCheckpointRef, StableOrbState, unix_ms_now,
};
use crate::runtime::{FlushOutcome, HeldSleep, Runtime, RuntimeError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// How often holds are checked.
const EVERY: Duration = Duration::from_secs(30);
/// How long a hold's expiry waits after its write failed.
const BACKOFF: Duration = Duration::from_secs(600);
/// The most memory ever held at once (see [`max_held`]).
pub const MAX_HELD: u64 = 16 * GIB;
/// The part of a graceful stop's budget held sleeps may take to write.
const DRAIN_SHARE: Duration = Duration::from_secs(120);
/// Disk kept free beyond a held checkpoint and the reserve.
const DISK_MARGIN: u64 = GIB;

/// Whether a pause of an orb with `memory` bytes may hold its sleep: the host's
/// `available` memory less its `reserve` still fits the `largest` orb it runs or holds
/// (this one included; the same rule the periodic check writes holds by), all held
/// memory (`held`, reservations included, plus this) stays within `max_held`, and every
/// held checkpoint, this one included, fits in `disk_room` (free disk above the reserve,
/// less what is committed).
pub fn may_hold(
    memory: u64,
    available: Option<u64>,
    reserve: u64,
    largest: u64,
    held: u64,
    max_held: u64,
    disk_room: u64,
) -> bool {
    let memory_ok = available.is_none_or(|a| a.saturating_sub(reserve) >= largest.max(memory));
    memory_ok
        && held.saturating_add(memory) <= max_held
        && disk_room >= memory.saturating_add(DISK_MARGIN)
}

/// The most memory held at once: what a graceful stop can write in half its budget at
/// the save speed measured on this host (100 MiB/s until one was), between 2 GiB and
/// [`MAX_HELD`].
pub(super) fn max_held(sh: &Shared) -> u64 {
    let rate = match sh.save_rate.load(std::sync::atomic::Ordering::Relaxed) {
        0 => 100 << 20,
        r => r,
    };
    rate.saturating_mul(DRAIN_SHARE.as_secs())
        .clamp(2 * GIB, MAX_HELD)
}

/// Records a checkpoint write of `bytes` that took `took`, for [`max_held`].
pub(super) fn note_save(sh: &Shared, bytes: u64, took: Duration) {
    let ms = took.as_millis().max(1) as u64;
    let rate = bytes.saturating_mul(1000) / ms;
    let old = sh.save_rate.load(std::sync::atomic::Ordering::Relaxed);
    let new = match old {
        0 => rate,
        o => (o * 3 + rate) / 4,
    };
    sh.save_rate
        .store(new, std::sync::atomic::Ordering::Relaxed);
}

/// The largest orb this host runs or holds (memory).
fn largest_orb(sh: &Shared) -> u64 {
    sh.reserved
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .map(|r| r.memory_bytes)
        .chain(held(sh).iter().map(|h| h.memory_bytes))
        .max()
        .unwrap_or(0)
}

/// A pause's claim on the hold limits until it has held or not: other pauses count it,
/// so concurrent pauses cannot all hold past the limits.
pub(super) struct Reservation<'a> {
    sh: &'a Shared,
    bytes: u64,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        let mut p = self
            .sh
            .hold_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *p = p.saturating_sub(self.bytes);
    }
}

/// Reserves a hold of `memory` bytes if [`may_hold`] allows it, counting the holds and
/// the reservations of other pauses, under one lock.
pub(super) fn reserve(sh: &Shared, memory: u64) -> Option<Reservation<'_>> {
    let mut pending = sh.hold_pending.lock().unwrap_or_else(|e| e.into_inner());
    let held = sh.held_memory_bytes().saturating_add(*pending);
    let room = sh
        .disk_stats()
        .0
        .saturating_sub(held)
        .saturating_sub(sh.disk_reserve);
    let ok = may_hold(
        memory,
        sh.memory_available(),
        sh.memory_reserve,
        largest_orb(sh),
        held,
        max_held(sh),
        room,
    );
    ok.then(|| {
        *pending += memory;
        Reservation { sh, bytes: memory }
    })
}

/// Checks every [`EVERY`] until shutdown (see the module docs). Tests shorten the hold
/// and the interval (`agent::hold::window_secs`, `agent::hold::every_secs`).
pub(super) async fn run_loop(sh: Arc<Shared>) {
    if !sh.runtimes.values().any(|r| r.holds_sleeps()) {
        return;
    }
    let window = sh.config.agent.sleep_hold.unwrap_or(Duration::ZERO);
    let window = failpoint_secs("agent::hold::window_secs").unwrap_or(window);
    let every = failpoint_secs("agent::hold::every_secs").unwrap_or(EVERY);
    if !window.is_zero() {
        tracing::info!(
            minutes = window.as_secs() / 60,
            "sleeps are held in RAM this long before their checkpoints are written"
        );
    }
    loop {
        tokio::select! {
            _ = sh.shutdown.cancelled() => break,
            _ = sh.draining.cancelled() => break,
            _ = tokio::time::sleep(every) => {}
        }
        let now = unix_ms_now();
        let all = held(&sh);
        let mut flushing = Vec::new();
        for h in &all {
            // statm unreadable: the VMM is gone.
            if h.resident_bytes == 0 {
                flushing.push((h.orb, "gone"));
                continue;
            }
            let expired = now.saturating_sub(h.since_unix_ms) >= window.as_millis() as u64;
            let backing_off = sh
                .flush_backoff
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&h.orb)
                .is_some_and(|until| Instant::now() < *until);
            if expired && !backing_off {
                flushing.push((h.orb, "expired"));
            }
        }
        // Room for the largest orb this host runs or holds (as `may_hold`), oldest
        // holds first.
        if let Some(available) = sh.memory_available() {
            let largest = largest_orb(&sh);
            let mut room = available.saturating_sub(sh.memory_reserve);
            for h in &all {
                if room >= largest {
                    break;
                }
                if !flushing.iter().any(|(o, _)| *o == h.orb) {
                    flushing.push((h.orb, "memory"));
                }
                room = room.saturating_add(h.resident_bytes);
            }
        }
        for (orb, reason) in flushing {
            let sh = sh.clone();
            tokio::spawn(async move { flush(&sh, orb, reason).await });
        }
    }
}

/// A `return(<secs>)` failpoint's seconds, for tests.
#[cfg(feature = "failpoints")]
fn failpoint_secs(name: &str) -> Option<Duration> {
    fail::eval(name, |a| a.and_then(|a| a.parse::<u64>().ok()))
        .flatten()
        .map(Duration::from_secs)
}

#[cfg(not(feature = "failpoints"))]
fn failpoint_secs(_name: &str) -> Option<Duration> {
    None
}

/// Every held sleep, oldest first.
fn held(sh: &Shared) -> Vec<HeldSleep> {
    let mut v: Vec<HeldSleep> = sh.runtimes.values().flat_map(|r| r.held()).collect();
    v.sort_by_key(|h| h.since_unix_ms);
    v
}

/// Whether `orb` is held in RAM by its runtime.
pub(super) fn is_held(rt: &dyn Runtime, orb: OrbId) -> bool {
    rt.held().iter().any(|h| h.orb == orb)
}

fn still_held(sh: &Shared, orb: OrbId) -> bool {
    sh.runtimes
        .values()
        .any(|r| r.held().iter().any(|h| h.orb == orb))
}

/// Writes held sleeps, oldest first and other than `except`'s, while `short(0)` says the
/// host lacks memory or capacity for an orb being admitted; none if `short(freed)` with
/// every other hold written would still say so. Returns how many were written.
pub(super) async fn make_room(
    sh: &Arc<Shared>,
    except: OrbId,
    short: impl Fn(u64) -> bool,
) -> usize {
    let others: Vec<HeldSleep> = held(sh).into_iter().filter(|h| h.orb != except).collect();
    let all: u64 = others.iter().map(|h| h.resident_bytes).sum();
    if others.is_empty() || short(all) {
        return 0;
    }
    let mut written = 0;
    for h in others {
        if !short(0) {
            break;
        }
        tracing::info!(orb = %h.orb, for_orb = %except, "writing a sleep held in RAM: an orb being admitted needs the memory");
        if flush(sh, h.orb, "memory").await {
            written += 1;
        }
    }
    written
}

/// Queues a write of `orb`'s held sleep on its actor and waits for it; true once the
/// orb is no longer held. One at a time per orb; a second caller waits for the first.
pub(super) async fn flush(sh: &Arc<Shared>, orb: OrbId, reason: &'static str) -> bool {
    if !sh
        .flush_queued
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(orb)
    {
        while sh
            .flush_queued
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&orb)
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        return !still_held(sh, orb);
    }
    struct Unqueue<'a>(&'a Shared, OrbId);
    impl Drop for Unqueue<'_> {
        fn drop(&mut self) {
            self.0
                .flush_queued
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.1);
        }
    }
    let _unqueue = Unqueue(sh, orb);
    let def = match sh.db.call(move |c| db::get_orb_definition(c, orb)).await {
        Ok(Some(d)) => d,
        Ok(None) => return false,
        Err(e) => {
            tracing::warn!(%orb, error = %e, "held sleep: cannot read the orb");
            return false;
        }
    };
    let (tx, rx) = oneshot::channel();
    executor::enqueue_work(
        sh,
        orb,
        executor::Work::Maintenance(Box::new(def), Task::FlushHeld { reason }, tx),
    );
    match rx.await {
        Ok(Outcome::Failed(e)) => {
            tracing::warn!(%orb, reason, error = %e, "writing a sleep held in RAM failed; it stays held");
            sh.flush_backoff
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(orb, Instant::now() + BACKOFF);
            false
        }
        Ok(_) => {
            sh.flush_backoff
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&orb);
            !still_held(sh, orb)
        }
        Err(_) => false,
    }
}

/// The maintenance task, on the orb's actor: writes its held sleep; drops it if the
/// write cannot fit on disk or fails during a graceful stop; or records that the hold's
/// VMM is gone.
pub(super) async fn run(
    sh: &Arc<Shared>,
    rt: &dyn Runtime,
    orb: &OrbDefinition,
    reason: &'static str,
) -> Outcome {
    let id = orb.id;
    if reason != "drain" {
        // A command under way or queued decides (a wake resumes it in place).
        match sh.db.call(move |c| db::get_orb_claimed(c, id)).await {
            Ok(Some((_, true))) => return Outcome::Unchanged,
            Ok(_) => {}
            Err(e) => return Outcome::Failed(format!("database: {e}")),
        }
    }
    // The runtime gives the write its own budget once it may write; this bounds the
    // wait for that and anything after.
    let deadline = Instant::now() + Duration::from_secs(3600);
    let ctx = super::maintenance::context(id, 0, deadline, deadline);
    let generation = rt
        .held()
        .into_iter()
        .find(|h| h.orb == id)
        .map(|h| h.checkpoint);
    let memory = orb.spec.template.resources.memory_bytes;
    let started = Instant::now();
    match rt.flush_held(orb, &ctx).await {
        Ok(FlushOutcome::Written) => {
            note_save(sh, memory, started.elapsed());
            metrics::counter!("orbd_agent_held_flushes_total", "reason" => reason).increment(1);
            tracing::info!(orb = %id, reason, "wrote the checkpoint of a sleep held in RAM");
            Outcome::Flushed
        }
        Ok(FlushOutcome::NotHeld) => Outcome::Unchanged,
        Ok(FlushOutcome::Lost) => {
            record_lost(
                sh,
                id,
                "asleep in RAM, and its VM ended before its checkpoint was written; processes lost",
            )
            .await
        }
        Err(e @ RuntimeError::InsufficientDisk(_)) => {
            drop_hold(
                sh,
                rt,
                id,
                generation,
                &format!("its checkpoint does not fit on disk ({e})"),
                "disk",
            )
            .await
        }
        Err(e) if reason == "drain" => {
            drop_hold(
                sh,
                rt,
                id,
                generation,
                &format!("its checkpoint was not written as the agent stopped ({e})"),
                "drain",
            )
            .await
        }
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

/// Drops `orb`'s held sleep (its VMM is killed; the guest synced its disk) and records
/// the orb stopped without a checkpoint.
async fn drop_hold(
    sh: &Arc<Shared>,
    rt: &dyn Runtime,
    orb: OrbId,
    checkpoint: Option<SleepCheckpointRef>,
    why: &str,
    label: &'static str,
) -> Outcome {
    let Some(cp) = checkpoint else {
        return Outcome::Unchanged;
    };
    if let Err(e) = rt.discard_checkpoint(orb, &cp).await {
        return Outcome::Failed(format!("dropping the held sleep: {e}"));
    }
    metrics::counter!("orbd_agent_held_flushes_total", "reason" => format!("dropped_{label}"))
        .increment(1);
    tracing::warn!(%orb, "dropped a sleep held in RAM: {why}; the orb cold-boots from its synced disk");
    record_lost(
        sh,
        orb,
        &format!("asleep in RAM, dropped: {why}; processes lost"),
    )
    .await
}

/// Records an orb still recorded asleep, with nothing else under way, as stopped
/// without a checkpoint, and reports it.
async fn record_lost(sh: &Arc<Shared>, orb: OrbId, reason: &str) -> Outcome {
    let state = OrbState::known(StableOrbState::DiskOnlyStopped {
        reason: reason.into(),
    });
    let recorded = sh
        .db
        .call(move |c| match db::get_orb_claimed(c, orb)? {
            Some((row, false))
                if matches!(
                    row.last_state,
                    Some(OrbState::Known {
                        state: StableOrbState::Sleeping { .. }
                    })
                ) =>
            {
                db::set_last_state(c, orb, &state)?;
                db::get_orb(c, orb)
            }
            _ => Ok(None),
        })
        .await;
    match recorded {
        Ok(Some(row)) => {
            sh.send_control(session::orb_report_event(&row));
            Outcome::Recorded
        }
        Ok(None) => Outcome::Unchanged,
        Err(e) => Outcome::Failed(format!("database: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pause holds only with room for another orb of its size, within the cap on held
    /// memory, and with its checkpoint fitting on disk.
    #[test]
    fn holds_need_memory_disk_and_room_under_the_cap() {
        let g = GIB;
        let cap = 16 * g;
        let ok = |memory, available, largest, held, room| {
            may_hold(memory, available, 4 * g, largest, held, cap, room)
        };
        assert!(ok(4 * g, Some(20 * g), 4 * g, 0, 40 * g));
        assert!(
            !ok(4 * g, Some(7 * g), 4 * g, 0, 40 * g),
            "no room for another"
        );
        assert!(
            !ok(4 * g, Some(10 * g), 8 * g, 0, 40 * g),
            "no room for the largest"
        );
        assert!(ok(4 * g, None, 4 * g, 0, 40 * g), "memory not bounding");
        assert!(
            !ok(4 * g, Some(64 * g), 4 * g, cap - 2 * g, 40 * g),
            "over the cap"
        );
        assert!(
            ok(4 * g, Some(64 * g), 4 * g, cap - 4 * g, 40 * g),
            "at the cap"
        );
        assert!(
            !ok(4 * g, Some(64 * g), 4 * g, 0, 4 * g),
            "its checkpoint must fit"
        );
        assert!(ok(4 * g, Some(64 * g), 4 * g, 0, 5 * g));
    }

    /// Concurrent pauses each count the others' reservations: together they never
    /// pass the cap.
    #[test]
    fn concurrent_reservations_respect_the_cap() {
        let g = GIB;
        let pending = std::sync::Mutex::new(0u64);
        let granted = std::sync::atomic::AtomicU64::new(0);
        std::thread::scope(|s| {
            for _ in 0..16 {
                s.spawn(|| {
                    let mut p = pending.lock().unwrap();
                    if may_hold(4 * g, None, 0, 4 * g, *p, 16 * g, u64::MAX) {
                        *p += 4 * g;
                        granted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(granted.into_inner(), 4, "16 GiB of 4 GiB holds");
    }
}
