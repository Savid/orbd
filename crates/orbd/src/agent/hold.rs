//! Sleeps held in RAM (`ORBD_SLEEP_HOLD_MINUTES`, on by default; see
//! `runtime::firecracker::hold`). A pause the executor lets hold leaves the orb's VM
//! paused with its memory, reported asleep: a wake within the hold resumes it in place
//! and writes nothing, where a sleep otherwise writes the orb's whole memory to disk.
//!
//! A pause holds only if ([`may_hold`]) the guest synced its disk, the host would still
//! fit another orb of its size, the held sleeps' checkpoints would still fit on disk
//! above the reserve, and all held memory stays within what a graceful stop can write
//! ([`MAX_HELD`]). Held memory counts against the agent's capacity at admission, and
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
//! * first thing on a graceful stop ([`flush_all`]).
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
/// The most memory held at once: what a graceful stop (280 s) can write at about
/// 100 MiB/s with time to spare, so a stop never leaves held sleeps unwritten.
pub const MAX_HELD: u64 = 16 * GIB;
/// Disk kept free beyond a held checkpoint and the reserve.
const DISK_MARGIN: u64 = GIB;

/// Whether a pause of an orb with `memory` bytes may hold its sleep: the host's
/// `available` memory less its `reserve` still fits another such orb, all held memory
/// (`held` plus this) stays within [`MAX_HELD`], and every held checkpoint, this one
/// included, fits in `disk_room` (free disk above the reserve, less what is committed).
pub fn may_hold(
    memory: u64,
    available: Option<u64>,
    reserve: u64,
    held: u64,
    disk_room: u64,
) -> bool {
    let memory_ok = available.is_none_or(|a| a.saturating_sub(reserve) >= memory);
    memory_ok
        && held.saturating_add(memory) <= MAX_HELD
        && disk_room >= memory.saturating_add(DISK_MARGIN)
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
        // Room for the largest orb this host runs or holds, oldest holds first.
        if let Some(available) = sh.memory_available() {
            let largest = sh
                .reserved
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .map(|r| r.memory_bytes)
                .chain(all.iter().map(|h| h.memory_bytes))
                .max()
                .unwrap_or(0);
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

/// Writes held sleeps, oldest first and other than `except`'s, while `short()` says the
/// host lacks memory or capacity for an orb being admitted. Returns how many were
/// written.
pub(super) async fn make_room(sh: &Arc<Shared>, except: OrbId, short: impl Fn() -> bool) -> usize {
    let mut written = 0;
    for h in held(sh) {
        if !short() {
            break;
        }
        if h.orb == except {
            continue;
        }
        tracing::info!(orb = %h.orb, for_orb = %except, "writing a sleep held in RAM: an orb being admitted needs the memory");
        if flush(sh, h.orb, "memory").await {
            written += 1;
        }
    }
    written
}

/// Graceful stop, first thing: writes every held sleep, oldest first, within
/// `deadline`. A write that fails drops the hold (see [`run`]).
pub(super) async fn flush_all(sh: &Arc<Shared>, deadline: Instant) {
    let all = held(sh);
    if all.is_empty() {
        return;
    }
    tracing::info!(held = all.len(), "draining: writing sleeps held in RAM");
    let mut left = 0;
    for h in all {
        let r = tokio::time::timeout_at(deadline.into(), flush(sh, h.orb, "drain")).await;
        if !matches!(r, Ok(true)) {
            left += 1;
        }
    }
    if left > 0 {
        tracing::warn!(
            orbs = left,
            "draining: sleeps held in RAM not written in time; those orbs cold-boot from their synced disks"
        );
    }
}

/// Queues a write of `orb`'s held sleep on its actor and waits for it; true once the
/// orb is no longer held. One at a time per orb; a second caller waits for the first.
async fn flush(sh: &Arc<Shared>, orb: OrbId, reason: &'static str) -> bool {
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
    if reason == "expired" {
        // A command under way decides (a wake resumes it in place).
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
    match rt.flush_held(orb, &ctx).await {
        Ok(FlushOutcome::Written) => {
            metrics::counter!("orbd_agent_held_flushes_total", "reason" => reason).increment(1);
            tracing::info!(orb = %id, reason, "wrote the checkpoint of a sleep held in RAM");
            Outcome::Flushed
        }
        Ok(FlushOutcome::NotHeld) => Outcome::Unchanged,
        Ok(FlushOutcome::Lost) => {
            metrics::counter!("orbd_agent_held_flushes_total", "reason" => "lost").increment(1);
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
        assert!(may_hold(4 * g, Some(20 * g), 4 * g, 0, 40 * g));
        assert!(
            !may_hold(4 * g, Some(7 * g), 4 * g, 0, 40 * g),
            "no room for another"
        );
        assert!(
            may_hold(4 * g, None, 4 * g, 0, 40 * g),
            "memory not bounding"
        );
        assert!(
            !may_hold(4 * g, Some(64 * g), 4 * g, MAX_HELD - 2 * g, 40 * g),
            "over the cap"
        );
        assert!(
            may_hold(4 * g, Some(64 * g), 4 * g, MAX_HELD - 4 * g, 40 * g),
            "at the cap"
        );
        assert!(
            !may_hold(4 * g, Some(64 * g), 4 * g, 0, 4 * g),
            "its checkpoint must fit"
        );
        assert!(may_hold(4 * g, Some(64 * g), 4 * g, 0, 5 * g));
    }
}
