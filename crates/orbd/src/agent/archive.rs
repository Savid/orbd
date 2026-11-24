//! Archives the disks of orbs stopped and unused for `ORBD_ARCHIVE_AFTER_HOURS` (24 by
//! default, 0 off): the runtime compresses the disk in place (see
//! `runtime::firecracker::archive`), and the orb's next wake restores it before its cold
//! boot. Orbs stopped that long rarely come back, and their disks are most of what an
//! agent's disk holds; one that comes back pays a restore (seconds for a typical disk).
//!
//! A candidate is recorded stopped without a memory checkpoint, with no unfinished
//! operation or restore intent, not archived yet, and its last command (accepted or
//! finished) older than the setting. The first check runs [`FIRST_CHECK`] after the
//! agent starts, then hourly; orbs are archived one at a time, each on the orb's actor
//! as a maintenance task, which checks everything again. A command for the orb that
//! arrives meanwhile cancels the archive (the disk is left as it was) and runs at once.

use super::maintenance::{Outcome, Task};
use super::{Shared, db, executor};
use crate::model::{OrbDefinition, OrbState, StableOrbState, unix_ms_now};
use crate::runtime::Runtime;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

const FIRST_CHECK: Duration = Duration::from_secs(900);
const EVERY: Duration = Duration::from_secs(3600);
/// How long an orb whose archive failed, or was not worth it, waits before another try.
const BACKOFF: Duration = Duration::from_secs(24 * 3600);

/// Tests shorten the first check and the setting (`agent::archive::first_check_secs`,
/// `agent::archive::after_secs`).
pub(super) async fn run_loop(sh: Arc<Shared>) {
    let Some(after) = sh.config.agent.archive_after else {
        return;
    };
    let after = failpoint_secs("agent::archive::after_secs").unwrap_or(after);
    if !sh.runtimes.values().any(|r| r.archives()) {
        return;
    }
    if crate::runtime::vm::on_path(std::path::Path::new("zstd")).is_none() {
        tracing::warn!("zstd is not installed: disks of stopped orbs are not archived");
        return;
    }
    tracing::info!(
        hours = after.as_secs() / 3600,
        "disks of orbs stopped and unused this long are archived (compressed until their next wake)"
    );
    let mut wait = failpoint_secs("agent::archive::first_check_secs").unwrap_or(FIRST_CHECK);
    loop {
        tokio::select! {
            _ = sh.shutdown.cancelled() => break,
            _ = sh.draining.cancelled() => break,
            _ = tokio::time::sleep(wait) => {}
        }
        sweep(&sh, after).await;
        wait = EVERY;
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

/// Whether a recorded orb may be archived: stopped without a checkpoint, unclaimed.
fn candidate(row: &db::OrbRow, claimed: bool) -> bool {
    !claimed
        && matches!(
            row.last_state,
            Some(OrbState::Known {
                state: StableOrbState::DiskOnlyStopped { .. }
            })
        )
}

/// Whether an orb last used at `last_used_unix_ms` is due at `now`.
fn due(last_used_unix_ms: u64, now_unix_ms: u64, after: Duration) -> bool {
    now_unix_ms.saturating_sub(last_used_unix_ms) >= after.as_millis() as u64
}

async fn sweep(sh: &Arc<Shared>, after: Duration) {
    let found = sh
        .db
        .call(|c| {
            Ok((
                db::list_orb_definitions(c)?,
                db::list_orbs_claimed(c)?,
                db::last_activity(c)?,
            ))
        })
        .await;
    let (defs, rows, activity) = match found {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "archive: cannot list orbs");
            return;
        }
    };
    let now = unix_ms_now();
    let mut due_orbs: Vec<(u64, OrbDefinition)> = rows
        .into_iter()
        .filter(|(row, claimed)| candidate(row, *claimed))
        .filter_map(|(row, _)| {
            let last = *activity.get(&row.orb_id)?;
            let def = defs.iter().find(|d| d.id == row.orb_id)?;
            let rt = executor::runtime_for(sh, def)?;
            let backing_off = sh
                .archive_backoff
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&def.id)
                .is_some_and(|until| Instant::now() < *until);
            (due(last, now, after)
                && !backing_off
                && rt.archives()
                && rt.archived(def.id).is_none())
            .then(|| (last, def.clone()))
        })
        .collect();
    due_orbs.sort_by_key(|(last, _)| *last);
    let mut archived = 0;
    for (_, def) in due_orbs {
        if sh.draining.is_cancelled() || sh.shutdown.is_cancelled() {
            break;
        }
        let (tx, rx) = oneshot::channel();
        let orb = def.id;
        executor::enqueue_work(
            sh,
            orb,
            executor::Work::Maintenance(Box::new(def), Task::Archive, tx),
        );
        match rx.await {
            Ok(Outcome::Archived) => archived += 1,
            Ok(Outcome::Failed(e)) => {
                tracing::warn!(%orb, error = %e, "not archived; not tried again for a day");
                sh.archive_backoff
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(orb, Instant::now() + BACKOFF);
            }
            _ => {}
        }
    }
    if archived > 0 {
        super::measure_disk(sh).await;
    }
}

/// The maintenance task, on the orb's actor (see the module docs).
pub(super) async fn run(sh: &Arc<Shared>, rt: &dyn Runtime, orb: &OrbDefinition) -> Outcome {
    let id = orb.id;
    // Registered before the check below: a command accepted after it cancels the archive.
    let token = CancellationToken::new();
    sh.archiving
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, token.clone());
    let unregister = || {
        sh.archiving
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    };
    match sh.db.call(move |c| db::get_orb_claimed(c, id)).await {
        Ok(Some((row, claimed))) if candidate(&row, claimed) && !sh.draining.is_cancelled() => {}
        Ok(_) => {
            unregister();
            return Outcome::Unchanged;
        }
        Err(e) => {
            unregister();
            return Outcome::Failed(format!("database: {e}"));
        }
    }
    let watcher = tokio::spawn({
        let (sh, token) = (sh.clone(), token.clone());
        async move {
            tokio::select! {
                _ = sh.shutdown.cancelled() => {}
                _ = sh.draining.cancelled() => {}
                _ = token.cancelled() => {}
            }
            token.cancel();
        }
    });
    // At idle priority, at worst about 20 MiB/s, plus time to check the archive.
    let allocated = std::fs::metadata(
        sh.config
            .agent
            .state_dir
            .join("orbs")
            .join(id.to_string())
            .join("disk.raw"),
    )
    .map_or(0, |m| std::os::unix::fs::MetadataExt::blocks(&m) * 512);
    let deadline = Instant::now() + Duration::from_secs(600 + allocated / (20 << 20));
    let mut ctx = super::maintenance::context(id, 0, deadline, deadline);
    ctx.cancel = token.clone();
    let r = rt.archive_disk(orb, &ctx).await;
    watcher.abort();
    unregister();
    match r {
        Ok(Some(info)) => {
            metrics::counter!("orbd_agent_disks_archived_total").increment(1);
            tracing::info!(
                orb = %id,
                allocated_mib = info.allocated_bytes >> 20,
                compressed_mib = info.compressed_bytes >> 20,
                "archived the disk of a stopped orb; its next wake restores it"
            );
            Outcome::Archived
        }
        Ok(None) => Outcome::Unchanged,
        Err(crate::runtime::RuntimeError::Cancelled) => {
            tracing::info!(orb = %id, "archive cancelled: a command for the orb arrived, or the agent is stopping");
            Outcome::Unchanged
        }
        Err(crate::runtime::RuntimeError::Unsupported(why)) if why.starts_with("not worth") => {
            metrics::counter!("orbd_agent_disks_not_archived_total", "reason" => "ratio")
                .increment(1);
            Outcome::Failed(why)
        }
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OrbId;

    fn row(state: Option<StableOrbState>) -> db::OrbRow {
        db::OrbRow {
            orb_id: OrbId::generate(),
            highest_generation: 2,
            created: true,
            last_state: state.map(OrbState::known),
        }
    }

    /// Only an orb recorded stopped without a checkpoint, with nothing under way, is
    /// archived; once unused for the whole setting.
    #[test]
    fn only_unclaimed_stopped_orbs_unused_long_enough_are_archived() {
        let stopped = StableOrbState::DiskOnlyStopped {
            reason: "stopped".into(),
        };
        assert!(candidate(&row(Some(stopped.clone())), false));
        assert!(!candidate(&row(Some(stopped)), true), "claimed");
        for s in [
            None,
            Some(StableOrbState::Running),
            Some(StableOrbState::Sleeping {
                checkpoint: crate::model::SleepCheckpointRef { generation: 1 },
            }),
            Some(StableOrbState::Uncreated),
            Some(StableOrbState::Deleted),
        ] {
            assert!(!candidate(&row(s.clone()), false), "{s:?}");
        }
        let day = Duration::from_secs(86_400);
        let now = 10 * 86_400_000;
        assert!(due(now - 86_400_000, now, day));
        assert!(!due(now - 86_400_000 + 1, now, day));
        assert!(!due(now + 5, now, day), "a clock behind is not due");
    }
}
