//! Agent maintenance: a graceful stop keeps running orbs across the agent's restart.
//!
//! Drain (SIGTERM): the agent stops taking new commands and tells the coordinator it is
//! draining; in-flight operations are interrupted and stay accepted. Then every running
//! orb whose runtime and offering preserve memory is checkpointed through its own
//! executor (so it never races a spawn, pause or delete), smallest first, within
//! [`SHUTDOWN_BUDGET`]. A restore intent bound to the orb's command generation
//! is recorded before each save; a save that does not complete clears it and records
//! what is actually left (a cold-stopped disk, processes lost).
//!
//! Restart: after interrupted operations are requeued, orbs with a restore intent are
//! restored from exactly that checkpoint, and the guest only gets its clock and network
//! resynced (no credentials: Amp sent no spawn). An orb with its own unfinished
//! operation, or a newer accepted command, is left to that command. Nothing here
//! reports an Amp command result.
//!
//! The same per-orb serialization runs [`super::checkpoint_age`]'s drops of memory
//! checkpoints older than `ORBD_CHECKPOINT_MAX_AGE_HOURS`, [`super::hold`]'s writes
//! of sleeps held in RAM (a drain writes every held sleep first) and
//! [`super::archive`]'s archives of stopped orbs' disks.

use super::db::{self, RestoreIntent};
use super::{Shared, executor};
use crate::model::{
    OperationId, OrbDefinition, OrbId, OrbState, PausePolicy, SleepCheckpointRef, StableOrbState,
};
use crate::runtime::{LogStream, OpContext, Runtime, RuntimeObservation, StartSource};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// How long a graceful stop may take. Give the process manager more, e.g.
/// `docker stop -t 300` or compose `stop_grace_period: 300s`; a save cut off by the
/// final SIGKILL is never published (the orb is reported stopped, processes lost).
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(280);
/// Kept from the shutdown budget for cleanup after a failed save.
const CLEANUP_RESERVE: Duration = Duration::from_secs(20);
/// Per-orb budget for restoring after a restart.
const RESTORE_BUDGET: Duration = Duration::from_secs(120);

pub(crate) enum Task {
    Checkpoint {
        deadline: Instant,
    },
    Restore {
        intent: RestoreIntent,
    },
    /// Drop the memory checkpoint of an orb asleep longer than `max_age`, or record that
    /// its host no longer has it (see [`super::checkpoint_age`]).
    DropCheckpoint {
        checkpoint: SleepCheckpointRef,
        max_age: Duration,
    },
    /// Write a sleep held in RAM to its checkpoint (see [`super::hold`]); `reason` is a
    /// metrics label.
    FlushHeld {
        reason: &'static str,
    },
    /// Archive a stopped orb's disk (see [`super::archive`]).
    Archive,
}

#[derive(Debug)]
pub(crate) enum Outcome {
    Saved,
    Restored,
    /// The memory checkpoint was dropped.
    Dropped,
    /// The host no longer had the checkpoint the orb was recorded asleep on; what it
    /// has was recorded.
    Recorded,
    /// A held sleep's checkpoint was written.
    Flushed,
    /// The orb's disk was archived.
    Archived,
    /// Nothing to do (not running, or already running; for a drop, not due).
    Unchanged,
    /// Could not save or restore; what is left was recorded.
    Failed(String),
}

/// Graceful stop: stop admission, then checkpoint running orbs within the budget.
pub(super) async fn drain(sh: &Arc<Shared>) {
    let started = Instant::now();
    let deadline = started + SHUTDOWN_BUDGET;
    sh.draining.cancel();
    sh.send_control(super::session::heartbeat(sh));
    let defs = match sh.db.call(|c| db::list_orb_definitions(c)).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "drain: cannot list orbs");
            return;
        }
    };
    let mut orbs: Vec<OrbDefinition> = defs
        .into_iter()
        .filter(|d| {
            matches!(
                d.spec.template.pause_policy,
                PausePolicy::MemoryPreserving { .. }
            ) && executor::runtime_for(sh, d)
                .is_some_and(|rt| rt.capabilities().memory_preserving_sleep)
        })
        .collect();
    // Sleeps held in RAM are lost with the agent's processes unless written too: one
    // queue with the running orbs, smallest first, so the most orbs finish within the
    // budget whatever the disk's speed.
    let held: HashSet<OrbId> = sh
        .runtimes
        .values()
        .flat_map(|r| r.held())
        .map(|h| h.orb)
        .collect();
    orbs.retain(|d| !held.contains(&d.id));
    let mut queue: Vec<(u64, OrbDefinition, bool)> = orbs
        .into_iter()
        .map(|d| (d.spec.template.resources.memory_bytes, d, false))
        .collect();
    let held_defs = sh
        .db
        .call(move |c| {
            let mut v = Vec::new();
            for id in held {
                if let Some(d) = db::get_orb_definition(c, id)? {
                    v.push(d);
                }
            }
            Ok(v)
        })
        .await
        .unwrap_or_default();
    queue.extend(
        held_defs
            .into_iter()
            .map(|d| (d.spec.template.resources.memory_bytes, d, true)),
    );
    queue.sort_by_key(|(m, _, _)| *m);
    tracing::info!(
        candidates = queue.len(),
        budget_secs = SHUTDOWN_BUDGET.as_secs(),
        "draining: checkpointing running orbs and writing held sleeps, smallest first"
    );
    let (mut saved, mut failed, mut unchanged) = (0, Vec::new(), 0);
    for (_, orb, held) in queue {
        if held {
            match tokio::time::timeout_at(deadline.into(), super::hold::flush(sh, orb.id, "drain"))
                .await
            {
                Ok(true) => saved += 1,
                _ => failed.push(format!("{}: held sleep not written", orb.id)),
            }
            continue;
        }
        let (tx, rx) = oneshot::channel();
        executor::enqueue_work(
            sh,
            orb.id,
            executor::Work::Maintenance(Box::new(orb.clone()), Task::Checkpoint { deadline }, tx),
        );
        match tokio::time::timeout_at(deadline.into(), rx).await {
            Ok(Ok(Outcome::Saved)) => saved += 1,
            Ok(Ok(Outcome::Failed(e))) => failed.push(format!("{}: {e}", orb.id)),
            Ok(Ok(_)) => unchanged += 1,
            Ok(Err(_)) | Err(_) => failed.push(format!("{}: shutdown budget exhausted", orb.id)),
        }
    }
    tracing::info!(
        saved,
        not_running = unchanged,
        failed = failed.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "drain finished"
    );
    for f in failed {
        tracing::error!("drain: not checkpointed (processes are lost): {f}");
    }
    // A pause that held after the queue was made (it decided before the drain began).
    let late: Vec<OrbId> = sh
        .runtimes
        .values()
        .flat_map(|r| r.held())
        .map(|h| h.orb)
        .collect();
    for orb in late {
        let _ =
            tokio::time::timeout_at(deadline.into(), super::hold::flush(sh, orb, "drain")).await;
    }
}

/// Startup: restores orbs the last drain checkpointed. Orbs in `busy` have unfinished
/// operations of their own, which decide their fate instead.
pub(super) async fn restore_all(sh: &Arc<Shared>, busy: &HashSet<OrbId>) -> anyhow::Result<()> {
    let intents = sh.db.call(|c| db::list_restore_intents(c)).await?;
    if intents.is_empty() {
        return Ok(());
    }
    let defs = sh.db.call(|c| db::list_orb_definitions(c)).await?;
    let mut waits = Vec::new();
    for (row, intent) in intents {
        let def = defs.iter().find(|d| d.id == row.orb_id);
        let superseded = busy.contains(&row.orb_id)
            || row.highest_generation != intent.generation
            || row.is_deleted();
        let Some(def) = def.filter(|_| !superseded) else {
            tracing::info!(orb = %row.orb_id, "restore intent superseded by the orb's own commands");
            let state = row
                .last_state
                .clone()
                .unwrap_or(OrbState::known(StableOrbState::Uncreated));
            let orb = row.orb_id;
            sh.db
                .call(move |c| db::record_maintenance(c, orb, &state, None))
                .await?;
            continue;
        };
        sh.reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(def.id, def.spec.template.resources);
        let (tx, rx) = oneshot::channel();
        executor::enqueue_work(
            sh,
            def.id,
            executor::Work::Maintenance(Box::new(def.clone()), Task::Restore { intent }, tx),
        );
        waits.push((def.id, rx));
    }
    let (mut restored, mut other) = (0, 0);
    for (orb, rx) in waits {
        match rx.await {
            Ok(Outcome::Restored) => restored += 1,
            Ok(o) => {
                other += 1;
                tracing::warn!(%orb, outcome = ?o, "orb was not restored after the restart");
            }
            Err(_) => other += 1,
        }
    }
    tracing::info!(
        restored,
        not_restored = other,
        "maintenance restore finished"
    );
    Ok(())
}

/// Runs one maintenance task on the orb's actor.
pub(super) async fn run(sh: &Arc<Shared>, orb: &OrbDefinition, task: Task) -> Outcome {
    let Some(rt) = executor::runtime_for(sh, orb) else {
        return Outcome::Failed("no runtime for this orb".into());
    };
    let outcome = match task {
        Task::Checkpoint { deadline } => checkpoint(sh, &*rt, orb, deadline).await,
        Task::Restore { intent } => restore(sh, &*rt, orb, intent).await,
        // Only ever drops a stopped orb's checkpoint: its reservation is unchanged.
        Task::DropCheckpoint {
            checkpoint,
            max_age,
        } => return super::checkpoint_age::run(sh, &*rt, orb.id, checkpoint, max_age).await,
        // Asleep and stopped orbs hold no reservation either.
        Task::FlushHeld { reason } => return super::hold::run(sh, &*rt, orb, reason).await,
        Task::Archive => return super::archive::run(sh, &*rt, orb).await,
    };
    let running = matches!(rt.inspect(orb.id).await, Ok(RuntimeObservation::Running));
    let mut reserved = sh.reserved.lock().unwrap_or_else(|e| e.into_inner());
    // A drained orb keeps its reservation: it is restored at the next start.
    if !running && !matches!(outcome, Outcome::Saved) {
        reserved.remove(&orb.id);
    }
    outcome
}

async fn checkpoint(
    sh: &Arc<Shared>,
    rt: &dyn Runtime,
    orb: &OrbDefinition,
    deadline: Instant,
) -> Outcome {
    match rt.inspect(orb.id).await {
        Ok(RuntimeObservation::Running) => {}
        Ok(_) => return Outcome::Unchanged,
        Err(e) => return Outcome::Failed(format!("inspect: {e}")),
    }
    let id = orb.id;
    let prepared = sh
        .db
        .call(move |c| {
            let row = db::get_orb(c, id)?;
            let g = db::allocate_maintenance_checkpoint(c, id)?;
            let intent = RestoreIntent {
                generation: row.map_or(0, |r| r.highest_generation),
                checkpoint: SleepCheckpointRef { generation: g },
            };
            // Recorded before the save, so a crash mid-save still restores whatever
            // the runtime publishes for this generation.
            db::record_maintenance(
                c,
                id,
                &OrbState::known(StableOrbState::Running),
                Some(&intent),
            )?;
            Ok(intent)
        })
        .await;
    let intent = match prepared {
        Ok(i) => i,
        Err(e) => return Outcome::Failed(format!("database: {e}")),
    };
    let work = deadline.checked_sub(CLEANUP_RESERVE).unwrap_or(deadline);
    let ctx = context(orb.id, intent.generation, work, deadline);
    let failure = if Instant::now() >= work {
        "no shutdown budget left".to_owned()
    } else {
        // Never held: the agent is stopping, and its orbs' memory with it.
        match rt
            .checkpoint_and_stop(orb, intent.checkpoint.generation, false, &ctx)
            .await
        {
            Ok(cp) => {
                let state = OrbState::known(StableOrbState::Sleeping {
                    checkpoint: cp.clone(),
                });
                let intent = RestoreIntent {
                    checkpoint: cp.clone(),
                    ..intent
                };
                return match sh
                    .db
                    .call(move |c| db::record_maintenance(c, id, &state, Some(&intent)))
                    .await
                {
                    Ok(()) => {
                        tracing::info!(orb = %id, checkpoint = cp.generation, "drain: checkpointed");
                        Outcome::Saved
                    }
                    Err(e) => Outcome::Failed(format!("database: {e}")),
                };
            }
            Err(e) => e.to_string(),
        }
    };
    // The runtime resumed the guest; shut it down cleanly while there is budget, so
    // its disk is consistent when the VMM is killed with the agent.
    let cctx = context(orb.id, intent.generation, deadline, deadline);
    if let Err(e) = rt.cold_stop(orb, &cctx).await {
        tracing::warn!(orb = %id, error = %e, "drain: cold stop after a failed save");
    }
    let reason = format!("agent shutdown: checkpoint failed ({failure}); processes lost");
    let state = match rt.inspect(orb.id).await {
        Ok(RuntimeObservation::Stopped { .. }) => {
            OrbState::known(StableOrbState::DiskOnlyStopped {
                reason: reason.clone(),
            })
        }
        other => OrbState::Faulted {
            last_known: StableOrbState::Running,
            reason: format!("{reason}; now {other:?}"),
        },
    };
    let _ = sh
        .db
        .call(move |c| db::record_maintenance(c, id, &state, None))
        .await;
    Outcome::Failed(failure)
}

async fn restore(
    sh: &Arc<Shared>,
    rt: &dyn Runtime,
    orb: &OrbDefinition,
    intent: RestoreIntent,
) -> Outcome {
    let id = orb.id;
    let deadline = Instant::now() + RESTORE_BUDGET;
    let ctx = context(id, intent.generation, deadline, deadline);
    let observed = rt.inspect(id).await;
    let (state, outcome) = match observed {
        Ok(RuntimeObservation::Stopped {
            checkpoint: Some(cp),
        }) if cp == intent.checkpoint => {
            match rt
                .start(orb, StartSource::MemoryCheckpoint(cp.clone()), &ctx)
                .await
            {
                Ok(()) => {
                    if let Err(e) = rt.discard_checkpoint(id, &cp).await {
                        tracing::warn!(orb = %id, error = %e, "discarding a restored checkpoint");
                    }
                    if let Err(e) = rt.guest().resync(orb, &ctx).await {
                        tracing::warn!(orb = %id, error = %e, "guest resync after restore");
                    }
                    tracing::info!(orb = %id, checkpoint = cp.generation, "restored after agent restart");
                    (StableOrbState::Running, Outcome::Restored)
                }
                Err(e) => {
                    let s = observed_state(rt, id).await;
                    (s, Outcome::Failed(format!("restore: {e}")))
                }
            }
        }
        // Mid-drain crash of the agent alone: the VMM survived and was resumed.
        Ok(RuntimeObservation::Running) => (StableOrbState::Running, Outcome::Unchanged),
        _ => {
            let s = observed_state(rt, id).await;
            let why = format!(
                "checkpoint {} is not restorable (found {s:?}); the orb cold-boots on its next spawn, processes lost",
                intent.checkpoint.generation
            );
            tracing::error!(orb = %id, "{why}");
            (s, Outcome::Failed(why))
        }
    };
    let state = OrbState::known(state);
    let _ = sh
        .db
        .call(move |c| db::record_maintenance(c, id, &state, None))
        .await;
    outcome
}

async fn observed_state(rt: &dyn Runtime, orb: OrbId) -> StableOrbState {
    match rt.inspect(orb).await {
        Ok(RuntimeObservation::Running) => StableOrbState::Running,
        Ok(RuntimeObservation::Stopped {
            checkpoint: Some(checkpoint),
        }) => StableOrbState::Sleeping { checkpoint },
        Ok(RuntimeObservation::Absent) => StableOrbState::Uncreated,
        _ => StableOrbState::DiskOnlyStopped {
            reason: "no restorable checkpoint; processes lost".into(),
        },
    }
}

/// A runtime context outside any command: fresh id, logs to the agent's own log.
pub(super) fn context(orb: OrbId, generation: u64, work: Instant, cleanup: Instant) -> OpContext {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(LogStream, bytes::Bytes)>(64);
    tokio::spawn(async move {
        while let Some((_, line)) = rx.recv().await {
            tracing::info!(%orb, "{}", String::from_utf8_lossy(&line).trim_end());
        }
    });
    OpContext {
        operation_id: OperationId::generate(),
        generation,
        work_deadline: work,
        cleanup_deadline: cleanup.max(work),
        cancel: CancellationToken::new(),
        log: tx,
    }
}
