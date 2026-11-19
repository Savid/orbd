//! Opt-in (`ORBD_CHECKPOINT_MAX_AGE_HOURS`, off by default): drops the memory checkpoint
//! of an orb asleep longer than the max age, so it cold-boots on its next wake (disk
//! kept, processes lost) instead of holding a file the size of its RAM on the host's disk
//! for as long as it sleeps.
//!
//! An orb's age is its checkpoint's: the time since its save completed, which the
//! runtime records in the checkpoint itself (the VM runtimes' manifest), so it is exact
//! per checkpoint and survives agent restarts. Checked at startup (after drained orbs
//! were restored) and hourly.
//!
//! Each drop runs on the orb's actor as a maintenance task, so it never races a spawn,
//! pause, delete or restore of the orb. There it checks again that the runtime sees the
//! orb stopped with exactly that checkpoint, that the checkpoint is old enough, and,
//! last, that the orb is still recorded asleep on it with no unfinished operation and no
//! restore intent. The checkpoint then goes as one `settle` finds incompatible: marked
//! consumed, then removed through the trash. The orb is recorded stopped without a
//! checkpoint, as after a failed drain save, and reported to the coordinator; the disk
//! is measured again right away, so the next heartbeat carries the freed bytes. A spawn
//! accepted while a drop runs waits behind it and cold-boots, as one arriving just after
//! would.

use super::maintenance::{Outcome, Task};
use super::{Shared, db, executor, session};
use crate::model::{OrbId, OrbState, SleepCheckpointRef, StableOrbState, unix_ms_now};
use crate::runtime::{Runtime, RuntimeObservation};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

const EVERY: Duration = Duration::from_secs(3600);

/// Drops due checkpoints now, then hourly, until shutdown. Returns at once when no max
/// age is set.
pub(super) async fn run_loop(sh: Arc<Shared>) {
    let Some(max_age) = sh.config.agent.checkpoint_max_age else {
        return;
    };
    tracing::info!(
        max_age_hours = max_age.as_secs() / 3600,
        "memory checkpoints of orbs asleep longer than this are dropped (they cold-boot on wake)"
    );
    loop {
        sweep(&sh, max_age).await;
        tokio::select! {
            _ = sh.shutdown.cancelled() => break,
            _ = sh.draining.cancelled() => break,
            _ = tokio::time::sleep(EVERY) => {}
        }
    }
}

/// Queues a drop on the actor of every orb whose checkpoint looks due, and waits for
/// them.
async fn sweep(sh: &Arc<Shared>, max_age: Duration) {
    let found = sh
        .db
        .call(|c| Ok((db::list_orb_definitions(c)?, db::list_orbs_claimed(c)?)))
        .await;
    let (defs, rows) = match found {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "checkpoint max age: cannot list orbs");
            return;
        }
    };
    let now = unix_ms_now();
    let mut waits = Vec::new();
    for (row, claimed) in rows {
        let Some(checkpoint) = candidate(&row, claimed) else {
            continue;
        };
        let Some(def) = defs.iter().find(|d| d.id == row.orb_id) else {
            continue;
        };
        let Some(rt) = executor::runtime_for(sh, def) else {
            continue;
        };
        // A first look off the actor (published files only), so orbs not due cost no
        // actor work; the actor checks everything again.
        match rt.checkpoint_info(def.id, &checkpoint).await {
            Ok(Some(info)) if expired(info.saved_unix_ms, now, max_age).is_some() => {}
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(orb = %def.id, error = %e, "checkpoint age unknown; keeping it");
                continue;
            }
        }
        let (tx, rx) = oneshot::channel();
        executor::enqueue_work(
            sh,
            def.id,
            executor::Work::Maintenance(
                Box::new(def.clone()),
                Task::DropCheckpoint {
                    checkpoint,
                    max_age,
                },
                tx,
            ),
        );
        waits.push((def.id, rx));
    }
    let mut dropped = false;
    for (orb, rx) in waits {
        match rx.await {
            Ok(Outcome::Dropped) => dropped = true,
            Ok(Outcome::Failed(e)) => {
                tracing::warn!(%orb, error = %e, "memory checkpoint not dropped");
            }
            // Not due after all, or the agent is stopping.
            _ => {}
        }
    }
    if dropped {
        super::measure_disk(sh).await;
    }
}

/// The checkpoint an orb sleeps on, if a drop may consider it: recorded asleep (not
/// faulted) on a memory checkpoint, and not claimed by an unfinished operation or a
/// restore intent.
fn candidate(row: &db::OrbRow, claimed: bool) -> Option<SleepCheckpointRef> {
    match &row.last_state {
        Some(OrbState::Known {
            state: StableOrbState::Sleeping { checkpoint },
        }) if !claimed => Some(checkpoint.clone()),
        _ => None,
    }
}

/// The checkpoint's age if it is at least `max_age` (a save time in the future, after
/// the clock was set back, is no age).
fn expired(saved_unix_ms: u64, now_unix_ms: u64, max_age: Duration) -> Option<Duration> {
    let age = Duration::from_millis(now_unix_ms.saturating_sub(saved_unix_ms));
    (age >= max_age).then_some(age)
}

/// The maintenance task, on the orb's actor: drops `checkpoint` if it is still due.
pub(super) async fn run(
    sh: &Arc<Shared>,
    rt: &dyn Runtime,
    orb: OrbId,
    checkpoint: SleepCheckpointRef,
    max_age: Duration,
) -> Outcome {
    if sh.draining.is_cancelled() {
        return Outcome::Unchanged;
    }
    match drop_if_due(&sh.db, rt, orb, &checkpoint, max_age, unix_ms_now()).await {
        Ok(Some(row)) => {
            sh.send_control(session::orb_report_event(&row));
            Outcome::Dropped
        }
        Ok(None) => Outcome::Unchanged,
        Err(e) => Outcome::Failed(e),
    }
}

/// Drops `checkpoint` if the runtime sees the orb stopped on exactly it, it is at least
/// `max_age` old, and the orb is still recorded asleep on it, unclaimed. Returns the
/// orb as now recorded, or None if the checkpoint was kept. Callers run it where
/// nothing else acts on the orb (its actor).
async fn drop_if_due(
    db: &db::Db,
    rt: &dyn Runtime,
    orb: OrbId,
    checkpoint: &SleepCheckpointRef,
    max_age: Duration,
    now_unix_ms: u64,
) -> Result<Option<db::OrbRow>, String> {
    match rt.inspect(orb).await {
        Ok(RuntimeObservation::Stopped {
            checkpoint: Some(cp),
        }) if &cp == checkpoint => {}
        Ok(_) => return Ok(None),
        Err(e) => return Err(format!("inspect: {e}")),
    }
    let info = match rt.checkpoint_info(orb, checkpoint).await {
        Ok(Some(info)) => info,
        Ok(None) => return Ok(None),
        Err(e) => return Err(format!("checkpoint age: {e}")),
    };
    let Some(age) = expired(info.saved_unix_ms, now_unix_ms, max_age) else {
        return Ok(None);
    };
    // Last before the drop: an operation accepted since the sweep looked (a wake) keeps
    // the checkpoint.
    let recorded = db
        .call(move |c| db::get_orb_claimed(c, orb))
        .await
        .map_err(|e| format!("database: {e}"))?;
    match recorded {
        Some((row, claimed)) if candidate(&row, claimed).as_ref() == Some(checkpoint) => {}
        _ => return Ok(None),
    }
    rt.discard_checkpoint(orb, checkpoint)
        .await
        .map_err(|e| format!("discarding the checkpoint: {e}"))?;
    let (age_hours, max_age_hours) = (age.as_secs() / 3600, max_age.as_secs() / 3600);
    tracing::info!(
        %orb,
        checkpoint = checkpoint.generation,
        age_hours,
        bytes_freed = info.bytes,
        "dropped the memory checkpoint of an orb asleep past ORBD_CHECKPOINT_MAX_AGE_HOURS; it cold-boots on its next wake"
    );
    let state = OrbState::known(StableOrbState::DiskOnlyStopped {
        reason: format!(
            "memory checkpoint dropped after {age_hours} h asleep (checkpoint max age \
             {max_age_hours} h); processes lost"
        ),
    });
    let row = db
        .call(move |c| {
            db::set_last_state(c, orb, &state)?;
            db::get_orb(c, orb)
        })
        .await
        .map_err(|e| format!("recording the dropped checkpoint: {e}"))?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent::FakeRuntimeConfig;
    use crate::runtime::fake::{FakeOrbState, FakeRuntime, load_orb_state};

    const HOUR_MS: u64 = 3_600_000;
    const MAX_AGE: Duration = Duration::from_secs(12 * 3600);

    fn row(state: Option<StableOrbState>) -> db::OrbRow {
        db::OrbRow {
            orb_id: OrbId::generate(),
            highest_generation: 2,
            created: true,
            last_state: state.map(OrbState::known),
        }
    }

    fn asleep(generation: u64) -> StableOrbState {
        StableOrbState::Sleeping {
            checkpoint: SleepCheckpointRef { generation },
        }
    }

    /// Only an orb recorded asleep on a checkpoint, with no unfinished operation and no
    /// restore intent, is looked at.
    #[test]
    fn candidates_are_unclaimed_orbs_asleep_on_a_checkpoint() {
        let cp = SleepCheckpointRef { generation: 3 };
        assert_eq!(candidate(&row(Some(asleep(3))), false), Some(cp));
        assert_eq!(
            candidate(&row(Some(asleep(3))), true),
            None,
            "an unfinished operation or a restore intent claims it"
        );
        for state in [
            None,
            Some(StableOrbState::Uncreated),
            Some(StableOrbState::Running),
            Some(StableOrbState::DiskOnlyStopped {
                reason: "stopped".into(),
            }),
            Some(StableOrbState::Deleted),
        ] {
            assert_eq!(candidate(&row(state.clone()), false), None, "{state:?}");
        }
        let mut faulted = row(None);
        faulted.last_state = Some(OrbState::Faulted {
            last_known: asleep(3),
            reason: "disk is missing".into(),
        });
        assert_eq!(candidate(&faulted, false), None, "faulted");
    }

    #[test]
    fn a_checkpoint_is_due_at_the_max_age() {
        let now = 1_000 * HOUR_MS;
        assert_eq!(expired(now - 12 * HOUR_MS + 1, now, MAX_AGE), None);
        assert_eq!(expired(now - 12 * HOUR_MS, now, MAX_AGE), Some(MAX_AGE));
        assert_eq!(
            expired(now - 30 * HOUR_MS, now, MAX_AGE),
            Some(Duration::from_secs(30 * 3600))
        );
        assert_eq!(
            expired(now + HOUR_MS, now, MAX_AGE),
            None,
            "saved in the future"
        );
    }

    struct Host {
        dir: tempfile::TempDir,
        db: db::Db,
        rt: FakeRuntime,
        orb: OrbId,
    }

    impl Host {
        /// An orb asleep on checkpoint 3, saved `age_hours` ago, recorded so.
        async fn new(age_hours: u64) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let db = db::Db::open(&dir.path().join("agent.sqlite")).unwrap();
            let rt = FakeRuntime::new(
                dir.path().to_path_buf(),
                &FakeRuntimeConfig {
                    memory_preserving_sleep: true,
                    ..Default::default()
                },
            );
            let host = Self {
                dir,
                db,
                rt,
                orb: OrbId::generate(),
            };
            host.runtime_sleeps_on(3, age_hours);
            host.record(asleep(3)).await;
            host
        }

        /// The fake runtime's orb: stopped with checkpoint `generation`, saved `age_hours`
        /// ago (and earlier ones consumed).
        fn runtime_sleeps_on(&self, generation: u64, age_hours: u64) {
            let st = FakeOrbState {
                disk: true,
                checkpoints: (1..=generation).collect(),
                consumed: (1..generation).collect(),
                checkpoint_saved_unix_ms: [(generation, unix_ms_now() - age_hours * HOUR_MS)]
                    .into(),
                ..Default::default()
            };
            let path = self
                .dir
                .path()
                .join("fake")
                .join(format!("{}.json", self.orb));
            std::fs::write(path, serde_json::to_vec(&st).unwrap()).unwrap();
        }

        fn fake(&self) -> FakeOrbState {
            load_orb_state(self.dir.path(), self.orb).unwrap().unwrap()
        }

        async fn record(&self, state: StableOrbState) {
            let (orb, json) = (
                self.orb.to_string(),
                serde_json::to_string(&OrbState::known(state)).unwrap(),
            );
            self.sql(
                "INSERT INTO orbs(orb_id, highest_generation, created, last_state_json)
                 VALUES (?1, 2, 1, ?2)
                 ON CONFLICT(orb_id) DO UPDATE SET last_state_json = excluded.last_state_json",
                vec![orb, json],
            )
            .await;
        }

        async fn sql(&self, sql: &'static str, params: Vec<String>) {
            self.db
                .call(move |c| {
                    c.execute(sql, rusqlite::params_from_iter(params))
                        .map(|_| ())
                })
                .await
                .unwrap();
        }

        async fn last_state(&self) -> Option<OrbState> {
            let orb = self.orb;
            self.db
                .call(move |c| db::get_orb(c, orb))
                .await
                .unwrap()
                .unwrap()
                .last_state
        }

        async fn drop_if_due(&self) -> Option<db::OrbRow> {
            let cp = SleepCheckpointRef { generation: 3 };
            drop_if_due(&self.db, &self.rt, self.orb, &cp, MAX_AGE, unix_ms_now())
                .await
                .unwrap()
        }

        /// Checkpoint 3 is still there to restore, and the orb still recorded asleep.
        async fn assert_kept(&self, why: &str) {
            assert_eq!(
                self.rt.inspect(self.orb).await.unwrap(),
                RuntimeObservation::Stopped {
                    checkpoint: Some(SleepCheckpointRef { generation: 3 })
                },
                "{why}"
            );
            assert_eq!(
                self.last_state().await,
                Some(OrbState::known(asleep(3))),
                "{why}"
            );
        }
    }

    /// A young checkpoint is kept.
    #[tokio::test]
    async fn keeps_a_checkpoint_younger_than_the_max_age() {
        let h = Host::new(11).await;
        assert!(h.drop_if_due().await.is_none());
        h.assert_kept("11 h old").await;
    }

    /// Checked again on the actor: an orb a wake has claimed since the sweep looked (an
    /// unfinished operation), one with a restore intent, one recorded otherwise and one
    /// asleep on another checkpoint keep theirs.
    #[tokio::test]
    async fn keeps_the_checkpoint_of_a_claimed_or_changed_orb() {
        let h = Host::new(13).await;
        let orb = h.orb.to_string();

        h.sql(
            "INSERT INTO receipts(operation_id, orb_id, generation, command_digest,
                command_json, orb_json, sealed_env, work_deadline_unix_ms,
                cleanup_deadline_unix_ms, accepted_at_unix_ms, status)
             VALUES ('op-1', ?1, 3, 'd', '{}', '{}', x'', 0, 0, 0, 'accepted')",
            vec![orb.clone()],
        )
        .await;
        assert!(h.drop_if_due().await.is_none());
        h.assert_kept("unfinished operation").await;
        h.sql(
            "UPDATE receipts SET status = 'terminal' WHERE operation_id = 'op-1'",
            vec![],
        )
        .await;

        h.sql(
            "UPDATE orbs SET restore_json = '{}' WHERE orb_id = ?1",
            vec![orb.clone()],
        )
        .await;
        assert!(h.drop_if_due().await.is_none());
        h.assert_kept("restore intent").await;
        h.sql(
            "UPDATE orbs SET restore_json = NULL WHERE orb_id = ?1",
            vec![orb.clone()],
        )
        .await;

        h.record(StableOrbState::Running).await;
        assert!(h.drop_if_due().await.is_none());
        assert_eq!(h.fake().consumed, [1, 2], "recorded running: kept");
        h.record(asleep(3)).await;

        // Woke and slept again since the sweep looked: the new checkpoint is not the
        // one that was due.
        h.runtime_sleeps_on(4, 13);
        h.record(asleep(4)).await;
        assert!(h.drop_if_due().await.is_none());
        assert!(!h.fake().consumed.contains(&4), "another checkpoint: kept");
    }

    /// A due checkpoint goes: it is never restored, the orb is recorded stopped without
    /// one (as after a failed drain save), so its next start is a cold boot of its
    /// disk; a second drop finds nothing to do.
    #[tokio::test]
    async fn drops_a_due_checkpoint_and_records_the_orb_stopped() {
        let h = Host::new(13).await;
        let row = h.drop_if_due().await.expect("dropped");
        assert!(h.fake().consumed.contains(&3));
        assert!(h.fake().disk, "the disk is kept");
        assert_eq!(
            h.rt.inspect(h.orb).await.unwrap(),
            RuntimeObservation::Stopped { checkpoint: None },
            "a spawn now cold-boots the existing disk"
        );
        let Some(OrbState::Known {
            state: StableOrbState::DiskOnlyStopped { reason },
        }) = &row.last_state
        else {
            panic!("recorded {:?}", row.last_state);
        };
        assert!(reason.contains("dropped after 13 h"), "{reason}");
        assert_eq!(h.last_state().await, row.last_state, "the reported row");
        assert!(h.drop_if_due().await.is_none(), "nothing left to drop");
    }
}
