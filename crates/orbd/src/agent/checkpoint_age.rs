//! Opt-in (`ORBD_CHECKPOINT_MAX_AGE_HOURS`, off by default): drops the memory checkpoint
//! of an orb asleep longer than the max age, so it cold-boots on its next wake (disk
//! kept, processes lost) instead of holding a file the size of its RAM on the host's disk
//! for as long as it sleeps.
//!
//! An orb's age is its checkpoint's: the time since its save completed, which the
//! runtime records in the checkpoint itself (the VM runtimes' manifest), so it is exact
//! per checkpoint and survives agent restarts. The first check runs [`FIRST_CHECK`] after
//! the agent starts, not at once: a host whose clock is still wrong (before NTP) would
//! otherwise find every checkpoint due, and a drop cannot be undone. Then hourly. A
//! checkpoint saved more than [`CLOCK_SLACK`] in the future is kept (a clock was wrong),
//! and so is one saved without the guest syncing its disk first: a cold boot of that disk
//! could find writes the guest had not made durable.
//!
//! Orbs are checked one at a time (a drop deletes GiB), each on the orb's actor as a
//! maintenance task, so a check never races a spawn, pause, delete or restore of the
//! orb. There the runtime decides:
//!
//! * The orb is stopped on the checkpoint it is recorded asleep on: it is dropped if it
//!   is still due and, checked last, the orb is still recorded asleep on it with no
//!   unfinished operation and no restore intent. The checkpoint is marked consumed and
//!   moved into the trash under the runtime's orb lock, as `settle` discards an
//!   incompatible one, and its files are deleted on a blocking thread.
//! * The orb is stopped without that checkpoint (a drop cut short before it was
//!   recorded, or `settle` discarded it): after the same guards, what the host has is
//!   recorded.
//!
//! Either way the orb ends up recorded stopped without a checkpoint, as after a failed
//! drain save, and reported to the coordinator; after drops the disk is measured again,
//! so the next heartbeat carries the freed bytes. A spawn accepted while a check runs
//! waits behind it and cold-boots, as one arriving just after would.

use super::maintenance::{Outcome, Task};
use super::{Shared, db, executor, session};
use crate::model::{OrbId, OrbState, SleepCheckpointRef, StableOrbState, unix_ms_now};
use crate::runtime::{CheckpointInfo, Runtime, RuntimeObservation};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// How long after the agent starts the first check runs.
const FIRST_CHECK: Duration = Duration::from_secs(600);
const EVERY: Duration = Duration::from_secs(3600);
/// A checkpoint saved further ahead of the clock than this is never dropped.
const CLOCK_SLACK: Duration = Duration::from_secs(3600);

/// Checks [`FIRST_CHECK`] after the start, then hourly, until shutdown. Returns at once
/// when no max age is set.
pub(super) async fn run_loop(sh: Arc<Shared>) {
    let Some(max_age) = sh.config.agent.checkpoint_max_age else {
        return;
    };
    let mut wait = first_check();
    tracing::info!(
        max_age_hours = max_age.as_secs() / 3600,
        first_check_secs = wait.as_secs(),
        "memory checkpoints of orbs asleep longer than this are dropped (they cold-boot on wake)"
    );
    loop {
        tokio::select! {
            _ = sh.shutdown.cancelled() => break,
            _ = sh.draining.cancelled() => break,
            _ = tokio::time::sleep(wait) => {}
        }
        sweep(&sh, max_age).await;
        wait = EVERY;
    }
}

/// [`FIRST_CHECK`]; tests set `agent::checkpoint_age::first_check_secs=return(<secs>)`.
fn first_check() -> Duration {
    #[cfg(feature = "failpoints")]
    if let Some(secs) = fail::eval("agent::checkpoint_age::first_check_secs", |a| {
        a.and_then(|a| a.parse::<u64>().ok())
    })
    .flatten()
    {
        return Duration::from_secs(secs);
    }
    FIRST_CHECK
}

/// Checks, one at a time on its actor, every orb whose checkpoint looks due or gone.
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
    let mut dropped = false;
    for (row, claimed) in rows {
        if sh.draining.is_cancelled() || sh.shutdown.is_cancelled() {
            break;
        }
        let Some(checkpoint) = candidate(&row, claimed) else {
            continue;
        };
        let Some(def) = defs.iter().find(|d| d.id == row.orb_id) else {
            continue;
        };
        let Some(rt) = executor::runtime_for(sh, def) else {
            continue;
        };
        let (orb, generation) = (def.id, checkpoint.generation);
        // A first look off the actor (published files only), so orbs that are not due
        // cost no actor work; the actor checks everything again.
        match rt.checkpoint_info(orb, &checkpoint).await {
            // Gone: the actor records what the host has.
            Ok(None) => {}
            Ok(Some(info)) => match verdict(&info, unix_ms_now(), max_age) {
                Verdict::Due(_) => {}
                Verdict::Young => continue,
                Verdict::Future(ahead) => {
                    tracing::warn!(
                        %orb,
                        checkpoint = generation,
                        ahead_mins = ahead.as_secs() / 60,
                        "memory checkpoint saved in the future (a clock was wrong); keeping it"
                    );
                    continue;
                }
                Verdict::Unsynced => {
                    tracing::debug!(
                        %orb,
                        checkpoint = generation,
                        "memory checkpoint past the max age kept: the guest did not sync its disk before it was saved"
                    );
                    continue;
                }
            },
            Err(e) => {
                tracing::warn!(%orb, error = %e, "checkpoint age unknown; keeping it");
                continue;
            }
        }
        let (tx, rx) = oneshot::channel();
        executor::enqueue_work(
            sh,
            orb,
            executor::Work::Maintenance(
                Box::new(def.clone()),
                Task::DropCheckpoint {
                    checkpoint,
                    max_age,
                },
                tx,
            ),
        );
        match rx.await {
            Ok(Outcome::Dropped) => dropped = true,
            Ok(Outcome::Failed(e)) => {
                tracing::warn!(%orb, error = %e, "memory checkpoint not dropped");
            }
            // Not due after all, recorded as found, or the agent is stopping.
            _ => {}
        }
    }
    if dropped {
        super::measure_disk(sh).await;
    }
}

/// The checkpoint an orb sleeps on, if a check may consider it: recorded asleep (not
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

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Older than the max age, by this much.
    Due(Duration),
    Young,
    /// Saved this far in the future, beyond [`CLOCK_SLACK`].
    Future(Duration),
    /// Older than the max age, but the guest did not sync its disk before the save.
    Unsynced,
}

fn verdict(info: &CheckpointInfo, now_unix_ms: u64, max_age: Duration) -> Verdict {
    let ahead = Duration::from_millis(info.saved_unix_ms.saturating_sub(now_unix_ms));
    if ahead > CLOCK_SLACK {
        return Verdict::Future(ahead);
    }
    let age = Duration::from_millis(now_unix_ms.saturating_sub(info.saved_unix_ms));
    if age < max_age {
        Verdict::Young
    } else if !info.synced {
        Verdict::Unsynced
    } else {
        Verdict::Due(age)
    }
}

/// The maintenance task, on the orb's actor (see the module docs).
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
    match check(&sh.db, rt, orb, &checkpoint, max_age, unix_ms_now()).await {
        Ok(Some(Checked::Dropped(row))) => {
            sh.send_control(session::orb_report_event(&row));
            Outcome::Dropped
        }
        Ok(Some(Checked::Gone(row))) => {
            sh.send_control(session::orb_report_event(&row));
            Outcome::Recorded
        }
        Ok(None) => Outcome::Unchanged,
        Err(e) => Outcome::Failed(e),
    }
}

/// What a check changed, with the orb as now recorded.
#[derive(Debug)]
enum Checked {
    /// The checkpoint was due and is dropped.
    Dropped(db::OrbRow),
    /// The host no longer had the checkpoint; what it has is recorded.
    Gone(db::OrbRow),
}

/// Drops `checkpoint`, or records that the host no longer has it, if the orb is still
/// recorded asleep on it, unclaimed (see the module docs). None if nothing changed.
/// Callers run it where nothing else acts on the orb (its actor).
async fn check(
    db: &db::Db,
    rt: &dyn Runtime,
    orb: OrbId,
    checkpoint: &SleepCheckpointRef,
    max_age: Duration,
    now_unix_ms: u64,
) -> Result<Option<Checked>, String> {
    let on_host = match rt.inspect(orb).await {
        Ok(RuntimeObservation::Stopped { checkpoint }) => checkpoint,
        // Running, gone or broken: the orb's commands deal with that.
        Ok(_) => return Ok(None),
        Err(e) => return Err(format!("inspect: {e}")),
    };
    if on_host.as_ref() != Some(checkpoint) {
        if !recorded_on(db, orb, checkpoint).await? {
            return Ok(None);
        }
        let state = match on_host {
            Some(other) => StableOrbState::Sleeping { checkpoint: other },
            None => StableOrbState::DiskOnlyStopped {
                reason: "memory checkpoint missing on disk; processes lost".into(),
            },
        };
        tracing::info!(
            %orb,
            checkpoint = checkpoint.generation,
            now = ?state,
            "orb was recorded asleep on a memory checkpoint its host no longer has; recording what the host has"
        );
        return Ok(record(db, orb, state).await?.map(Checked::Gone));
    }
    let info = match rt.checkpoint_info(orb, checkpoint).await {
        Ok(Some(info)) => info,
        Ok(None) => return Ok(None),
        Err(e) => return Err(format!("checkpoint age: {e}")),
    };
    let Verdict::Due(age) = verdict(&info, now_unix_ms, max_age) else {
        return Ok(None);
    };
    // Last before the drop: an operation accepted since the sweep looked (a wake) keeps
    // the checkpoint.
    if !recorded_on(db, orb, checkpoint).await? {
        return Ok(None);
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
    let state = StableOrbState::DiskOnlyStopped {
        reason: format!(
            "memory checkpoint dropped after {age_hours} h asleep (checkpoint max age \
             {max_age_hours} h); processes lost"
        ),
    };
    Ok(record(db, orb, state).await?.map(Checked::Dropped))
}

/// Whether the orb is still recorded asleep on `checkpoint`, unclaimed.
async fn recorded_on(
    db: &db::Db,
    orb: OrbId,
    checkpoint: &SleepCheckpointRef,
) -> Result<bool, String> {
    let recorded = db
        .call(move |c| db::get_orb_claimed(c, orb))
        .await
        .map_err(|e| format!("database: {e}"))?;
    Ok(matches!(
        recorded,
        Some((row, claimed)) if candidate(&row, claimed).as_ref() == Some(checkpoint)
    ))
}

async fn record(
    db: &db::Db,
    orb: OrbId,
    state: StableOrbState,
) -> Result<Option<db::OrbRow>, String> {
    let state = OrbState::known(state);
    db.call(move |c| {
        db::set_last_state(c, orb, &state)?;
        db::get_orb(c, orb)
    })
    .await
    .map_err(|e| format!("recording the orb's state: {e}"))
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

    /// Due at the max age; never when the guest did not sync its disk first, or when
    /// the save time is more than an hour ahead of the clock (a little ahead is no age).
    #[test]
    fn a_checkpoint_is_due_at_the_max_age_if_synced_and_not_from_the_future() {
        let now = 1_000 * HOUR_MS;
        let info = |saved_unix_ms, synced| CheckpointInfo {
            saved_unix_ms,
            bytes: 1,
            synced,
        };
        let v = |saved, synced| verdict(&info(saved, synced), now, MAX_AGE);
        assert_eq!(v(now - 12 * HOUR_MS + 1, true), Verdict::Young);
        assert_eq!(v(now - 12 * HOUR_MS, true), Verdict::Due(MAX_AGE));
        assert_eq!(
            v(now - 30 * HOUR_MS, true),
            Verdict::Due(Duration::from_secs(30 * 3600))
        );
        assert_eq!(v(now - 30 * HOUR_MS, false), Verdict::Unsynced);
        assert_eq!(v(now - HOUR_MS, false), Verdict::Young);
        assert_eq!(v(now + HOUR_MS / 2, true), Verdict::Young, "a little ahead");
        assert_eq!(v(now + HOUR_MS, true), Verdict::Young);
        assert_eq!(
            v(now + 3 * HOUR_MS, true),
            Verdict::Future(Duration::from_secs(3 * 3600))
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
            host.runtime_sleeps_on(3, unix_ms_now() - age_hours * HOUR_MS);
            host.record(asleep(3)).await;
            host
        }

        /// The fake runtime's orb: stopped with checkpoint `generation` saved at
        /// `saved_unix_ms` (earlier ones consumed).
        fn runtime_sleeps_on(&self, generation: u64, saved_unix_ms: u64) {
            self.set_fake(FakeOrbState {
                disk: true,
                checkpoints: (1..=generation).collect(),
                consumed: (1..generation).collect(),
                checkpoint_saved_unix_ms: [(generation, saved_unix_ms)].into(),
                ..Default::default()
            });
        }

        fn fake(&self) -> FakeOrbState {
            load_orb_state(self.dir.path(), self.orb).unwrap().unwrap()
        }

        fn set_fake(&self, st: FakeOrbState) {
            let path = self
                .dir
                .path()
                .join("fake")
                .join(format!("{}.json", self.orb));
            std::fs::write(path, serde_json::to_vec(&st).unwrap()).unwrap();
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

        /// An accepted operation for the orb that is not terminal yet.
        async fn claim(&self) {
            self.sql(
                "INSERT INTO receipts(operation_id, orb_id, generation, command_digest,
                    command_json, orb_json, sealed_env, work_deadline_unix_ms,
                    cleanup_deadline_unix_ms, accepted_at_unix_ms, status)
                 VALUES ('op-1', ?1, 3, 'd', '{}', '{}', x'', 0, 0, 0, 'accepted')",
                vec![self.orb.to_string()],
            )
            .await;
        }

        async fn unclaim(&self) {
            self.sql(
                "UPDATE receipts SET status = 'terminal' WHERE operation_id = 'op-1'",
                vec![],
            )
            .await;
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

        /// A check of the orb recorded asleep on checkpoint 3.
        async fn check(&self) -> Option<Checked> {
            let cp = SleepCheckpointRef { generation: 3 };
            check(&self.db, &self.rt, self.orb, &cp, MAX_AGE, unix_ms_now())
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
        assert!(h.check().await.is_none());
        h.assert_kept("11 h old").await;
    }

    /// A checkpoint saved without the guest syncing its disk is kept however old: its
    /// disk may not cold-boot cleanly.
    #[tokio::test]
    async fn keeps_an_unsynced_checkpoint() {
        let h = Host::new(48).await;
        let mut st = h.fake();
        st.checkpoints_unsynced = vec![3];
        h.set_fake(st);
        assert!(h.check().await.is_none());
        h.assert_kept("unsynced").await;
    }

    /// A save time hours ahead of the clock means a clock was wrong: kept.
    #[tokio::test]
    async fn keeps_a_checkpoint_saved_in_the_future() {
        let h = Host::new(0).await;
        h.runtime_sleeps_on(3, unix_ms_now() + 3 * HOUR_MS);
        assert!(h.check().await.is_none());
        h.assert_kept("saved 3 h ahead").await;
    }

    /// Checked again on the actor: an orb a wake has claimed since the sweep looked (an
    /// unfinished operation), one with a restore intent and one recorded otherwise (here
    /// running, or asleep on a newer checkpoint than the runtime has) keep theirs, as
    /// does one whose runtime has moved on to another checkpoint than the sweep saw.
    #[tokio::test]
    async fn keeps_the_checkpoint_of_a_claimed_or_changed_orb() {
        let h = Host::new(13).await;
        let orb = h.orb.to_string();

        h.claim().await;
        assert!(h.check().await.is_none());
        h.assert_kept("unfinished operation").await;
        h.unclaim().await;

        h.sql(
            "UPDATE orbs SET restore_json = '{}' WHERE orb_id = ?1",
            vec![orb.clone()],
        )
        .await;
        assert!(h.check().await.is_none());
        h.assert_kept("restore intent").await;
        h.sql(
            "UPDATE orbs SET restore_json = NULL WHERE orb_id = ?1",
            vec![orb.clone()],
        )
        .await;

        h.record(StableOrbState::Running).await;
        assert!(h.check().await.is_none());
        assert_eq!(h.fake().consumed, [1, 2], "recorded running: kept");

        // The runtime is still on checkpoint 3 and it is due, but the orb is now recorded
        // asleep on 4: only the last check, against the database, keeps it.
        h.record(asleep(4)).await;
        assert!(h.check().await.is_none());
        assert_eq!(h.fake().consumed, [1, 2], "recorded on 4: kept");

        // Woke and slept again since the sweep looked (recorded and on the host: 4).
        h.runtime_sleeps_on(4, unix_ms_now() - 13 * HOUR_MS);
        assert!(h.check().await.is_none());
        assert!(!h.fake().consumed.contains(&4), "another checkpoint: kept");
        assert_eq!(h.last_state().await, Some(OrbState::known(asleep(4))));
    }

    /// A due checkpoint goes: it is never restored, the orb is recorded stopped without
    /// one (as after a failed drain save), so its next start is a cold boot of its
    /// disk; a second check finds nothing to do.
    #[tokio::test]
    async fn drops_a_due_checkpoint_and_records_the_orb_stopped() {
        let h = Host::new(13).await;
        let Some(Checked::Dropped(row)) = h.check().await else {
            panic!("not dropped");
        };
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
        assert!(h.check().await.is_none(), "nothing left to do");
    }

    /// An orb recorded asleep on a checkpoint its host no longer has (a drop cut short
    /// before it was recorded, or one `settle` discarded) is recorded stopped, however
    /// young the checkpoint was, unless something claims the orb.
    #[tokio::test]
    async fn records_an_orb_whose_checkpoint_is_gone() {
        let h = Host::new(1).await;
        let mut st = h.fake();
        st.consumed.push(3);
        h.set_fake(st);

        h.claim().await;
        assert!(h.check().await.is_none());
        assert_eq!(h.last_state().await, Some(OrbState::known(asleep(3))));
        h.unclaim().await;

        let Some(Checked::Gone(row)) = h.check().await else {
            panic!("not recorded");
        };
        let Some(OrbState::Known {
            state: StableOrbState::DiskOnlyStopped { reason },
        }) = &row.last_state
        else {
            panic!("recorded {:?}", row.last_state);
        };
        assert!(reason.contains("missing on disk"), "{reason}");
        assert_eq!(h.last_state().await, row.last_state, "the reported row");
        assert!(h.check().await.is_none(), "nothing left to do");
    }
}
