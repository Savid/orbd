//! Sleeps held in RAM. Most sleeps end within minutes, and writing every sleep's memory
//! (GiB each) to disk is most of what a busy agent writes. So a pause the agent allows
//! to hold (see the agent's `ORBD_SLEEP_HOLD_MINUTES`) does what a sleep does up to the
//! save: the guest syncs its disk, the vCPUs are paused (with the same care
//! for half-done I/O), and the disk file is fsynced. Then, instead of the save, the hold
//! is recorded in `<orb>/held.json` (fsynced) and the VMM is left paused, holding its
//! memory. The orb is reported asleep on the checkpoint generation it was given.
//!
//! * A wake of that checkpoint resumes the VM in place and removes the record.
//! * [`flush_held`](crate::runtime::Runtime::flush_held) writes the checkpoint exactly as
//!   a sleep would (into `<gen>.tmp`, disk fsync, manifest), then kills the VMM,
//!   publishes it and removes the record. A failed write leaves the orb held.
//! * Dropping the checkpoint (`discard_checkpoint`) kills the VMM: the orb cold-boots.
//!
//! Recovery: the record names the launch it holds. Reconciliation of a live VMM with a
//! matching record keeps it held (discarding an unfinished write, finishing one whose
//! files are complete); a VMM gone (the agent's container stopped without a drain, the
//! host crashed) loses only RAM: the record is removed and the orb is stopped without a
//! checkpoint, its disk as the guest synced it before the pause.

use super::{FirecrackerRuntime, LaunchRecord, Observed, api_err, marker};
use crate::model::{OrbId, SleepCheckpointRef, unix_ms_now};
use crate::runtime::vm::fsutil::{fsync_dir, read_json, write_json_atomic};
use crate::runtime::vm::process::Process;
use crate::runtime::vm::{io_err, log};
use crate::runtime::{CheckpointInfo, HeldSleep, OpContext, RuntimeError};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// `<orb>/held.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct HeldRecord {
    pub generation: u64,
    pub since_unix_ms: u64,
    /// The launch whose VMM holds the memory.
    pub nonce: String,
    /// The guest's boot id from PrepareSleep, if it answered (the checkpoint's manifest
    /// records it when the hold is written).
    pub guest_boot_id: Option<String>,
}

/// A held sleep as the runtime tracks it (from the record, plus the VMM's pid and the
/// orb's memory size).
#[derive(Clone, Debug)]
pub(super) struct Held {
    pub record: HeldRecord,
    pub pid: i32,
    pub memory_bytes: u64,
    /// The VMM's `oom_score_adj` before the hold, restored on wake.
    pub oom_before: Option<String>,
}

/// Anonymous memory resident in `pid` (`RssAnon`: the guest's RAM, not the file-backed
/// pages a VM restored from a checkpoint maps, which the kernel can drop), 0 if it is
/// gone.
fn resident_bytes(pid: i32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("RssAnon:"))?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .map_or(0, |kib| kib.saturating_mul(1024))
}

/// Makes `pid` the OOM killer's first choice while it holds a sleep (it loses only RAM;
/// its disk is synced). Returns its value before. Best effort.
fn oom_first(pid: i32) -> Option<String> {
    let path = format!("/proc/{pid}/oom_score_adj");
    let before = std::fs::read_to_string(&path)
        .ok()
        .map(|v| v.trim().to_owned());
    if let Err(e) = std::fs::write(&path, "1000") {
        tracing::debug!(pid, error = %e, "setting a held VMM's oom_score_adj");
    }
    before
}

/// Gives `pid` back the `oom_score_adj` it had before its hold (0 if unknown). Best
/// effort.
fn oom_restore(pid: i32, before: Option<&str>) {
    let v = before.filter(|v| *v != "1000").unwrap_or("0");
    if let Err(e) = std::fs::write(format!("/proc/{pid}/oom_score_adj"), v) {
        tracing::debug!(pid, error = %e, "restoring a woken VMM's oom_score_adj");
    }
}

impl FirecrackerRuntime {
    fn held_path(&self, orb: OrbId) -> std::path::PathBuf {
        self.orb_paths(orb).dir.join("held.json")
    }

    pub(super) fn read_held(&self, orb: OrbId) -> Option<HeldRecord> {
        read_json(&self.held_path(orb)).ok().flatten()
    }

    /// Forgets the orb's hold, durably.
    pub(super) fn clear_held(&self, orb: OrbId) -> Result<(), RuntimeError> {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&orb);
        let path = self.held_path(orb);
        match std::fs::remove_file(&path) {
            Ok(()) => fsync_dir(&self.orb_paths(orb).dir).map_err(io_err),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(e)),
        }
        .inspect(|()| self.held_gauge())
    }

    pub(super) fn held_gauge(&self) {
        let n = self.held.lock().unwrap_or_else(|e| e.into_inner()).len();
        metrics::gauge!("orbd_agent_held_orbs").set(n as f64);
    }

    /// Records the paused VMM of `record` as holding the orb's sleep on `generation`,
    /// the caller holding the orb's lock.
    pub(super) fn record_held(
        &self,
        orb: OrbId,
        generation: u64,
        record: &LaunchRecord,
        pid: i32,
        guest_boot_id: Option<String>,
    ) -> Result<(), RuntimeError> {
        let held = HeldRecord {
            generation,
            since_unix_ms: unix_ms_now(),
            nonce: record.nonce.clone(),
            guest_boot_id,
        };
        write_json_atomic(&self.held_path(orb), &held).map_err(io_err)?;
        let memory_bytes = self.read_recipe(orb).map_or(0, |r| r.memory_bytes);
        self.held.lock().unwrap_or_else(|e| e.into_inner()).insert(
            orb,
            Held {
                record: held,
                pid,
                memory_bytes,
                oom_before: oom_first(pid),
            },
        );
        self.held_gauge();
        Ok(())
    }

    /// Reconciliation of a live VMM whose launch the orb's hold record names: None if it
    /// was killed (a complete write is then published from its files).
    pub(super) async fn settle_held(
        &self,
        orb: OrbId,
        proc: Process,
        record: &LaunchRecord,
        held: HeldRecord,
    ) -> Result<Option<Observed>, RuntimeError> {
        let info = match self.api(orb).info(super::SETTLE_TIMEOUT).await {
            Ok(i) => i,
            Err(e) => {
                return Ok(Some(Observed::Inconsistent(format!(
                    "held Firecracker process {} does not answer: {e}",
                    proc.pid
                ))));
            }
        };
        if info.id != marker(record) {
            return Ok(Some(Observed::Inconsistent(format!(
                "Firecracker process {} is not this orb's launch",
                proc.pid
            ))));
        }
        let cps = self.checkpoints(orb);
        match info.state.as_str() {
            "Paused" => {
                if cps.complete_tmp() == Some(held.generation) {
                    // A write finished but its agent died before the VMM exited.
                    tracing::warn!(%orb, generation = held.generation, "finishing an interrupted write of a held sleep");
                    self.kill(orb, &proc).await?;
                    self.clear_held(orb)?;
                    return Ok(None);
                }
                cps.discard_tmps()?;
                let generation = held.generation;
                let memory_bytes = self.read_recipe(orb).map_or(0, |r| r.memory_bytes);
                self.held.lock().unwrap_or_else(|e| e.into_inner()).insert(
                    orb,
                    Held {
                        record: held,
                        pid: proc.pid,
                        memory_bytes,
                        // Adopted: what it had before is not known.
                        oom_before: {
                            oom_first(proc.pid);
                            None
                        },
                    },
                );
                self.held_gauge();
                Ok(Some(Observed::Held { generation, proc }))
            }
            "Running" => {
                // Resumed by a wake that did not get to remove the record.
                tracing::info!(%orb, "held VM was resumed; removing its hold record");
                self.clear_held(orb)?;
                cps.discard_tmps()?;
                cps.discard_all()?;
                Ok(Some(Observed::Running(proc)))
            }
            other => Ok(Some(Observed::Inconsistent(format!(
                "held Firecracker process {} is {other}",
                proc.pid
            )))),
        }
    }

    /// Wakes the held orb: resumes its VM in place. The caller holds the orb's lock.
    pub(super) async fn resume_held(
        &self,
        orb: OrbId,
        generation: u64,
        proc: &Process,
        ctx: &OpContext,
    ) -> Result<(), RuntimeError> {
        let started = std::time::Instant::now();
        let before = self
            .held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&orb)
            .and_then(|h| h.oom_before.clone());
        oom_restore(proc.pid, before.as_deref());
        self.api(orb)
            .set_state("Resumed", super::API_TIMEOUT)
            .await
            .map_err(api_err)?;
        crate::crash_point!("firecracker::wake::after_resume");
        self.clear_held(orb)?;
        let ms = started.elapsed().as_millis();
        tracing::info!(%orb, generation, ms, "woke from RAM");
        log(
            ctx,
            &format!("woke from RAM (checkpoint {generation} was never written) in {ms} ms"),
        );
        Ok(())
    }

    /// Kills the held orb's VMM: its sleep is dropped and it cold-boots on its next
    /// wake. The caller holds the orb's lock.
    pub(super) async fn drop_held(&self, orb: OrbId, proc: &Process) -> Result<(), RuntimeError> {
        self.kill(orb, proc).await?;
        self.clear_held(orb)?;
        tracing::info!(%orb, "dropped a sleep held in RAM; the orb cold-boots on its next wake");
        Ok(())
    }

    /// The held sleep's checkpoint info: saved when the VM was paused.
    pub(super) fn held_info(&self, orb: OrbId, generation: u64) -> Option<CheckpointInfo> {
        let h = self.read_held(orb).filter(|h| h.generation == generation)?;
        Some(CheckpointInfo {
            saved_unix_ms: h.since_unix_ms,
            bytes: 0,
            synced: h.guest_boot_id.is_some(),
        })
    }

    /// Every held sleep this runtime tracks.
    pub(super) fn held_sleeps(&self) -> Vec<HeldSleep> {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(orb, h)| HeldSleep {
                orb: *orb,
                checkpoint: SleepCheckpointRef {
                    generation: h.record.generation,
                },
                since_unix_ms: h.record.since_unix_ms,
                resident_bytes: resident_bytes(h.pid),
                memory_bytes: h.memory_bytes,
            })
            .collect()
    }

    /// After a failed write of a held sleep: once Firecracker executes no snapshot
    /// request any more, discards the partial files; the VM stays paused (held).
    pub(super) async fn abort_flush(&self, orb: OrbId, generation: u64, wait: Duration) {
        match self.api(orb).info(wait).await {
            Ok(_) => {
                if let Err(e) = self.checkpoints(orb).discard_tmp(generation) {
                    tracing::warn!(%orb, generation, error = %e, "discarding a failed write of a held sleep");
                }
            }
            Err(e) => {
                tracing::warn!(%orb, generation, error = %e, "Firecracker still busy after a failed write of a held sleep; its files are discarded later")
            }
        }
    }
}
