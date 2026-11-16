//! `orbd.control.v1.Orbs` on the admin socket, and the `orbd orb` and `orbd status` CLI:
//! the coordinator's orbs and why one is stuck, deleting one whose thread is gone (Amp
//! never deletes the orbs of archived threads), and pausing or deleting one Amp no
//! longer drives.

use super::core::{
    BACKEND_CALL_TIMEOUT, Msg, OperatorJob, Policy, demand, shortfalls, state_label,
};
use super::db::Db;
use super::store::{self, CmdHistory};
use super::types::{ReqStatus, Status as ReqResult};
use crate::backend::{Availability, ComputeBackend, OrbDiskUse, PlacementRequest};
use crate::model::{
    ActionResult, AmpOrbId, BackendId, ExecutionTarget, Location, OrbId, OrbRecord, OrbState,
    StableOrbState, unix_ms_now,
};
use orbd_proto::control::v1 as pb;
use orbd_proto::control::v1::dispatch_event::Event;
use orbd_proto::control::v1::orbs_server::Orbs;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

pub struct OrbsService {
    pub(super) core: mpsc::Sender<Msg>,
    pub(super) db: Db,
    pub(super) backends: HashMap<BackendId, Arc<dyn ComputeBackend>>,
    pub(super) policy: Policy,
}

/// Commands older than this are not read for `ListOrbs` (failures, last activity).
const RECENT: Duration = Duration::from_secs(7 * 86_400);
const MAX_FAILURES: usize = 5;

fn internal(e: anyhow::Error) -> Status {
    Status::internal(format!("{e:#}"))
}

/// serde's snake_case name of a unit enum value.
fn snake<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Everything `ListOrbs` and `GetOrb` read from the database in one go.
struct Snapshot {
    orbs: Vec<(OrbRecord, u64)>,
    commands: Vec<CmdHistory>,
    requests: Vec<super::types::Req>,
    pools: HashMap<(String, String), store::PoolUse>,
}

#[tonic::async_trait]
impl Orbs for OrbsService {
    async fn list_orbs(
        &self,
        _: Request<pb::ListOrbsRequest>,
    ) -> Result<Response<pb::ListOrbsResponse>, Status> {
        let snap = self.snapshot().await?;
        let orbs = self.infos(&snap, &snap.orbs).await;
        Ok(Response::new(pb::ListOrbsResponse { orbs }))
    }

    async fn get_orb(
        &self,
        request: Request<pb::GetOrbRequest>,
    ) -> Result<Response<pb::GetOrbResponse>, Status> {
        let r = request.into_inner();
        let snap = self.snapshot().await?;
        let (orb, created) = resolve(&snap.orbs, &r.orb)?.clone();
        let info = self
            .infos(&snap, std::slice::from_ref(&(orb.clone(), created)))
            .await
            .pop()
            .expect("one orb");
        let history = match r.history {
            0 => 20,
            n => n.min(500),
        };
        let id = orb.id;
        let commands = self
            .db
            .call(move |c| store::orb_commands(c, id, history))
            .await
            .map_err(internal)?
            .iter()
            .map(command_pb)
            .collect();
        let requests = snap
            .requests
            .iter()
            .rev()
            .filter(|q| {
                q.amp_endpoint == orb.identity.amp_endpoint
                    && q.amp_orb_id == orb.identity.amp_orb_id
            })
            .map(|q| {
                let res = q.result.as_ref();
                pb::OrbRequest {
                    action: q.action.name().into(),
                    status: q.status.as_str().into(),
                    start_unix_ms: q.start_ms,
                    result: res.map(|r| r.status.label().to_owned()).unwrap_or_default(),
                    message: res.map(|r| r.message.clone()).unwrap_or_default(),
                    operation_id: q.operation_id.map(|o| o.to_string()).unwrap_or_default(),
                }
            })
            .collect();
        let image_ref = match &orb.spec.initial_disk {
            crate::model::InitialDiskSource::Image { image_ref }
            | crate::model::InitialDiskSource::ProjectSnapshot { image_ref, .. } => {
                image_ref.clone()
            }
        };
        Ok(Response::new(pb::GetOrbResponse {
            orb: Some(info),
            amp_endpoint: orb.identity.amp_endpoint.to_string(),
            spec_digest: orb.spec_digest.0.clone(),
            image_ref,
            generation: orb.observation.generation,
            commands,
            requests,
        }))
    }

    async fn delete_orb(
        &self,
        request: Request<pb::DeleteOrbRequest>,
    ) -> Result<Response<pb::DeleteOrbResponse>, Status> {
        let r = request.into_inner();
        let min_asleep = (!r.force).then(|| Duration::from_secs(r.min_asleep_secs));
        let message = self
            .job(&r.amp_orb_id, OperatorJob::Delete { min_asleep })
            .await?;
        Ok(Response::new(pb::DeleteOrbResponse { message }))
    }

    async fn pause_orb(
        &self,
        request: Request<pb::PauseOrbRequest>,
    ) -> Result<Response<pb::PauseOrbResponse>, Status> {
        let r = request.into_inner();
        let message = self.job(&r.amp_orb_id, OperatorJob::Pause).await?;
        Ok(Response::new(pb::PauseOrbResponse { message }))
    }
}

/// Finds the one live orb `query` names: an Amp orb id or a unique prefix of one, a
/// thread id (`T-<uuid>`, or the bare uuid) or an internal orb id.
fn resolve<'a>(orbs: &'a [(OrbRecord, u64)], query: &str) -> Result<&'a (OrbRecord, u64), Status> {
    let q = query.trim();
    if q.is_empty() {
        return Err(Status::invalid_argument("no orb given"));
    }
    if let Some(o) = orbs.iter().find(|(o, _)| o.id.to_string() == q) {
        return Ok(o);
    }
    let q = match q.strip_prefix("T-") {
        Some(rest) => format!("amp-{rest}"),
        None if q.starts_with("amp-") => q.to_owned(),
        None => format!("amp-{q}"),
    };
    if let Some(o) = orbs.iter().find(|(o, _)| o.identity.amp_orb_id.0 == q) {
        return Ok(o);
    }
    let matches: Vec<_> = orbs
        .iter()
        .filter(|(o, _)| o.identity.amp_orb_id.0.starts_with(&q))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(Status::not_found(format!(
            "no orb matches {query:?} (`orbd orb list` lists them; deleted orbs are not kept)"
        ))),
        many => Err(Status::invalid_argument(format!(
            "{query:?} matches {} orbs: {}",
            many.len(),
            many.iter()
                .take(10)
                .map(|(o, _)| o.identity.amp_orb_id.0.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn failure_pb(
    action: &str,
    f: &crate::model::CommandFailure,
    at: u64,
    op: String,
) -> pb::OrbFailure {
    pb::OrbFailure {
        action: action.into(),
        code: snake(&f.code),
        message: f.message.clone(),
        unix_ms: at,
        operation_id: op,
    }
}

fn command_pb(c: &CmdHistory) -> pb::OrbCommand {
    let at = c.terminal_ms.unwrap_or(c.created_ms);
    let (result, failure) = match c.outcome.as_ref().map(|o| &o.result) {
        Some(Ok(ActionResult::Spawned { start, .. })) => {
            (format!("spawned ({})", snake(start)), None)
        }
        Some(Ok(ActionResult::Paused {
            checkpoint: Some(_),
        })) => ("paused (memory checkpoint)".into(), None),
        Some(Ok(ActionResult::Paused { checkpoint: None })) => ("paused (disk only)".into(), None),
        Some(Ok(ActionResult::Deleted)) => ("deleted".into(), None),
        Some(Err(f)) => (
            "failed".into(),
            Some(failure_pb(
                c.action.name(),
                f,
                at,
                c.operation_id.to_string(),
            )),
        ),
        None => (String::new(), None),
    };
    pb::OrbCommand {
        operation_id: c.operation_id.to_string(),
        action: c.action.name().into(),
        generation: c.generation,
        status: c.status.clone(),
        created_unix_ms: c.created_ms,
        accepted_unix_ms: c.accepted_ms.unwrap_or(0),
        finished_unix_ms: c.terminal_ms.unwrap_or(0),
        result,
        failure,
    }
}

/// Outcomes of one orb's commands and of its Amp requests that never became a command,
/// as (time, failure or None for a success).
fn outcomes(
    orb: &OrbRecord,
    created: u64,
    commands: &[&CmdHistory],
    requests: &[super::types::Req],
) -> Vec<(u64, Option<pb::OrbFailure>)> {
    let mut out: Vec<(u64, Option<pb::OrbFailure>)> = commands
        .iter()
        .filter(|c| c.status == "terminal")
        .map(|c| (c.terminal_ms.unwrap_or(c.created_ms), command_pb(c).failure))
        .collect();
    for q in requests {
        if q.amp_endpoint != orb.identity.amp_endpoint
            || q.amp_orb_id != orb.identity.amp_orb_id
            || q.start_ms < created
            || q.operation_id.is_some()
            || q.status != ReqStatus::Finished
        {
            continue;
        }
        let Some(r) = &q.result else { continue };
        let at = q.dispatch_deadline_ms.min(unix_ms_now()).max(q.start_ms);
        let failure = (r.status != ReqResult::Succeeded).then(|| {
            match r.outcome.as_ref().map(|o| &o.result) {
                Some(Err(f)) => failure_pb(q.action.name(), f, q.start_ms, String::new()),
                _ => pb::OrbFailure {
                    action: q.action.name().into(),
                    code: r.status.label().into(),
                    message: r.message.clone(),
                    unix_ms: q.start_ms,
                    operation_id: String::new(),
                },
            }
        });
        out.push((if failure.is_some() { q.start_ms } else { at }, failure));
    }
    out.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    out
}

impl OrbsService {
    async fn snapshot(&self) -> Result<Snapshot, Status> {
        let since = unix_ms_now().saturating_sub(RECENT.as_millis() as u64);
        let backends: Vec<String> = self.backends.keys().map(|b| b.to_string()).collect();
        self.db
            .call(move |c| {
                let mut pools = HashMap::new();
                for b in backends {
                    for (pool, used) in store::pools(c, &b)? {
                        pools.insert((b.clone(), pool), used);
                    }
                }
                Ok(Snapshot {
                    orbs: store::live_orbs_created(c)?,
                    commands: store::recent_commands(c, since)?,
                    requests: store::all_requests(c)?,
                    pools,
                })
            })
            .await
            .map_err(internal)
    }

    /// `OrbInfo` of each of `orbs`, with a capacity check against its host now for
    /// each orb that does not run.
    async fn infos(&self, snap: &Snapshot, orbs: &[(OrbRecord, u64)]) -> Vec<pb::OrbInfo> {
        let mut disk: HashMap<Location, HashMap<OrbId, OrbDiskUse>> = HashMap::new();
        let mut hosts: HashMap<Location, Result<crate::backend::PlacementCandidate, String>> =
            HashMap::new();
        let mut by_orb: HashMap<OrbId, Vec<&CmdHistory>> = HashMap::new();
        for c in &snap.commands {
            by_orb.entry(c.orb_id).or_default().push(c);
        }
        let mut out = Vec::with_capacity(orbs.len());
        for (orb, created) in orbs {
            let backend = self.backends.get(orb.location.backend_id());
            if !disk.contains_key(&orb.location) {
                let d = backend
                    .and_then(|b| b.orb_disk(&orb.location))
                    .unwrap_or_default();
                disk.insert(orb.location.clone(), d);
            }
            let commands = by_orb.get(&orb.id).map(Vec::as_slice).unwrap_or_default();
            let state = &orb.observation.state;
            let running = matches!(state.last_known(), StableOrbState::Running);
            let deleted = matches!(state.last_known(), StableOrbState::Deleted);
            if let Some(backend) = backend
                && !hosts.contains_key(&orb.location)
            {
                let h = self.host(backend, orb).await;
                hosts.insert(orb.location.clone(), h);
            }
            let host = hosts.get(&orb.location);
            let mut wake_blockers = Vec::new();
            if !running && !deleted {
                match host {
                    None => {}
                    Some(Err(reason)) => wake_blockers.push(reason.clone()),
                    Some(Ok(cand)) => {
                        let key = (
                            cand.location.backend_id().to_string(),
                            cand.capacity_pool.clone(),
                        );
                        let used = snap.pools.get(&key).copied().unwrap_or_default();
                        let need = demand(&self.policy, &orb.spec.template);
                        wake_blockers
                            .extend(shortfalls(cand, &used, need).into_iter().map(|(_, s)| s));
                    }
                }
            }
            let outcomes = outcomes(orb, *created, commands, &snap.requests);
            let failures_since_success =
                outcomes.iter().take_while(|(_, f)| f.is_some()).count() as u32;
            let failures = outcomes
                .iter()
                .take_while(|(_, f)| f.is_some())
                .take(MAX_FAILURES)
                .filter_map(|(_, f)| f.clone())
                .collect();
            let last_active = commands
                .iter()
                .filter_map(|c| match c.outcome.as_ref().map(|o| &o.result) {
                    Some(Ok(ActionResult::Spawned { .. } | ActionResult::Paused { .. })) => {
                        c.terminal_ms
                    }
                    _ => None,
                })
                .max()
                .unwrap_or(*created);
            let open_command = commands
                .iter()
                .rev()
                .find(|c| c.status != "terminal")
                .map(|c| command_pb(c));
            let queued_requests = snap
                .requests
                .iter()
                .filter(|q| {
                    q.status == ReqStatus::Queued
                        && q.amp_endpoint == orb.identity.amp_endpoint
                        && q.amp_orb_id == orb.identity.amp_orb_id
                })
                .count() as u32;
            let tmpl = &orb.spec.template;
            let (agent_id, backend_id) = match &orb.location {
                Location::Fleet { agent_id, .. } => (agent_id.to_string(), String::new()),
                Location::External { backend_id, .. } => (String::new(), backend_id.to_string()),
            };
            out.push(pb::OrbInfo {
                amp_orb_id: orb.identity.amp_orb_id.to_string(),
                offering_id: orb.offering_id.to_string(),
                agent_id: if agent_id.is_empty() {
                    backend_id.clone()
                } else {
                    agent_id
                },
                state: state_label(state),
                observed_unix_ms: orb.observation.observed_at_unix_ms,
                orb_id: orb.id.to_string(),
                arch: tmpl.requirements.arch.as_str().into(),
                runtime: match &tmpl.target {
                    ExecutionTarget::Fleet { runtime } => runtime.as_str().into(),
                    ExecutionTarget::Provider { profile } => profile.to_string(),
                },
                resources: Some(tmpl.resources.into()),
                created_unix_ms: *created,
                disk: disk[&orb.location].get(&orb.id).map(|d| pb::OrbDiskUsage {
                    orb_id: orb.id.to_string(),
                    allocated_bytes: d.allocated_bytes,
                    checkpoint_bytes: d.checkpoint_bytes,
                }),
                wake_blockers,
                failures,
                failures_since_success,
                open_command,
                queued_requests,
                last_active_unix_ms: last_active,
                fault: match state {
                    OrbState::Faulted { reason, .. } => reason.clone(),
                    OrbState::Known { .. } => String::new(),
                },
                backend_id,
                overflow_agent: matches!(host, Some(Ok(c)) if c.overflow),
            });
        }
        out
    }

    /// The orb's host as a placement candidate, or why it cannot take the orb now.
    async fn host(
        &self,
        backend: &Arc<dyn ComputeBackend>,
        orb: &OrbRecord,
    ) -> Result<crate::backend::PlacementCandidate, String> {
        let tmpl = &orb.spec.template;
        let req = PlacementRequest {
            target: tmpl.target.clone(),
            resources: tmpl.resources,
            existing: Some(orb.location.clone()),
            project_snapshot: None,
        };
        let cands = match tokio::time::timeout(BACKEND_CALL_TIMEOUT, backend.candidates(req)).await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(format!("its host could not be checked: {e}")),
            Err(_) => return Err("its host could not be checked: timed out".into()),
        };
        let host = match &orb.location {
            Location::Fleet { agent_id, .. } => agent_id.to_string(),
            Location::External { backend_id, .. } => backend_id.to_string(),
        };
        match cands.into_iter().find(|c| c.location == orb.location) {
            None => Err(format!("{host} is not a known host")),
            Some(c) => match &c.availability {
                Availability::Available => Ok(c),
                Availability::Draining => Err(format!("{host} is shutting down")),
                Availability::Unavailable { reason } => {
                    Err(format!("{host} is unavailable: {reason}"))
                }
            },
        }
    }

    /// Runs `job` on the orb through the coordinator and waits for its result message.
    async fn job(&self, amp_orb_id: &str, job: OperatorJob) -> Result<String, Status> {
        let amp_orb_id =
            AmpOrbId::parse(amp_orb_id).map_err(|_| Status::invalid_argument("invalid orb id"))?;
        let (tx, mut rx) = mpsc::channel(64);
        self.core
            .send(Msg::OperatorJob {
                amp_orb_id,
                job,
                tx,
            })
            .await
            .map_err(|_| Status::unavailable("coordinator is shutting down"))?;
        while let Some(ev) = rx.recv().await {
            if let Some(Event::Result(res)) = ev?.event {
                return match pb::DispatchStatus::try_from(res.status) {
                    Ok(pb::DispatchStatus::Succeeded) => Ok(res.message),
                    Ok(pb::DispatchStatus::Unavailable) => Err(Status::unavailable(res.message)),
                    _ => Err(Status::aborted(res.message)),
                };
            }
        }
        Err(Status::unavailable(
            "the coordinator stopped before the job finished",
        ))
    }
}
