//! `orbd.control.v1.Orbs` on the admin socket, and the `orbd orb list|pause|delete` CLI:
//! the coordinator's orbs, deleting one whose thread is gone (Amp never deletes the
//! orbs of archived threads), and pausing or deleting one Amp no longer drives.

use super::core::{Msg, OperatorJob, state_label};
use super::db::Db;
use super::store;
use crate::model::{AmpOrbId, Location, unix_ms_now};
use orbd_proto::control::v1 as pb;
use orbd_proto::control::v1::dispatch_event::Event;
use orbd_proto::control::v1::orbs_server::Orbs;
use std::time::Duration;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

pub struct OrbsService {
    pub(super) core: mpsc::Sender<Msg>,
    pub(super) db: Db,
}

#[tonic::async_trait]
impl Orbs for OrbsService {
    async fn list_orbs(
        &self,
        _: Request<pb::ListOrbsRequest>,
    ) -> Result<Response<pb::ListOrbsResponse>, Status> {
        let orbs = self
            .db
            .call(|c| store::live_orbs(c))
            .await
            .map_err(|e| Status::internal(format!("{e:#}")))?;
        let orbs = orbs
            .into_iter()
            .map(|o| pb::OrbInfo {
                amp_orb_id: o.identity.amp_orb_id.to_string(),
                offering_id: o.offering_id.to_string(),
                agent_id: match &o.location {
                    Location::Fleet { agent_id, .. } => agent_id.to_string(),
                    Location::External { backend_id, .. } => backend_id.to_string(),
                },
                state: state_label(&o.observation.state),
                observed_unix_ms: o.observation.observed_at_unix_ms,
            })
            .collect();
        Ok(Response::new(pb::ListOrbsResponse { orbs }))
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

impl OrbsService {
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

// --- CLI ---------------------------------------------------------------------------

async fn client(
    socket: &std::path::Path,
) -> anyhow::Result<pb::orbs_client::OrbsClient<tonic::transport::Channel>> {
    use anyhow::Context;
    let channel = crate::amp::dispatch::connect(socket)
        .await
        .with_context(|| {
            format!(
                "connecting to {} (is the coordinator running?)",
                socket.display()
            )
        })?;
    Ok(pb::orbs_client::OrbsClient::new(channel))
}

fn age(ms: u64) -> String {
    let m = ms / 60_000;
    match m {
        0..60 => format!("{m}m"),
        60..1440 => format!("{}h", m / 60),
        _ => format!("{}d", m / 1440),
    }
}

/// One line per orb: Amp orb id, state and for how long, agent, offering.
pub async fn cli_list(socket: &std::path::Path) -> anyhow::Result<String> {
    let r = client(socket)
        .await?
        .list_orbs(pb::ListOrbsRequest {})
        .await
        .map_err(|s| anyhow::anyhow!("{}", s.message()))?;
    let now = unix_ms_now();
    let mut out = String::new();
    for o in r.into_inner().orbs {
        out.push_str(&format!(
            "{}\t{} for {}\t{}\t{}\n",
            o.amp_orb_id,
            o.state,
            age(now.saturating_sub(o.observed_unix_ms)),
            o.agent_id,
            o.offering_id
        ));
    }
    Ok(out)
}

/// Deletes one orb if it has been asleep, with no job, for `min_asleep`; with `None`,
/// whatever it is doing.
pub async fn cli_delete(
    socket: &std::path::Path,
    amp_orb_id: &str,
    min_asleep: Option<Duration>,
) -> anyhow::Result<String> {
    let r = client(socket)
        .await?
        .delete_orb(pb::DeleteOrbRequest {
            amp_orb_id: amp_orb_id.to_owned(),
            min_asleep_secs: min_asleep.unwrap_or_default().as_secs(),
            force: min_asleep.is_none(),
        })
        .await
        .map_err(|s| anyhow::anyhow!("{amp_orb_id} not deleted: {}", s.message()))?;
    Ok(format!("{amp_orb_id} deleted: {}", r.into_inner().message))
}

/// Pauses one orb as Amp's `pause` would.
pub async fn cli_pause(socket: &std::path::Path, amp_orb_id: &str) -> anyhow::Result<String> {
    let r = client(socket)
        .await?
        .pause_orb(pb::PauseOrbRequest {
            amp_orb_id: amp_orb_id.to_owned(),
        })
        .await
        .map_err(|s| anyhow::anyhow!("{amp_orb_id} not paused: {}", s.message()))?;
    Ok(format!("{amp_orb_id} paused: {}", r.into_inner().message))
}
