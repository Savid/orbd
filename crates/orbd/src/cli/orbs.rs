//! `orbd orb list|show|pause|delete`.

use super::{CliError, Exit, age, gib, orbs_client, size, table, to_json, utc};
use crate::model::unix_ms_now;
use orbd_proto::control::v1 as pb;
use serde::Serialize;
use std::path::Path;
use std::time::Duration;

/// An orb as `--json` prints it.
#[derive(Clone, Debug, Serialize)]
pub struct OrbJson {
    pub amp_orb_id: String,
    /// Amp thread of the orb (`T-<uuid>`).
    pub thread_id: String,
    /// Internal id: the orb's directory on its agent (`<state_dir>/orbs/<orb_id>`).
    pub orb_id: String,
    /// running, asleep, stopped, uncreated, or faulted (<last known state>).
    pub state: String,
    pub state_since_unix_ms: u64,
    pub state_for_secs: u64,
    /// Agent (or other backend) the orb lives on; orbs never move.
    pub agent: String,
    pub overflow_agent: bool,
    pub orb_type: String,
    pub arch: String,
    pub runtime: String,
    pub vcpus: u32,
    pub memory_bytes: u64,
    /// Disk size (sparse; see `disk_allocated_bytes`).
    pub disk_size_bytes: u64,
    /// On the agent's disk: all of the orb's files, and the memory checkpoint among them.
    /// Null when the agent does not report it (orbd < 0.1.3).
    pub disk_allocated_bytes: Option<u64>,
    pub checkpoint_bytes: Option<u64>,
    pub created_unix_ms: u64,
    pub last_active_unix_ms: u64,
    pub fault: Option<String>,
    /// Why it could not start on its agent right now; empty when it would (or it runs).
    pub wake_blockers: Vec<String>,
    pub failures_since_success: u32,
    /// Latest first, at most 5.
    pub failures: Vec<FailureJson>,
    pub open_command: Option<CommandJson>,
    pub queued_requests: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct FailureJson {
    pub action: String,
    pub code: String,
    pub message: String,
    pub unix_ms: u64,
    /// Null for a request refused before a command was created (e.g. no capacity).
    pub operation_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CommandJson {
    pub operation_id: String,
    pub action: String,
    pub generation: u64,
    pub status: String,
    pub created_unix_ms: u64,
    pub accepted_unix_ms: Option<u64>,
    pub finished_unix_ms: Option<u64>,
    pub result: String,
    pub failure: Option<FailureJson>,
}

fn nz(v: u64) -> Option<u64> {
    (v > 0).then_some(v)
}

fn failure(f: &pb::OrbFailure) -> FailureJson {
    FailureJson {
        action: f.action.clone(),
        code: f.code.clone(),
        message: f.message.clone(),
        unix_ms: f.unix_ms,
        operation_id: (!f.operation_id.is_empty()).then(|| f.operation_id.clone()),
    }
}

fn command(c: &pb::OrbCommand) -> CommandJson {
    CommandJson {
        operation_id: c.operation_id.clone(),
        action: c.action.clone(),
        generation: c.generation,
        status: c.status.clone(),
        created_unix_ms: c.created_unix_ms,
        accepted_unix_ms: nz(c.accepted_unix_ms),
        finished_unix_ms: nz(c.finished_unix_ms),
        result: c.result.clone(),
        failure: c.failure.as_ref().map(failure),
    }
}

pub fn thread_id(amp_orb_id: &str) -> String {
    match amp_orb_id.strip_prefix("amp-") {
        Some(rest) => format!("T-{rest}"),
        None => String::new(),
    }
}

impl OrbJson {
    pub fn from_pb(o: &pb::OrbInfo, now: u64) -> Self {
        let r = o.resources.unwrap_or_default();
        Self {
            amp_orb_id: o.amp_orb_id.clone(),
            thread_id: thread_id(&o.amp_orb_id),
            orb_id: o.orb_id.clone(),
            state: o.state.clone(),
            state_since_unix_ms: o.observed_unix_ms,
            state_for_secs: now.saturating_sub(o.observed_unix_ms) / 1000,
            agent: o.agent_id.clone(),
            overflow_agent: o.overflow_agent,
            orb_type: o.offering_id.clone(),
            arch: o.arch.clone(),
            runtime: o.runtime.clone(),
            vcpus: r.vcpus,
            memory_bytes: r.memory_bytes,
            disk_size_bytes: r.disk_bytes,
            disk_allocated_bytes: o.disk.as_ref().map(|d| d.allocated_bytes),
            checkpoint_bytes: o.disk.as_ref().map(|d| d.checkpoint_bytes),
            created_unix_ms: o.created_unix_ms,
            last_active_unix_ms: o.last_active_unix_ms,
            fault: (!o.fault.is_empty()).then(|| o.fault.clone()),
            wake_blockers: o.wake_blockers.clone(),
            failures_since_success: o.failures_since_success,
            failures: o.failures.iter().map(failure).collect(),
            open_command: o.open_command.as_ref().map(command),
            queued_requests: o.queued_requests,
        }
    }

    pub fn running(&self) -> bool {
        self.state == "running"
    }

    pub fn asleep(&self) -> bool {
        self.state == "asleep" || self.state == "stopped"
    }

    /// Something is wrong with it: a fault, failures since its last success, or a
    /// command in flight for over 10 minutes.
    pub fn has_problem(&self, now: u64) -> bool {
        self.fault.is_some() || self.failures_since_success > 0 || self.stuck_for(now).is_some()
    }

    /// How long a running orb has gone without Amp starting or pausing it, if a day or
    /// more: Amp never touches the orb of a deleted thread again. (Not how long it has
    /// run: an agent restart restores it, which renews its state.)
    pub fn undriven_for(&self, now: u64) -> Option<u64> {
        let t = now.saturating_sub(self.last_active_unix_ms);
        (self.running() && self.open_command.is_none() && t >= 86_400_000).then_some(t)
    }

    /// How long its open command has been in flight, if over 10 minutes.
    pub fn stuck_for(&self, now: u64) -> Option<u64> {
        let c = self.open_command.as_ref()?;
        let t = now.saturating_sub(c.created_unix_ms);
        (t > 10 * 60_000).then_some(t)
    }

    /// The resources a blocker names: `memory`, `disk`, `vCPUs`, or the whole text.
    fn blocker_short(&self) -> String {
        let mut v: Vec<&str> = self
            .wake_blockers
            .iter()
            .map(|b| match b.split_once(':') {
                Some((k, _)) if !k.contains(' ') => k,
                _ => b.as_str(),
            })
            .collect();
        v.dedup();
        v.join(", ")
    }

    /// One-line note for `orb list`.
    fn note(&self, now: u64) -> String {
        let mut n = Vec::new();
        if let Some(f) = &self.fault {
            n.push(format!("fault: {f}"));
        }
        if self.failures_since_success > 0 {
            let last = &self.failures[0];
            let times = match self.failures_since_success {
                1 => String::new(),
                k => format!(" ({k} failures)"),
            };
            if !self.wake_blockers.is_empty() {
                n.push(format!("can't wake: {}{times}", self.blocker_short()));
            } else {
                n.push(format!("{} failed: {}{times}", last.action, last.code));
            }
        } else if !self.wake_blockers.is_empty() {
            n.push(format!("would not fit now: {}", self.blocker_short()));
        }
        if let Some(c) = &self.open_command {
            n.push(format!(
                "{} in flight {}",
                c.action,
                age(now.saturating_sub(c.created_unix_ms))
            ));
        }
        if self.queued_requests > 0 {
            n.push(format!("{} queued", self.queued_requests));
        }
        n.join("; ")
    }
}

/// `orb list` filters.
#[derive(Clone, Debug, Default)]
pub struct ListFilter {
    pub agent: Option<String>,
    pub state: Option<String>,
    /// Asleep or stopped for at least this long.
    pub asleep_for: Option<Duration>,
    pub problems: bool,
}

pub async fn fetch(socket: &Path) -> Result<Vec<pb::OrbInfo>, CliError> {
    Ok(orbs_client(socket)
        .await?
        .list_orbs(pb::ListOrbsRequest {})
        .await
        .map_err(|s| CliError::from_status(&s, Some("listing orbs")))?
        .into_inner()
        .orbs)
}

pub async fn list(socket: &Path, f: &ListFilter, json: bool) -> Result<String, CliError> {
    let now = unix_ms_now();
    let orbs: Vec<OrbJson> = fetch(socket)
        .await?
        .iter()
        .map(|o| OrbJson::from_pb(o, now))
        .filter(|o| f.agent.as_ref().is_none_or(|a| &o.agent == a))
        .filter(|o| {
            f.state
                .as_ref()
                .is_none_or(|s| o.state == *s || o.state.starts_with(&format!("{s} ")))
        })
        .filter(|o| {
            f.asleep_for
                .is_none_or(|d| o.asleep() && o.state_for_secs >= d.as_secs())
        })
        .filter(|o| !f.problems || o.has_problem(now))
        .collect();
    if json {
        #[derive(Serialize)]
        struct Out {
            now_unix_ms: u64,
            orbs: Vec<OrbJson>,
        }
        return Ok(to_json(&Out {
            now_unix_ms: now,
            orbs,
        }));
    }
    if orbs.is_empty() {
        return Ok("no orbs\n".into());
    }
    let rows: Vec<Vec<String>> = orbs
        .iter()
        .map(|o| {
            vec![
                o.amp_orb_id.clone(),
                o.state.clone(),
                age(o.state_for_secs * 1000),
                o.agent.clone(),
                o.orb_type.clone(),
                o.arch.clone(),
                size(o.disk_allocated_bytes),
                size(o.checkpoint_bytes),
                o.note(now),
            ]
        })
        .collect();
    Ok(table(
        &[
            "ORB", "STATE", "FOR", "AGENT", "TYPE", "ARCH", "DISK", "CKPT", "NOTE",
        ],
        &rows,
    ))
}

#[derive(Serialize)]
struct ShowJson {
    now_unix_ms: u64,
    #[serde(flatten)]
    orb: OrbJson,
    amp_endpoint: String,
    image_ref: String,
    spec_digest: String,
    generation: u64,
    /// Latest first.
    commands: Vec<CommandJson>,
    /// Amp requests the coordinator holds (finished ones for about an hour), latest first.
    requests: Vec<RequestJson>,
    /// Suggested next steps.
    hints: Vec<String>,
}

#[derive(Serialize)]
struct RequestJson {
    action: String,
    status: String,
    start_unix_ms: u64,
    result: Option<String>,
    message: Option<String>,
    operation_id: Option<String>,
}

pub async fn show(socket: &Path, orb: &str, history: u32, json: bool) -> Result<String, CliError> {
    let r = orbs_client(socket)
        .await?
        .get_orb(pb::GetOrbRequest {
            orb: orb.to_owned(),
            history,
        })
        .await
        .map_err(|s| CliError::from_status(&s, None))?
        .into_inner();
    let now = unix_ms_now();
    let info = r.orb.unwrap_or_default();
    let o = OrbJson::from_pb(&info, now);
    let hints = hints(&o, now);
    let commands: Vec<CommandJson> = r.commands.iter().map(command).collect();
    let requests: Vec<RequestJson> = r
        .requests
        .iter()
        .map(|q| RequestJson {
            action: q.action.clone(),
            status: q.status.clone(),
            start_unix_ms: q.start_unix_ms,
            result: (!q.result.is_empty()).then(|| q.result.clone()),
            message: (!q.message.is_empty()).then(|| q.message.clone()),
            operation_id: (!q.operation_id.is_empty()).then(|| q.operation_id.clone()),
        })
        .collect();
    if json {
        return Ok(to_json(&ShowJson {
            now_unix_ms: now,
            orb: o,
            amp_endpoint: r.amp_endpoint,
            image_ref: r.image_ref,
            spec_digest: r.spec_digest,
            generation: r.generation,
            commands,
            requests,
            hints,
        }));
    }

    let mut out = String::new();
    let mut kv = |k: &str, v: String| out.push_str(&format!("  {k:<11} {v}\n"));
    let ago = |t: u64| age(now.saturating_sub(t));
    kv("thread", o.thread_id.clone());
    kv(
        "orb id",
        format!("{} (its directory on the agent)", o.orb_id),
    );
    kv(
        "state",
        format!(
            "{} for {} (since {}), generation {}",
            o.state,
            age(o.state_for_secs * 1000),
            utc(o.state_since_unix_ms),
            r.generation
        ),
    );
    if let Some(f) = &o.fault {
        kv("fault", f.clone());
    }
    kv(
        "agent",
        format!(
            "{}{}",
            o.agent,
            if o.overflow_agent { " (overflow)" } else { "" }
        ),
    );
    kv(
        "type",
        format!(
            "{}: {} vCPUs, {} memory, {} disk, {}, {}",
            o.orb_type,
            o.vcpus,
            gib(o.memory_bytes),
            gib(o.disk_size_bytes),
            o.arch,
            o.runtime
        ),
    );
    kv(
        "on disk",
        match (o.disk_allocated_bytes, o.checkpoint_bytes) {
            (Some(a), Some(c)) => format!("{} ({} of it the memory checkpoint)", gib(a), gib(c)),
            _ => "not reported by the agent".into(),
        },
    );
    kv("image", r.image_ref.clone());
    kv(
        "created",
        format!(
            "{} ({} ago)",
            utc(o.created_unix_ms),
            ago(o.created_unix_ms)
        ),
    );
    kv("last active", format!("{} ago", ago(o.last_active_unix_ms)));
    if !o.running() && o.state != "deleted" {
        kv(
            "wake check",
            if o.wake_blockers.is_empty() {
                "fits on its agent now".into()
            } else {
                format!("would be refused: {}", o.wake_blockers.join("; "))
            },
        );
    }
    match &o.open_command {
        Some(c) => kv(
            "in flight",
            format!(
                "{} (operation {}, {}, for {}), {} queued behind it",
                c.action,
                c.operation_id,
                c.status,
                ago(c.created_unix_ms),
                o.queued_requests
            ),
        ),
        None if o.queued_requests > 0 => kv("in flight", format!("{} queued", o.queued_requests)),
        None => {}
    }
    if o.failures_since_success > 0 {
        kv(
            "failing",
            format!(
                "{} {} failures since its last successful {}:",
                o.failures_since_success, o.failures[0].action, o.failures[0].action
            ),
        );
        for f in &o.failures {
            out.push_str(&format!(
                "                {} ago  {}: {}\n",
                ago(f.unix_ms),
                f.code,
                f.message
            ));
        }
    }

    out.insert_str(0, &format!("{}\n", o.amp_orb_id));
    if !commands.is_empty() {
        out.push_str("\nCOMMANDS (latest first)\n");
        let rows: Vec<Vec<String>> = commands
            .iter()
            .map(|c| {
                let took = match c.finished_unix_ms {
                    Some(f) => format!(
                        "{:.1}s",
                        f.saturating_sub(c.created_unix_ms) as f64 / 1000.0
                    ),
                    None => "-".into(),
                };
                let result = match &c.failure {
                    Some(f) => format!("failed: {}: {}", f.code, f.message),
                    None => c.result.clone(),
                };
                vec![
                    format!("{} ago", ago(c.created_unix_ms)),
                    c.action.clone(),
                    c.generation.to_string(),
                    c.status.clone(),
                    took,
                    result,
                ]
            })
            .collect();
        out.push_str(&table(
            &["WHEN", "ACTION", "GEN", "STATUS", "TOOK", "RESULT"],
            &rows,
        ));
    }
    if !requests.is_empty() {
        out.push_str("\nAMP REQUESTS (latest first; finished ones are kept for about an hour)\n");
        let rows: Vec<Vec<String>> = requests
            .iter()
            .map(|q| {
                vec![
                    format!("{} ago", ago(q.start_unix_ms)),
                    q.action.clone(),
                    q.status.clone(),
                    q.message.clone().unwrap_or_default(),
                ]
            })
            .collect();
        out.push_str(&table(&["WHEN", "ACTION", "STATUS", "RESULT"], &rows));
    }
    if !hints.is_empty() {
        out.push_str("\nNEXT\n");
        for h in &hints {
            out.push_str(&format!("  - {h}\n"));
        }
    }
    Ok(out)
}

/// What an operator could do about the orb's state, if anything.
pub fn hints(o: &OrbJson, now: u64) -> Vec<String> {
    let mut h = Vec::new();
    let id = &o.amp_orb_id;
    let blocked = |what: &str| o.wake_blockers.iter().any(|b| b.starts_with(what));
    if o.wake_blockers
        .iter()
        .any(|b| b.contains("unavailable") || b.contains("shutting down"))
    {
        h.push(format!(
            "its agent {} is down; orbs never move, so it wakes once the agent is back (`orbd agent list`)",
            o.agent
        ));
    }
    if blocked("memory") || blocked("vCPUs") {
        h.push(format!(
            "it needs {} on {}, which is full; orbs never move to another agent. Free room by pausing an orb there (`orbd orb list --agent {} --state running`, then `orbd orb pause <id>`), or let Amp pause idle ones",
            gib(o.memory_bytes),
            o.agent,
            o.agent
        ));
    }
    if blocked("disk") {
        h.push(format!(
            "{} is short of disk: delete orbs of archived threads there (`orbd orb list --agent {} --asleep-days 3`, then `orbd orb delete <id>`)",
            o.agent, o.agent
        ));
    }
    if o.fault.is_some() {
        h.push(format!(
            "faulted: read the agent's log on {} for orb {} (and `<state_dir>/orbs/{}/logs/`)",
            o.agent, o.orb_id, o.orb_id
        ));
    }
    if let Some(t) = o.stuck_for(now) {
        h.push(format!(
            "a command has been in flight for {}; the agent's log on {} says what it is doing",
            age(t),
            o.agent
        ));
    }
    if o.failures_since_success > 0 && o.wake_blockers.is_empty() && o.fault.is_none() {
        h.push(format!(
            "the last {} failed ({}); the agent's log on {} has the details",
            o.failures[0].action, o.failures[0].code, o.agent
        ));
    }
    if let Some(t) = o.undriven_for(now) {
        h.push(format!(
            "running with no spawn or pause from Amp for {}: if its thread is gone, Amp will not pause it; `orbd orb pause {id}`",
            age(t)
        ));
    }
    if o.asleep() && o.state_for_secs >= 3 * 86_400 {
        h.push(format!(
            "asleep for {}: if its thread is archived, `orbd orb delete {id}` frees {}",
            age(o.state_for_secs * 1000),
            o.disk_allocated_bytes.map_or("its disk".into(), gib)
        ));
    }
    h
}

pub async fn delete(
    socket: &Path,
    amp_orb_id: &str,
    min_asleep: Option<Duration>,
    json: bool,
) -> Result<String, CliError> {
    let r = orbs_client(socket)
        .await?
        .delete_orb(pb::DeleteOrbRequest {
            amp_orb_id: amp_orb_id.to_owned(),
            min_asleep_secs: min_asleep.unwrap_or_default().as_secs(),
            force: min_asleep.is_none(),
        })
        .await
        .map_err(|s| {
            let e = CliError::from_status(&s, Some(&format!("{amp_orb_id} not deleted")));
            match e.exit {
                Exit::Refused => e.hint(
                    "`orbd orb show` says what it is doing; `orbd orb pause` it, or wait, then delete again",
                ),
                _ => e,
            }
        })?;
    done(amp_orb_id, "deleted", r.into_inner().message, json)
}

pub async fn pause(socket: &Path, amp_orb_id: &str, json: bool) -> Result<String, CliError> {
    let r = orbs_client(socket)
        .await?
        .pause_orb(pb::PauseOrbRequest {
            amp_orb_id: amp_orb_id.to_owned(),
        })
        .await
        .map_err(|s| CliError::from_status(&s, Some(&format!("{amp_orb_id} not paused"))))?;
    done(amp_orb_id, "paused", r.into_inner().message, json)
}

fn done(amp_orb_id: &str, what: &str, message: String, json: bool) -> Result<String, CliError> {
    if json {
        return Ok(to_json(&serde_json::json!({
            "amp_orb_id": amp_orb_id,
            "result": what,
            "message": message,
        })));
    }
    Ok(format!("{amp_orb_id} {what}: {message}\n"))
}
