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
    /// running, asleep, stopped, uncreated, deleting (a delete started and has not
    /// finished), or faulted (<last known state>).
    pub state: String,
    /// The last known state without the fault: running, asleep, stopped, ...
    pub stable_state: String,
    pub faulted: bool,
    pub state_since_unix_ms: u64,
    pub state_for_secs: u64,
    /// Agent the orb lives on (orbs never move); null outside the agent fleet.
    pub agent_id: Option<String>,
    /// Backend of an orb outside the agent fleet (e.g. boat).
    pub backend_id: Option<String>,
    pub overflow_agent: bool,
    pub orb_type: String,
    pub arch: String,
    pub runtime: String,
    pub vcpus: u32,
    pub memory_bytes: u64,
    /// Disk size (sparse; see `disk_allocated_bytes`).
    pub disk_size_bytes: u64,
    /// On the agent's disk: all of the orb's files, and the memory checkpoint among them
    /// (blocks shared with a cloned image count in full). Null when the agent does not
    /// report it.
    pub disk_allocated_bytes: Option<u64>,
    pub checkpoint_bytes: Option<u64>,
    /// The disk is archived (compressed) until the orb's next wake, which restores it.
    pub disk_archived: bool,
    pub created_unix_ms: u64,
    /// When Amp last spawned or paused it successfully (its creation if never).
    pub last_active_unix_ms: u64,
    pub fault: Option<String>,
    /// Why it could not start on its agent right now, as admission would refuse it;
    /// empty when it would, when it runs, or while it is starting.
    pub wake_blockers: Vec<Blocker>,
    /// Failures of one action since that action's last success: failed spawns if any,
    /// else the action that failed last.
    pub failures_since_success: u32,
    /// Latest first, at most 5.
    pub failures: Vec<FailureJson>,
    pub open_command: Option<CommandJson>,
    pub queued_requests: u32,
}

/// Why something was or would be refused. `code` is a failure code in snake_case:
/// insufficient_memory, insufficient_disk, quota_exceeded (vCPUs), backend_unavailable
/// (its agent is down), ...
#[derive(Clone, Debug, Serialize)]
pub struct Blocker {
    pub code: String,
    pub message: String,
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

fn some(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_owned())
}

/// `insufficient_memory` for `FAILURE_CODE_INSUFFICIENT_MEMORY`.
pub fn code_name(code: i32) -> String {
    match pb::FailureCode::try_from(code) {
        Ok(c) => c
            .as_str_name()
            .trim_start_matches("FAILURE_CODE_")
            .to_lowercase(),
        Err(_) => format!("code_{code}"),
    }
}

/// A refusal for room (memory, vCPUs or disk) rather than a fault.
pub fn is_capacity(code: &str) -> bool {
    matches!(
        code,
        "insufficient_memory" | "insufficient_disk" | "quota_exceeded"
    )
}

fn failure(f: &pb::OrbFailure) -> FailureJson {
    FailureJson {
        action: f.action.clone(),
        code: code_name(f.code),
        message: f.message.clone(),
        unix_ms: f.unix_ms,
        operation_id: some(&f.operation_id),
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
        let stable = match o.state.strip_prefix("faulted (") {
            Some(rest) => rest.trim_end_matches(')').to_owned(),
            None => o.state.clone(),
        };
        Self {
            amp_orb_id: o.amp_orb_id.clone(),
            thread_id: thread_id(&o.amp_orb_id),
            orb_id: o.orb_id.clone(),
            state: o.state.clone(),
            stable_state: stable,
            faulted: !o.fault.is_empty(),
            state_since_unix_ms: o.observed_unix_ms,
            state_for_secs: now.saturating_sub(o.observed_unix_ms) / 1000,
            agent_id: some(&o.agent_id),
            backend_id: some(&o.backend_id),
            overflow_agent: o.overflow_agent,
            orb_type: o.offering_id.clone(),
            arch: o.arch.clone(),
            runtime: o.runtime.clone(),
            vcpus: r.vcpus,
            memory_bytes: r.memory_bytes,
            disk_size_bytes: r.disk_bytes,
            disk_allocated_bytes: o.disk.as_ref().map(|d| d.allocated_bytes),
            checkpoint_bytes: o.disk.as_ref().map(|d| d.checkpoint_bytes),
            disk_archived: o.disk.as_ref().is_some_and(|d| d.archived),
            created_unix_ms: o.created_unix_ms,
            last_active_unix_ms: o.last_active_unix_ms,
            fault: some(&o.fault),
            wake_blockers: o
                .wake_blockers
                .iter()
                .map(|b| Blocker {
                    code: code_name(b.code),
                    message: b.message.clone(),
                })
                .collect(),
            failures_since_success: o.failures_since_success,
            failures: o.failures.iter().map(failure).collect(),
            open_command: o.open_command.as_ref().map(command),
            queued_requests: o.queued_requests,
        }
    }

    /// Its agent, or its backend outside the agent fleet.
    pub fn host(&self) -> &str {
        self.agent_id
            .as_deref()
            .or(self.backend_id.as_deref())
            .unwrap_or("")
    }

    pub fn running(&self) -> bool {
        self.stable_state == "running" && self.state != "deleting"
    }

    pub fn asleep(&self) -> bool {
        matches!(self.state.as_str(), "asleep" | "stopped")
    }

    pub fn blocked_by(&self, code: &str) -> bool {
        self.wake_blockers.iter().any(|b| b.code == code)
    }

    /// Its agent lacks room for it (memory or vCPUs).
    pub fn blocked_by_room(&self) -> bool {
        self.blocked_by("insufficient_memory") || self.blocked_by("quota_exceeded")
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

    /// Its delete started and nothing is running it any more: it failed.
    pub fn delete_failed(&self) -> bool {
        self.state == "deleting" && self.open_command.is_none() && self.queued_requests == 0
    }

    /// Its last spawn was refused for room it has now: it wakes on its thread's next
    /// message.
    pub fn refused_but_fits_now(&self) -> bool {
        self.failures.first().is_some_and(|f| {
            f.action == "spawn" && is_capacity(&f.code) && self.wake_blockers.is_empty()
        }) && !self.running()
    }

    /// The resources its blockers name: `memory`, `vCPUs`, `disk`, `agent down`.
    fn blocker_short(&self) -> String {
        let mut v: Vec<&str> = self
            .wake_blockers
            .iter()
            .map(|b| match b.code.as_str() {
                "insufficient_memory" => "memory",
                "quota_exceeded" => "vCPUs",
                "insufficient_disk" => "disk",
                "backend_unavailable" => "agent down",
                other => other,
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
        if self.delete_failed() {
            n.push("delete failed".into());
        }
        if self.failures_since_success > 0 {
            let last = &self.failures[0];
            let times = match self.failures_since_success {
                1 => String::new(),
                k => format!(" ({k} failures)"),
            };
            if !self.wake_blockers.is_empty() {
                n.push(format!("can't wake: {}{times}", self.blocker_short()));
            } else if self.refused_but_fits_now() {
                n.push(format!("spawn refused{times}, fits now"));
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
        if self.disk_archived {
            n.push("disk archived".into());
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
    /// Only orbs named by a problem of `orbd status` of severity warning or error.
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
    let all: Vec<OrbJson> = fetch(socket)
        .await?
        .iter()
        .map(|o| OrbJson::from_pb(o, now))
        .collect();
    let named: Option<std::collections::HashSet<String>> = if f.problems {
        let agents = super::status::agents(socket).await?;
        let problems =
            super::status::problems(&agents, &all, super::status::Thresholds::default(), now);
        Some(
            problems
                .into_iter()
                .filter(|p| p.severity != super::status::Severity::Info)
                .flat_map(|p| p.amp_orb_ids)
                .collect(),
        )
    } else {
        None
    };
    let orbs: Vec<OrbJson> = all
        .into_iter()
        .filter(|o| f.agent.as_ref().is_none_or(|a| o.host() == a))
        .filter(|o| {
            f.state
                .as_ref()
                .is_none_or(|s| o.state == *s || (s == "faulted" && o.faulted))
        })
        .filter(|o| {
            f.asleep_for
                .is_none_or(|d| o.asleep() && o.state_for_secs >= d.as_secs())
        })
        .filter(|o| named.as_ref().is_none_or(|n| n.contains(&o.amp_orb_id)))
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
                o.host().to_owned(),
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
            result: some(&q.result),
            message: some(&q.message),
            operation_id: some(&q.operation_id),
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
            o.host(),
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
            (Some(a), _) if o.disk_archived => format!(
                "{} (the disk, archived: compressed until the next wake, which restores it)",
                gib(a)
            ),
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
    kv(
        "last active",
        format!("{} ago (last spawn or pause)", ago(o.last_active_unix_ms)),
    );
    if o.asleep() || o.state == "uncreated" {
        let starting = o.open_command.as_ref().is_some_and(|c| c.action == "spawn");
        kv(
            "wake check",
            if starting {
                "starting now".into()
            } else if o.wake_blockers.is_empty() {
                "fits on its agent now".into()
            } else {
                format!(
                    "would be refused: {}",
                    o.wake_blockers
                        .iter()
                        .map(|b| b.message.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                )
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
        let a = &o.failures[0].action;
        kv(
            "failing",
            format!(
                "{} {a} failures since its last successful {a}:",
                o.failures_since_success
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
    let host = o.host();
    if o.blocked_by("backend_unavailable") {
        h.push(format!(
            "its agent {host} is down; orbs never move, so it wakes once the agent is back (`orbd agent list`)"
        ));
    }
    if o.blocked_by_room() {
        h.push(format!(
            "it needs {} on {host}, which is full; orbs never move to another agent. Make room there: delete orbs whose threads are gone (`orbd orb delete --force <id>`, no checkpoint written) or pause idle ones (`orbd orb list --agent {host} --state running`)",
            gib(o.memory_bytes)
        ));
    }
    if o.blocked_by("insufficient_disk") {
        h.push(format!(
            "{host} is short of disk: delete orbs of archived threads there (`orbd orb list --agent {host} --asleep-days 3`, then `orbd orb delete <id>`)"
        ));
    }
    if o.fault.is_some() {
        h.push(format!(
            "faulted: read the agent's log on {host} for orb {} (and `<state_dir>/orbs/{}/logs/`)",
            o.orb_id, o.orb_id
        ));
    }
    if o.delete_failed() {
        h.push(format!(
            "its delete did not finish: `orbd orb delete --force {id}` retries it"
        ));
    }
    if let Some(t) = o.stuck_for(now) {
        h.push(format!(
            "a command has been in flight for {}; the agent's log on {host} says what it is doing",
            age(t)
        ));
    }
    if let Some(f) = o.failures.first()
        && o.wake_blockers.is_empty()
        && o.fault.is_none()
    {
        if o.refused_but_fits_now() {
            h.push("its last spawn was refused for room it has now: its thread's next message wakes it".into());
        } else if f.action == "pause" && f.code == "insufficient_disk" {
            h.push(format!(
                "it could not be paused: no disk on {host} for its memory checkpoint, so it keeps running and holding its memory. Free disk there (`orbd orb list --agent {host} --asleep-days 3`)"
            ));
        } else {
            h.push(format!(
                "the last {} failed ({}); the agent's log on {host} has the details",
                f.action, f.code
            ));
        }
    }
    if let Some(t) = o.undriven_for(now) {
        h.push(format!(
            "running with no spawn or pause from Amp for {}: Amp never pauses the orb of a deleted thread. If its thread is gone, `orbd orb delete --force {id}` (frees its memory without writing a checkpoint); otherwise `orbd orb pause {id}`",
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

fn job_error(s: &tonic::Status, what: &str) -> CliError {
    let e = CliError::from_status(s, Some(what));
    match e.exit {
        Exit::Refused => e.hint(
            "nothing was done; `orbd orb show <orb>` says what it is doing: wait, or `orbd orb pause` it first",
        ),
        Exit::Failed => e.hint("`orbd orb show <orb>` shows whether it happened and why it failed"),
        _ => e,
    }
}

pub async fn delete(
    socket: &Path,
    orb: &str,
    min_asleep: Option<Duration>,
    json: bool,
) -> Result<String, CliError> {
    let r = orbs_client(socket)
        .await?
        .delete_orb(pb::DeleteOrbRequest {
            amp_orb_id: orb.to_owned(),
            min_asleep_secs: min_asleep.unwrap_or_default().as_secs(),
            force: min_asleep.is_none(),
        })
        .await
        .map_err(|s| job_error(&s, &format!("{orb} not deleted")))?;
    done(orb, "deleted", r.into_inner().message, json)
}

pub async fn pause(socket: &Path, orb: &str, json: bool) -> Result<String, CliError> {
    let r = orbs_client(socket)
        .await?
        .pause_orb(pb::PauseOrbRequest {
            amp_orb_id: orb.to_owned(),
        })
        .await
        .map_err(|s| job_error(&s, &format!("{orb} not paused")))?;
    done(orb, "paused", r.into_inner().message, json)
}

fn done(orb: &str, what: &str, message: String, json: bool) -> Result<String, CliError> {
    if json {
        return Ok(to_json(&serde_json::json!({
            "orb": orb,
            "result": what,
            "message": message,
        })));
    }
    Ok(format!("{orb} {what}: {message}\n"))
}
