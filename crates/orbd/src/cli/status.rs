//! `orbd status` (agents, orbs and what needs attention) and `orbd agent list`.

use super::orbs::{OrbJson, fetch};
use super::{CliError, Exit, admin_client, age, gib, gib_short, table, to_json};
use crate::model::unix_ms_now;
use orbd_proto::control::v1 as pb;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// An agent as `--json` prints it. Booked = held by running orbs (asleep orbs hold no
/// vCPUs or memory); usable disk = what admission would still hand out: free space less
/// the agent's reserve, and its disk limit less what orbd allocated, each less the
/// headroom held for running orbs.
#[derive(Clone, Debug, Serialize)]
pub struct AgentJson {
    pub agent_id: String,
    /// connected, disconnected or removed.
    pub state: String,
    pub overflow: bool,
    pub orbs: u32,
    pub running_orbs: u32,
    pub vcpus: u32,
    pub vcpus_booked: u32,
    pub memory_bytes: u64,
    pub memory_booked_bytes: u64,
    pub memory_unbooked_bytes: u64,
    /// The host's available memory and the part the agent keeps (null: not reported).
    pub host_memory_available_bytes: Option<u64>,
    pub host_memory_reserve_bytes: Option<u64>,
    /// Null until the agent reports its disk.
    pub disk_total_bytes: Option<u64>,
    pub disk_free_bytes: Option<u64>,
    pub disk_reserve_bytes: Option<u64>,
    pub disk_held_bytes: u64,
    pub disk_usable_bytes: Option<u64>,
    /// Allocated under the agent's state directory (orb disks, checkpoints, images).
    pub disk_allocated_bytes: Option<u64>,
    pub disk_limit_bytes: u64,
    pub enrolled_unix_ms: u64,
    pub certificate_expires_unix_ms: u64,
}

impl AgentJson {
    fn from_pb(a: &pb::AgentInfo) -> Self {
        let cap = a.capacity.unwrap_or_default();
        let held = a.reserved.unwrap_or_default();
        let disk = |v: u64| a.disk_reported.then_some(v);
        let mem = |v: u64| (a.memory_available_bytes > 0).then_some(v);
        let fs_room = a
            .disk_free_bytes
            .saturating_sub(a.disk_reserve_bytes)
            .saturating_sub(held.disk_bytes);
        let cap_room = cap
            .disk_bytes
            .saturating_sub(a.disk_allocated_bytes)
            .saturating_sub(held.disk_bytes);
        Self {
            agent_id: a.agent_id.clone(),
            state: match (a.removed, a.connected) {
                (true, _) => "removed",
                (false, true) => "connected",
                (false, false) => "disconnected",
            }
            .into(),
            overflow: a.overflow,
            orbs: a.orbs,
            running_orbs: a.running_orbs,
            vcpus: cap.vcpus,
            vcpus_booked: held.vcpus,
            memory_bytes: cap.memory_bytes,
            memory_booked_bytes: held.memory_bytes,
            memory_unbooked_bytes: cap.memory_bytes.saturating_sub(held.memory_bytes),
            host_memory_available_bytes: mem(a.memory_available_bytes),
            host_memory_reserve_bytes: mem(a.memory_reserve_bytes),
            disk_total_bytes: disk(a.disk_total_bytes).filter(|t| *t > 0),
            disk_free_bytes: disk(a.disk_free_bytes),
            disk_reserve_bytes: disk(a.disk_reserve_bytes),
            disk_held_bytes: held.disk_bytes,
            disk_usable_bytes: disk(fs_room.min(cap_room)),
            disk_allocated_bytes: disk(a.disk_allocated_bytes),
            disk_limit_bytes: cap.disk_bytes,
            enrolled_unix_ms: a.enrolled_unix_ms,
            certificate_expires_unix_ms: a.certificate_expires_unix_ms,
        }
    }
}

pub async fn agents(socket: &Path) -> Result<Vec<AgentJson>, CliError> {
    Ok(admin_client(socket)
        .await?
        .list_agents(pb::ListAgentsRequest {})
        .await
        .map_err(|s| CliError::from_status(&s, Some("listing agents")))?
        .into_inner()
        .agents
        .iter()
        .map(AgentJson::from_pb)
        .collect())
}

/// `orbd agent list`: one line per agent, or `{"agents": [...]}` with `json`.
pub async fn agent_list(socket: &Path, json: bool) -> Result<String, CliError> {
    let now = unix_ms_now();
    let agents = agents(socket).await?;
    if json {
        #[derive(Serialize)]
        struct Out {
            now_unix_ms: u64,
            agents: Vec<AgentJson>,
        }
        return Ok(to_json(&Out {
            now_unix_ms: now,
            agents,
        }));
    }
    let mut out = String::new();
    for a in &agents {
        let state = if a.overflow {
            format!("{} (overflow)", a.state)
        } else {
            a.state.clone()
        };
        let days = a.certificate_expires_unix_ms.saturating_sub(now) / 86_400_000;
        let disk = match (
            a.disk_free_bytes,
            a.disk_reserve_bytes,
            a.disk_allocated_bytes,
        ) {
            (Some(free), Some(reserve), Some(allocated)) => {
                let of = a
                    .disk_total_bytes
                    .map_or(String::new(), |t| format!(" of {}", gib(t)));
                format!(
                    "disk {} free{of} ({} kept free), {} allocated, {} reserved, limit {}",
                    gib(free),
                    gib(reserve),
                    gib(allocated),
                    gib(a.disk_held_bytes),
                    gib(a.disk_limit_bytes)
                )
            }
            _ => "disk not reported".into(),
        };
        let host_mem = match (a.host_memory_available_bytes, a.host_memory_reserve_bytes) {
            (Some(avail), Some(keep)) => format!(
                " ({} available on the host, {} kept)",
                gib(avail),
                gib(keep)
            ),
            _ => String::new(),
        };
        out.push_str(&format!(
            "{}\t{state}\t{} orbs ({} running)\tvCPUs {}/{}\tmemory {}/{}{host_mem}\t{disk}\t\
             certificate expires in {days}d\n",
            a.agent_id,
            a.orbs,
            a.running_orbs,
            a.vcpus_booked,
            a.vcpus,
            gib(a.memory_booked_bytes),
            gib(a.memory_bytes),
        ));
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

pub const PROBLEM_KINDS_HELP: &str = "\
Problem kinds (stable; `kind` in --json), worst first:
  agent_disconnected  an agent is gone (error; warning with no orbs; info for overflow agents)
  agent_disk_full     an agent's free disk is within its reserve: nothing starts there
  orb_faulted         an orb is faulted
  orb_cannot_wake     an orb's wake was refused lately and still would be
  orb_delete_failed   a delete of an orb started and did not finish
  orb_failing         an orb's spawn, pause or delete failed lately (info when a refused
                      spawn fits now)
  orb_command_stuck   a command has been in flight for over 10 minutes
  agent_memory_full   asleep orbs active lately would be refused memory or vCPUs on wake
  agent_disk_low      asleep orbs active lately would be refused disk on wake
  orb_undriven        an orb runs with no spawn or pause from Amp for a day (Amp never
                      pauses the orb of a deleted thread)
  orbs_idle           orbs asleep for --idle-days or more (cleanup candidates)";

/// Something that needs attention. `kind` is stable (see [`PROBLEM_KINDS_HELP`]).
#[derive(Clone, Debug, Serialize)]
pub struct Problem {
    pub severity: Severity,
    pub kind: &'static str,
    /// The agent it is about, if one.
    pub agent_id: Option<String>,
    /// The orbs it is about.
    pub amp_orb_ids: Vec<String>,
    /// Bytes involved, where that is the point (e.g. disk held by idle orbs).
    pub bytes: Option<u64>,
    pub message: String,
    /// A command that shows more or fixes it.
    pub hint: Option<String>,
}

impl Problem {
    fn new(severity: Severity, kind: &'static str, message: String) -> Self {
        Self {
            severity,
            kind,
            agent_id: None,
            amp_orb_ids: vec![],
            bytes: None,
            message,
            hint: None,
        }
    }
    fn agent(mut self, a: &str) -> Self {
        self.agent_id = Some(a.into());
        self
    }
    fn orbs<'a>(mut self, ids: impl IntoIterator<Item = &'a str>) -> Self {
        self.amp_orb_ids = ids.into_iter().map(Into::into).collect();
        self
    }
    fn hint(mut self, h: String) -> Self {
        self.hint = Some(h);
        self
    }
}

#[derive(Debug, Default, Serialize)]
pub struct OrbCounts {
    pub total: u32,
    pub running: u32,
    pub asleep: u32,
    pub stopped: u32,
    pub deleting: u32,
    pub faulted: u32,
    pub other: u32,
}

/// Thresholds for `orbd status`.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Thresholds {
    /// Orbs asleep this long are cleanup candidates; asleep orbs not active for this
    /// long do not count towards an agent's memory or disk being full.
    #[serde(serialize_with = "secs")]
    pub idle: Duration,
    /// Failures older than this are history, not a problem.
    #[serde(serialize_with = "secs")]
    pub failure_window: Duration,
}

fn secs<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_secs())
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(3 * 86_400),
            failure_window: Duration::from_secs(86_400),
        }
    }
}

/// Everything wrong with the fleet, worst first.
pub fn problems(agents: &[AgentJson], orbs: &[OrbJson], t: Thresholds, now: u64) -> Vec<Problem> {
    let mut out = Vec::new();
    let idle_ms = t.idle.as_millis() as u64;
    let days = (t.idle.as_secs() / 86_400).max(1);
    // Asleep orbs that may well be woken (active lately): an agent too full for them
    // matters; one too full for orbs of long-archived threads does not.
    let wakeable = |o: &&OrbJson| {
        o.asleep()
            && o.failures_since_success == 0
            && now.saturating_sub(o.last_active_unix_ms) < idle_ms
    };
    for a in agents.iter().filter(|a| a.state != "removed") {
        let id = a.agent_id.as_str();
        let on: Vec<&OrbJson> = orbs.iter().filter(|o| o.host() == id).collect();
        if a.state == "disconnected" {
            let severity = match (a.overflow, a.orbs) {
                (true, _) => Severity::Info,
                (false, 0) => Severity::Warning,
                _ => Severity::Error,
            };
            out.push(
                Problem::new(
                    severity,
                    "agent_disconnected",
                    format!(
                        "{id} is disconnected: none of its {} orbs can wake or pause{}",
                        a.orbs,
                        if a.overflow {
                            " (an overflow agent, often off)"
                        } else {
                            ""
                        }
                    ),
                )
                .agent(id)
                .orbs(on.iter().map(|o| o.amp_orb_id.as_str()))
                .hint(format!(
                    "check orbd on {id} (its log, `docker ps`); `orbd agent list`"
                )),
            );
            continue;
        }
        let idle_bytes: u64 = on
            .iter()
            .filter(|o| o.asleep())
            .filter_map(|o| o.disk_allocated_bytes)
            .sum();
        let disk_hint = format!(
            "delete orbs of archived threads: `orbd orb list --agent {id} --asleep-days {days}` ({} held by asleep orbs there)",
            gib(idle_bytes)
        );
        if let (Some(free), Some(reserve)) = (a.disk_free_bytes, a.disk_reserve_bytes)
            && free <= reserve
        {
            let mut p = Problem::new(
                Severity::Error,
                "agent_disk_full",
                format!(
                    "{id}: {} free is within its {} reserve: no orb can start or wake there",
                    gib(free),
                    gib(reserve)
                ),
            )
            .agent(id)
            .hint(disk_hint.clone());
            p.bytes = Some(free);
            out.push(p);
        }
        let room: Vec<&OrbJson> = on
            .iter()
            .copied()
            .filter(wakeable)
            .filter(|o| o.blocked_by_room())
            .collect();
        if !room.is_empty() {
            out.push(
                Problem::new(
                    if a.overflow {
                        Severity::Info
                    } else {
                        Severity::Warning
                    },
                    "agent_memory_full",
                    format!(
                        "{id}: {} of {} memory booked by {} running orbs; {} asleep orbs active in the last {days}d would be refused if woken now",
                        gib(a.memory_booked_bytes),
                        gib(a.memory_bytes),
                        a.running_orbs,
                        room.len()
                    ),
                )
                .agent(id)
                .orbs(room.iter().map(|o| o.amp_orb_id.as_str()))
                .hint(format!(
                    "orbs never move between agents: delete orbs there whose threads are gone, or pause idle ones (`orbd orb list --agent {id} --state running`)"
                )),
            );
        }
        let disk: Vec<&OrbJson> = on
            .iter()
            .copied()
            .filter(wakeable)
            .filter(|o| o.blocked_by("insufficient_disk"))
            .collect();
        if !disk.is_empty() {
            let mut p = Problem::new(
                Severity::Warning,
                "agent_disk_low",
                format!(
                    "{id}: {} of disk usable; {} asleep orbs active in the last {days}d would be refused disk if woken now",
                    a.disk_usable_bytes.map_or("?".into(), gib),
                    disk.len()
                ),
            )
            .agent(id)
            .orbs(disk.iter().map(|o| o.amp_orb_id.as_str()))
            .hint(disk_hint);
            p.bytes = a.disk_usable_bytes;
            out.push(p);
        }
    }

    let window = t.failure_window.as_millis() as u64;
    for o in orbs {
        let id = o.amp_orb_id.as_str();
        let host = o.host();
        let show = format!("orbd orb show {id}");
        let p = |severity, kind, message| {
            Problem::new(severity, kind, message)
                .agent(host)
                .orbs([id])
                .hint(show.clone())
        };
        if let Some(f) = &o.fault {
            out.push(p(
                Severity::Error,
                "orb_faulted",
                format!("{id} on {host} is faulted: {f}"),
            ));
        }
        if o.delete_failed() {
            out.push(
                p(
                    Severity::Error,
                    "orb_delete_failed",
                    format!("{id} on {host}: its delete started and did not finish"),
                )
                .hint(format!("`orbd orb delete --force {id}` retries it")),
            );
        }
        let recent = o
            .failures
            .first()
            .filter(|f| now.saturating_sub(f.unix_ms) <= window);
        if let Some(f) = recent
            && o.fault.is_none()
        {
            let n = o.failures_since_success;
            let times = if n == 1 {
                "once".into()
            } else {
                format!("{n} times")
            };
            let when = age(now.saturating_sub(f.unix_ms));
            if f.action == "spawn" && !o.wake_blockers.is_empty() && !o.running() {
                out.push(p(
                    Severity::Error,
                    "orb_cannot_wake",
                    format!(
                        "{id} cannot wake on {host} (refused {times}, last {when} ago): {}",
                        o.wake_blockers
                            .iter()
                            .map(|b| b.message.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                ));
            } else if o.refused_but_fits_now() {
                out.push(p(
                    Severity::Info,
                    "orb_failing",
                    format!(
                        "{id} on {host}: spawn refused {times}, last {when} ago ({}); it fits now",
                        f.code
                    ),
                ));
            } else if !o.delete_failed() {
                // A pause refused for disk (no room for its checkpoint) keeps the orb
                // running, holding its memory: a warning like any other failure.
                out.push(p(
                    Severity::Warning,
                    "orb_failing",
                    format!(
                        "{id} on {host}: {} failed {times}, last {when} ago: {}: {}",
                        f.action, f.code, f.message
                    ),
                ));
            }
        }
        if let (Some(c), Some(t)) = (&o.open_command, o.stuck_for(now)) {
            out.push(p(
                Severity::Warning,
                "orb_command_stuck",
                format!(
                    "{id} on {host}: {} in flight for {} ({})",
                    c.action,
                    age(t),
                    c.status
                ),
            ));
        }
        if let Some(t) = o.undriven_for(now) {
            out.push(
                p(
                    Severity::Warning,
                    "orb_undriven",
                    format!(
                        "{id} on {host} runs, holding {}, with no spawn or pause from Amp for {} (Amp never pauses the orb of a deleted thread)",
                        gib(o.memory_bytes),
                        age(t)
                    ),
                )
                .hint(format!(
                    "if its thread is gone: `orbd orb delete --force {id}` (writes no checkpoint); else `orbd orb pause {id}`"
                )),
            );
        }
    }

    let idle: Vec<&OrbJson> = orbs
        .iter()
        .filter(|o| o.asleep() && o.state_for_secs * 1000 >= idle_ms)
        .collect();
    if !idle.is_empty() {
        let mut per: BTreeMap<&str, u32> = BTreeMap::new();
        for o in &idle {
            *per.entry(o.host()).or_default() += 1;
        }
        let bytes: u64 = idle.iter().filter_map(|o| o.disk_allocated_bytes).sum();
        let mut p = Problem::new(
            Severity::Info,
            "orbs_idle",
            format!(
                "{} orbs asleep for {days}d or more hold {} on disk ({}); Amp never deletes the orbs of archived threads",
                idle.len(),
                gib(bytes),
                per.iter()
                    .map(|(a, n)| format!("{a}: {n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .orbs(idle.iter().map(|o| o.amp_orb_id.as_str()))
        .hint(format!(
            "`orbd orb list --asleep-days {days}`; `orbd orb delete <id>` for those whose threads are archived"
        ));
        p.bytes = Some(bytes);
        out.push(p);
    }
    out.sort_by_key(|p| p.severity);
    out
}

fn counts(orbs: &[OrbJson]) -> OrbCounts {
    let mut c = OrbCounts::default();
    for o in orbs {
        c.total += 1;
        match o.state.as_str() {
            _ if o.faulted => c.faulted += 1,
            "running" => c.running += 1,
            "asleep" => c.asleep += 1,
            "stopped" => c.stopped += 1,
            "deleting" => c.deleting += 1,
            _ => c.other += 1,
        }
    }
    c
}

/// `orbd status`: the output, and whether no problem is an error.
pub async fn status(socket: &Path, t: Thresholds, json: bool) -> Result<(String, bool), CliError> {
    let now = unix_ms_now();
    let agents = agents(socket).await?;
    let orbs: Vec<OrbJson> = fetch(socket)
        .await?
        .iter()
        .map(|o| OrbJson::from_pb(o, now))
        .collect();
    let problems = problems(&agents, &orbs, t, now);
    let healthy = !problems.iter().any(|p| p.severity == Severity::Error);
    if json {
        #[derive(Serialize)]
        struct Out<'a> {
            now_unix_ms: u64,
            /// No problem of severity error.
            healthy: bool,
            thresholds_secs: Thresholds,
            agents: &'a [AgentJson],
            orb_counts: OrbCounts,
            problems: &'a [Problem],
        }
        let s = to_json(&Out {
            now_unix_ms: now,
            healthy,
            thresholds_secs: t,
            agents: &agents,
            orb_counts: counts(&orbs),
            problems: &problems,
        });
        return Ok((s, healthy));
    }

    let mut out = String::new();
    let rows: Vec<Vec<String>> = agents
        .iter()
        .filter(|a| a.state != "removed")
        .map(|a| {
            let opt = |v: Option<u64>| v.map_or("-".into(), gib_short);
            vec![
                a.agent_id.clone(),
                format!("{}{}", a.state, if a.overflow { " (overflow)" } else { "" }),
                format!("{}/{}", a.running_orbs, a.orbs),
                format!("{}/{}", a.vcpus_booked, a.vcpus),
                format!(
                    "{}/{}",
                    gib_short(a.memory_booked_bytes),
                    gib_short(a.memory_bytes)
                ),
                opt(a.host_memory_available_bytes),
                opt(a.disk_free_bytes),
                opt(a.disk_usable_bytes),
                opt(a.disk_allocated_bytes),
            ]
        })
        .collect();
    out.push_str(&table(
        &[
            "AGENT",
            "STATE",
            "RUNNING/ORBS",
            "VCPUS",
            "MEMORY BOOKED",
            "HOST MEM FREE",
            "DISK FREE",
            "DISK USABLE",
            "ORBD ON DISK",
        ],
        &rows,
    ));
    let c = counts(&orbs);
    let extra = |n: u32, what: &str| {
        if n > 0 {
            format!(", {n} {what}")
        } else {
            String::new()
        }
    };
    out.push_str(&format!(
        "\n{} orbs: {} running, {} asleep{}{}{}{}\n",
        c.total,
        c.running,
        c.asleep,
        extra(c.stopped, "stopped"),
        extra(c.deleting, "deleting"),
        extra(c.faulted, "faulted"),
        extra(c.other, "other"),
    ));
    if problems.is_empty() {
        out.push_str("\nno problems\n");
    } else {
        out.push_str("\nPROBLEMS\n");
        for p in &problems {
            let sev = match p.severity {
                Severity::Error => "error",
                Severity::Warning => "warn",
                Severity::Info => "info",
            };
            out.push_str(&format!("  {sev:<5}  {}\n", p.message));
            if let Some(h) = &p.hint {
                out.push_str(&format!("         -> {h}\n"));
            }
        }
    }
    Ok((out, healthy))
}

pub fn unhealthy() -> CliError {
    CliError::new(Exit::Unhealthy, "problems of severity error (see above)")
}

#[cfg(test)]
mod tests {
    use super::super::orbs::{Blocker, FailureJson};
    use super::*;

    const DAY: u64 = 86_400_000;
    const NOW: u64 = 100 * DAY;
    const G: u64 = super::super::GIB;

    fn orb(id: &str, agent: &str, state: &str, since: u64, active: u64) -> OrbJson {
        OrbJson {
            amp_orb_id: id.into(),
            thread_id: String::new(),
            orb_id: String::new(),
            state: state.into(),
            stable_state: state.into(),
            faulted: false,
            state_since_unix_ms: since,
            state_for_secs: (NOW - since) / 1000,
            agent_id: Some(agent.into()),
            backend_id: None,
            overflow_agent: false,
            orb_type: "4vcpu-8gb".into(),
            arch: "amd64".into(),
            runtime: "firecracker".into(),
            vcpus: 4,
            memory_bytes: 8 * G,
            disk_size_bytes: 50 * G,
            disk_allocated_bytes: Some(12 * G),
            checkpoint_bytes: Some(8 * G),
            created_unix_ms: 0,
            last_active_unix_ms: active,
            fault: None,
            wake_blockers: vec![],
            failures_since_success: 0,
            failures: vec![],
            open_command: None,
            queued_requests: 0,
        }
    }

    fn agent(id: &str, state: &str, free: u64, reserve: u64, overflow: bool) -> AgentJson {
        AgentJson {
            agent_id: id.into(),
            state: state.into(),
            overflow,
            orbs: 2,
            running_orbs: 1,
            vcpus: 32,
            vcpus_booked: 4,
            memory_bytes: 54 * G,
            memory_booked_bytes: 8 * G,
            memory_unbooked_bytes: 46 * G,
            host_memory_available_bytes: None,
            host_memory_reserve_bytes: None,
            disk_total_bytes: Some(900 * G),
            disk_free_bytes: Some(free),
            disk_reserve_bytes: Some(reserve),
            disk_held_bytes: 18 * G,
            disk_usable_bytes: Some(free.saturating_sub(reserve + 18 * G)),
            disk_allocated_bytes: Some(100 * G),
            disk_limit_bytes: 900 * G,
            enrolled_unix_ms: 0,
            certificate_expires_unix_ms: 0,
        }
    }

    fn blocked(mut o: OrbJson, code: &str) -> OrbJson {
        o.wake_blockers = vec![Blocker {
            code: code.into(),
            message: format!("{code}: ..."),
        }];
        o
    }

    fn failed(mut o: OrbJson, action: &str, code: &str, at: u64) -> OrbJson {
        o.failures_since_success = 1;
        o.failures = vec![FailureJson {
            action: action.into(),
            code: code.into(),
            message: "...".into(),
            unix_ms: at,
            operation_id: None,
        }];
        o
    }

    fn kinds(p: &[Problem]) -> Vec<(Severity, &str, Vec<&str>)> {
        p.iter()
            .map(|p| {
                (
                    p.severity,
                    p.kind,
                    p.amp_orb_ids.iter().map(String::as_str).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn problems_worst_first() {
        let agents = [
            agent("a", "connected", 500 * G, 44 * G, false),
            agent("b", "disconnected", 500 * G, 44 * G, false),
            agent("c", "connected", 40 * G, 44 * G, false),
            agent("laptop", "disconnected", 500 * G, 44 * G, true),
        ];
        let orbs = [
            // Restored by an agent restart lately, but Amp has not driven it for 2 days.
            orb("amp-orphan", "a", "running", NOW - 60_000, NOW - 2 * DAY),
            orb("amp-busy", "a", "running", NOW - 3 * DAY, NOW - 60_000),
            orb("amp-old", "a", "asleep", NOW - 4 * DAY, NOW - 4 * DAY),
            // Would not fit: counts for a full agent only if active lately.
            blocked(
                orb("amp-recent", "a", "asleep", NOW - DAY, NOW - DAY),
                "insufficient_memory",
            ),
            blocked(
                orb("amp-stale", "a", "asleep", NOW - 5 * DAY, NOW - 5 * DAY),
                "insufficient_memory",
            ),
            // Refused lately and still would be.
            failed(
                blocked(
                    orb("amp-stuck", "a", "asleep", NOW - DAY, NOW - DAY),
                    "insufficient_memory",
                ),
                "spawn",
                "insufficient_memory",
                NOW - 60_000,
            ),
            // Refused, fits now.
            failed(
                orb("amp-fits", "c", "asleep", NOW - DAY, NOW - DAY),
                "spawn",
                "insufficient_memory",
                NOW - 60_000,
            ),
            // Could not checkpoint for lack of disk: keeps running.
            failed(
                orb("amp-nopause", "c", "running", NOW - DAY, NOW - 60_000),
                "pause",
                "insufficient_disk",
                NOW - 60_000,
            ),
        ];
        let got = problems(&agents, &orbs, Thresholds::default(), NOW);
        assert_eq!(
            kinds(&got),
            [
                (Severity::Error, "agent_disconnected", vec![]),
                (Severity::Error, "agent_disk_full", vec![]),
                (Severity::Error, "orb_cannot_wake", vec!["amp-stuck"]),
                (Severity::Warning, "agent_memory_full", vec!["amp-recent"]),
                (Severity::Warning, "orb_undriven", vec!["amp-orphan"]),
                (Severity::Warning, "orb_failing", vec!["amp-nopause"]),
                (Severity::Info, "agent_disconnected", vec![]),
                (Severity::Info, "orb_failing", vec!["amp-fits"]),
                (Severity::Info, "orbs_idle", vec!["amp-old", "amp-stale"]),
            ]
        );
        let undriven = got.iter().find(|p| p.kind == "orb_undriven").unwrap();
        assert!(undriven.message.contains("for 2d"), "{}", undriven.message);
        assert!(undriven.hint.as_ref().unwrap().contains("delete --force"));
    }
}
