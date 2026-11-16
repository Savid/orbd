//! `orbd status` (agents, orbs and what needs attention) and `orbd agent list --json`.

use super::orbs::{OrbJson, fetch};
use super::{CliError, Exit, admin_client, age, gib, table, to_json};
use crate::model::unix_ms_now;
use orbd_proto::control::v1 as pb;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// An agent as `--json` prints it. Booked = held by running orbs (asleep orbs hold no
/// vCPUs or memory); usable disk = free less the agent's reserve and the headroom held
/// for running orbs (below that, orbs are refused).
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
            disk_usable_bytes: disk(
                a.disk_free_bytes
                    .saturating_sub(a.disk_reserve_bytes)
                    .saturating_sub(held.disk_bytes),
            ),
            disk_allocated_bytes: disk(a.disk_allocated_bytes),
            disk_limit_bytes: cap.disk_bytes,
            enrolled_unix_ms: a.enrolled_unix_ms,
            certificate_expires_unix_ms: a.certificate_expires_unix_ms,
        }
    }
}

async fn agents(socket: &Path) -> Result<Vec<AgentJson>, CliError> {
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

pub async fn agent_list_json(socket: &Path) -> Result<String, CliError> {
    #[derive(Serialize)]
    struct Out {
        now_unix_ms: u64,
        agents: Vec<AgentJson>,
    }
    Ok(to_json(&Out {
        now_unix_ms: unix_ms_now(),
        agents: agents(socket).await?,
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// Something that needs attention. `kind` is stable; `subject` is an agent id, an orb
/// id, or a count of orbs.
#[derive(Clone, Debug, Serialize)]
pub struct Problem {
    pub severity: Severity,
    pub kind: &'static str,
    pub subject: String,
    pub message: String,
    /// A command that shows more or fixes it.
    pub hint: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct OrbCounts {
    pub total: u32,
    pub running: u32,
    pub asleep: u32,
    pub stopped: u32,
    pub faulted: u32,
    pub other: u32,
}

/// Thresholds for `orbd status`.
#[derive(Clone, Copy, Debug)]
pub struct Thresholds {
    /// Orbs asleep this long are listed as cleanup candidates.
    pub idle: Duration,
    /// Failures older than this are history, not a problem.
    pub failure_window: Duration,
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
    fn on<'a>(orbs: &'a [OrbJson], a: &'a str) -> impl Iterator<Item = &'a OrbJson> {
        orbs.iter().filter(move |o| o.agent == a)
    }
    for a in agents.iter().filter(|a| a.state != "removed") {
        let id = &a.agent_id;
        if a.state == "disconnected" {
            let asleep = on(orbs, id).filter(|o| !o.running()).count();
            out.push(Problem {
                severity: Severity::Error,
                kind: "agent_disconnected",
                subject: id.clone(),
                message: format!(
                    "{id} is disconnected: none of its {} orbs can wake or pause ({asleep} not running)",
                    a.orbs
                ),
                hint: Some(format!("check orbd on {id} (its log, `docker ps`); `orbd agent list`")),
            });
            continue;
        }
        if let (Some(free), Some(reserve), Some(usable)) =
            (a.disk_free_bytes, a.disk_reserve_bytes, a.disk_usable_bytes)
        {
            // What a waking orb here may need: its disk headroom (at most 10 GiB by
            // default) plus a memory checkpoint the size of its memory.
            let need = on(orbs, id)
                .filter(|o| !o.running())
                .map(|o| o.memory_bytes + 10 * super::GIB)
                .max()
                .unwrap_or(0);
            let idle: u64 = on(orbs, id)
                .filter(|o| o.asleep())
                .filter_map(|o| o.disk_allocated_bytes)
                .sum();
            let hint = Some(format!(
                "delete orbs of archived threads: `orbd orb list --agent {id} --asleep-days 3` ({} held by asleep orbs)",
                gib(idle)
            ));
            if free <= reserve {
                out.push(Problem {
                    severity: Severity::Error,
                    kind: "agent_disk_full",
                    subject: id.clone(),
                    message: format!(
                        "{id}: {} free is within its {} reserve: no orb can start or wake there",
                        gib(free),
                        gib(reserve)
                    ),
                    hint,
                });
            } else if usable < need {
                out.push(Problem {
                    severity: Severity::Warning,
                    kind: "agent_disk_low",
                    subject: id.clone(),
                    message: format!(
                        "{id}: {} of disk usable ({} free, {} reserve, {} held by running orbs); its largest asleep orb needs up to {} to wake",
                        gib(usable),
                        gib(free),
                        gib(reserve),
                        gib(a.disk_held_bytes),
                        gib(need)
                    ),
                    hint,
                });
            }
        }
        let blocked: Vec<&OrbJson> = on(orbs, id)
            .filter(|o| o.asleep() && o.failures_since_success == 0)
            .filter(|o| {
                o.wake_blockers
                    .iter()
                    .any(|b| b.starts_with("memory") || b.starts_with("vCPUs"))
            })
            .collect();
        if !blocked.is_empty() {
            out.push(Problem {
                severity: if a.overflow { Severity::Info } else { Severity::Warning },
                kind: "agent_memory_full",
                subject: id.clone(),
                message: format!(
                    "{id}: {} of {} memory booked by {} running orbs; {} of its asleep orbs would be refused if woken now",
                    gib(a.memory_booked_bytes),
                    gib(a.memory_bytes),
                    a.running_orbs,
                    blocked.len()
                ),
                hint: Some(format!(
                    "orbs never move between agents: pause idle ones there (`orbd orb list --agent {id} --state running`)"
                )),
            });
        }
    }

    let window = t.failure_window.as_millis() as u64;
    for o in orbs {
        let id = &o.amp_orb_id;
        let show = Some(format!("orbd orb show {id}"));
        if let Some(f) = &o.fault {
            out.push(Problem {
                severity: Severity::Error,
                kind: "orb_faulted",
                subject: id.clone(),
                message: format!("{id} on {} is faulted: {f}", o.agent),
                hint: show.clone(),
            });
        }
        let recent = o
            .failures
            .first()
            .filter(|f| now.saturating_sub(f.unix_ms) <= window);
        if let Some(f) = recent {
            let n = o.failures_since_success;
            let times = if n == 1 {
                "once".into()
            } else {
                format!("{n} times")
            };
            if !o.wake_blockers.is_empty() && !o.running() {
                out.push(Problem {
                    severity: Severity::Error,
                    kind: "orb_cannot_wake",
                    subject: id.clone(),
                    message: format!(
                        "{id} cannot wake on {} (failed {times}, last {} ago): {}",
                        o.agent,
                        age(now.saturating_sub(f.unix_ms)),
                        o.wake_blockers.join("; ")
                    ),
                    hint: show.clone(),
                });
            } else if o.fault.is_none() {
                out.push(Problem {
                    severity: Severity::Warning,
                    kind: "orb_failing",
                    subject: id.clone(),
                    message: format!(
                        "{id} on {}: {} failed {times}, last {} ago: {}: {}",
                        o.agent,
                        f.action,
                        age(now.saturating_sub(f.unix_ms)),
                        f.code,
                        f.message
                    ),
                    hint: show.clone(),
                });
            }
        }
        if let (Some(c), Some(t)) = (&o.open_command, o.stuck_for(now)) {
            out.push(Problem {
                severity: Severity::Warning,
                kind: "orb_command_stuck",
                subject: id.clone(),
                message: format!(
                    "{id} on {}: {} in flight for {} ({})",
                    o.agent,
                    c.action,
                    age(t),
                    c.status
                ),
                hint: show.clone(),
            });
        }
        if o.running() && o.state_for_secs >= 86_400 {
            out.push(Problem {
                severity: Severity::Info,
                kind: "orb_running_long",
                subject: id.clone(),
                message: format!(
                    "{id} on {} has run for {}, holding {} (Amp does not pause the orb of a deleted thread)",
                    o.agent,
                    age(o.state_for_secs * 1000),
                    gib(o.memory_bytes)
                ),
                hint: Some(format!("if its thread is gone: `orbd orb pause {id}`")),
            });
        }
    }

    let idle_secs = t.idle.as_secs();
    let idle: Vec<&OrbJson> = orbs
        .iter()
        .filter(|o| o.asleep() && o.state_for_secs >= idle_secs)
        .collect();
    if !idle.is_empty() {
        let mut per: BTreeMap<&str, u32> = BTreeMap::new();
        for o in &idle {
            *per.entry(o.agent.as_str()).or_default() += 1;
        }
        let bytes: u64 = idle.iter().filter_map(|o| o.disk_allocated_bytes).sum();
        let days = idle_secs / 86_400;
        out.push(Problem {
            severity: Severity::Info,
            kind: "orbs_idle",
            subject: format!("{} orbs", idle.len()),
            message: format!(
                "{} orbs asleep for {days}d or more hold {} on disk ({}); Amp never deletes the orbs of archived threads",
                idle.len(),
                gib(bytes),
                per.iter()
                    .map(|(a, n)| format!("{a}: {n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            hint: Some(format!(
                "`orbd orb list --asleep-days {days}`; `orbd orb delete <id>` for those whose threads are archived"
            )),
        });
    }
    out.sort_by_key(|p| p.severity);
    out
}

fn counts(orbs: &[OrbJson]) -> OrbCounts {
    let mut c = OrbCounts::default();
    for o in orbs {
        c.total += 1;
        match o.state.as_str() {
            "running" => c.running += 1,
            "asleep" => c.asleep += 1,
            "stopped" => c.stopped += 1,
            s if s.starts_with("faulted") => c.faulted += 1,
            _ => c.other += 1,
        }
    }
    c
}

/// `orbd status`. With `check`, fails with [`Exit::Unhealthy`] (after printing) when a
/// problem has severity error.
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
            agents: &'a [AgentJson],
            orbs: OrbCounts,
            problems: &'a [Problem],
        }
        let s = to_json(&Out {
            now_unix_ms: now,
            healthy,
            agents: &agents,
            orbs: counts(&orbs),
            problems: &problems,
        });
        return Ok((s, healthy));
    }

    let mut out = String::new();
    let rows: Vec<Vec<String>> = agents
        .iter()
        .filter(|a| a.state != "removed")
        .map(|a| {
            let opt = |v: Option<u64>| v.map_or("-".into(), super::gib_short);
            vec![
                a.agent_id.clone(),
                format!("{}{}", a.state, if a.overflow { " (overflow)" } else { "" }),
                format!("{}/{}", a.running_orbs, a.orbs),
                format!("{}/{}", a.vcpus_booked, a.vcpus),
                format!(
                    "{}/{}",
                    super::gib_short(a.memory_booked_bytes),
                    super::gib_short(a.memory_bytes)
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
    out.push_str(&format!(
        "\n{} orbs: {} running, {} asleep{}{}{}\n",
        c.total,
        c.running,
        c.asleep,
        if c.stopped > 0 {
            format!(", {} stopped", c.stopped)
        } else {
            String::new()
        },
        if c.faulted > 0 {
            format!(", {} faulted", c.faulted)
        } else {
            String::new()
        },
        if c.other > 0 {
            format!(", {} other", c.other)
        } else {
            String::new()
        },
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
