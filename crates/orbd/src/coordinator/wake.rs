//! `wake:` hooks. Commands run one at a time. After the sleep command, spawns wait for
//! the agents to disconnect before waking them, so a non-blocking sleep command is safe.

use super::core::Msg;
use crate::config::coordinator::WakeConfig;
use crate::model::InvocationId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const WAKE_RETRY: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    Wake,
    Sleep,
}

impl Hook {
    fn name(self) -> &'static str {
        match self {
            Hook::Wake => "wake",
            Hook::Sleep => "sleep",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Hold {
    No,
    Wait,
    GiveUp(String),
}

pub struct Waker {
    timeout: Duration,
    sleep_after: Option<Duration>,
    runs: mpsc::UnboundedSender<Hook>,
    woke_at: Option<Instant>,
    wake_error: Option<String>,
    /// When the sleep command was started, while it runs.
    sleeping_since: Option<Instant>,
    /// When the sleep command finished, while agents it should stop are still connected.
    draining_since: Option<Instant>,
    connected: HashSet<String>,
    /// The sleep command ran and nothing has woken the agents since.
    slept: bool,
    idle_since: Option<Instant>,
    /// Held spawns: since when, and whether the wake note was sent.
    waiting: HashMap<InvocationId, (Instant, bool)>,
}

impl Waker {
    pub fn start(cfg: WakeConfig, core: mpsc::Sender<Msg>) -> Self {
        let (runs, mut rx) = mpsc::unbounded_channel::<Hook>();
        let (wake, sleep) = (cfg.command.clone(), cfg.sleep_command.clone());
        let hook_timeout = Duration::from_secs(cfg.hook_timeout_secs);
        tokio::spawn(async move {
            while let Some(hook) = rx.recv().await {
                let argv = match hook {
                    Hook::Wake => &wake,
                    Hook::Sleep => sleep.as_ref().expect("sleep only runs when configured"),
                };
                let result = run(hook, argv, hook_timeout).await;
                if core.send(Msg::HookFinished { hook, result }).await.is_err() {
                    break;
                }
            }
        });
        Self {
            timeout: Duration::from_secs(cfg.timeout_secs),
            sleep_after: cfg
                .sleep_command
                .is_some()
                .then(|| Duration::from_secs(cfg.sleep_after_idle_secs)),
            runs,
            woke_at: None,
            wake_error: None,
            sleeping_since: None,
            draining_since: None,
            connected: HashSet::new(),
            slept: false,
            idle_since: None,
            waiting: HashMap::new(),
        }
    }

    fn wake(&mut self) {
        tracing::info!("waking the agents' hosts");
        metrics::counter!("orbd_wake_hooks_total", "hook" => "wake").increment(1);
        self.woke_at = Some(Instant::now());
        self.wake_error = None;
        self.slept = false;
        self.idle_since = None;
        let _ = self.runs.send(Hook::Wake);
    }

    fn draining(&self) -> bool {
        self.draining_since
            .is_some_and(|t| t.elapsed() < self.timeout)
    }

    /// Whether a spawn arriving now must wait even if an agent looks available.
    pub fn holding(&self) -> bool {
        self.sleeping_since.is_some() || self.draining()
    }

    /// `unavailable`: placement found no host. The note is for the job's log.
    pub fn hold(&mut self, inv: InvocationId, unavailable: bool) -> (Hold, Option<String>) {
        if self
            .waiting
            .get(&inv)
            .is_some_and(|(t, _)| t.elapsed() >= self.timeout)
        {
            // Kept until the spawn is placed or given up, so its wait is not restarted.
            if !unavailable {
                return (Hold::No, None);
            }
            self.waiting.remove(&inv);
            let mut why = format!(
                "no agent connected within {}s of the wake command",
                self.timeout.as_secs()
            );
            if let Some(e) = &self.wake_error {
                why = format!("{why} (it failed: {e})");
            }
            return (Hold::GiveUp(why), None);
        }
        if self.holding() {
            let mut note = None;
            self.waiting.entry(inv).or_insert_with(|| {
                note = Some(
                    "waiting for the agents' hosts to go to sleep before waking them".to_owned(),
                );
                (Instant::now(), false)
            });
            return (Hold::Wait, note);
        }
        if !unavailable {
            return (Hold::No, None);
        }
        let stale = self.woke_at.is_none_or(|t| {
            t.elapsed() >= self.timeout || (self.wake_error.is_some() && t.elapsed() >= WAKE_RETRY)
        });
        if stale {
            self.wake();
        }
        let entry = self
            .waiting
            .entry(inv)
            .or_insert_with(|| (Instant::now(), false));
        let note = (!entry.1).then(|| {
            entry.1 = true;
            "waiting for an agent to connect after the wake command".to_owned()
        });
        (Hold::Wait, note)
    }

    pub fn forget(&mut self, inv: InvocationId) {
        self.waiting.remove(&inv);
    }

    pub fn agent_connected(&mut self, agent: String) {
        self.connected.insert(agent);
        self.slept = false;
        self.idle_since = None;
    }

    pub fn agent_disconnected(&mut self, agent: &str) {
        self.connected.remove(agent);
        if self.connected.is_empty() {
            self.draining_since = None;
        }
    }

    pub fn finished(&mut self, hook: Hook, result: Result<(), String>) {
        match (hook, result) {
            (Hook::Wake, Err(e)) => self.wake_error = Some(e),
            (Hook::Wake, Ok(())) => {}
            (Hook::Sleep, Ok(())) => {
                self.sleeping_since = None;
                if !self.connected.is_empty() {
                    self.draining_since = Some(Instant::now());
                }
            }
            (Hook::Sleep, Err(_)) => {
                self.sleeping_since = None;
                // The host may still be up: count idle time again before the next try.
                self.slept = false;
            }
        }
    }

    pub fn tick(&mut self, busy: bool) {
        let now = Instant::now();
        let keep = self.timeout + Duration::from_secs(60);
        self.waiting
            .retain(|_, (t, _)| now.duration_since(*t) < keep);
        let Some(after) = self.sleep_after else {
            return;
        };
        let waking = self.woke_at.is_some_and(|t| t.elapsed() < self.timeout);
        if busy || waking || self.slept || self.holding() || !self.waiting.is_empty() {
            self.idle_since = None;
            return;
        }
        let since = *self.idle_since.get_or_insert(now);
        if now.duration_since(since) >= after {
            tracing::info!(
                idle_secs = after.as_secs(),
                "agents idle: putting their hosts to sleep"
            );
            metrics::counter!("orbd_wake_hooks_total", "hook" => "sleep").increment(1);
            self.slept = true;
            self.sleeping_since = Some(now);
            self.idle_since = None;
            let _ = self.runs.send(Hook::Sleep);
        }
    }
}

/// Runs the command in its own process group, so a timeout also kills what it started.
async fn run(hook: Hook, argv: &[String], timeout: Duration) -> Result<(), String> {
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    let result = match cmd.spawn() {
        Err(e) => Err(format!("{}: {e}", argv[0])),
        Ok(child) => {
            let pid = child.id();
            match tokio::time::timeout(timeout, child.wait_with_output()).await {
                Err(_) => {
                    if let Some(pid) = pid {
                        let _ = nix::sys::signal::killpg(
                            nix::unistd::Pid::from_raw(pid as i32),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                    Err(format!("timed out after {}s", timeout.as_secs()))
                }
                Ok(Err(e)) => Err(format!("{}: {e}", argv[0])),
                Ok(Ok(out)) if out.status.success() => {
                    tracing::info!(hook = hook.name(), stdout = %tail(&out.stdout), "hook command finished");
                    Ok(())
                }
                // Only the status reaches the job's message; stderr stays in the log.
                Ok(Ok(out)) => {
                    tracing::warn!(hook = hook.name(), stderr = %tail(&out.stderr), "hook command stderr");
                    Err(out.status.to_string())
                }
            }
        }
    };
    if let Err(e) = &result {
        tracing::warn!(hook = hook.name(), error = %e, "hook command failed");
    }
    result
}

fn tail(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    let s = s.trim();
    let mut from = s.len().saturating_sub(500);
    while !s.is_char_boundary(from) {
        from += 1;
    }
    s[from..].to_owned()
}
