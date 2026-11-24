//! systemd's service watchdogs across a sleep. A VM held paused in RAM resumes with
//! CLOCK_MONOTONIC moved on by the whole pause, so after a pause longer than a unit's
//! `WatchdogSec` (3 minutes for journald and udevd) its watchdog timer in PID 1 and its
//! own keepalive are both overdue, and a unit that has not pinged yet gets SIGABRT. So
//! PrepareSleep turns the service manager's watchdog handling off
//! (`systemctl service-watchdogs no`, runtime-only: a boot resets it) and it is turned
//! back on a few seconds after the next Wake or Resync, once services have pinged. If no
//! wake comes (a save that failed and resumed the guest), a thread of its own turns it
//! back on: [`AFTER_JUMP`] after it sees the clock jump, or [`WITHOUT_JUMP`] after the
//! sleep was prepared if it never does.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long after a Wake or Resync the watchdogs come back.
pub const AFTER_WAKE: Duration = Duration::from_secs(10);
/// How long after a clock jump (a pause) with no Wake they come back.
const AFTER_JUMP: Duration = Duration::from_secs(30);
/// How long after a PrepareSleep with no pause they come back.
const WITHOUT_JUMP: Duration = Duration::from_secs(120);
const TICK: Duration = Duration::from_secs(5);

/// When the watchdogs were turned off, while they are.
static OFF_SINCE: Mutex<Option<Instant>> = Mutex::new(None);

fn set(on: bool) -> String {
    let arg = if on { "yes" } else { "no" };
    match crate::cmd::check(
        &["systemctl", "service-watchdogs", arg],
        Duration::from_secs(5),
    ) {
        Ok(_) => format!("service watchdogs {}", if on { "on" } else { "off" }),
        Err(e) => format!("service watchdogs not changed ({e})"),
    }
}

/// Before a sleep: turns service watchdogs off (see the module docs). Returns what to log.
pub fn suspend() -> String {
    let msg = set(false);
    let mut off = OFF_SINCE.lock().unwrap_or_else(|e| e.into_inner());
    let first = off.is_none();
    *off = Some(Instant::now());
    drop(off);
    if first {
        std::thread::spawn(fallback);
    }
    msg
}

/// After a Wake or Resync: turns them back on [`AFTER_WAKE`] later.
pub fn resume_soon() {
    if OFF_SINCE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_none()
    {
        return;
    }
    std::thread::spawn(|| {
        std::thread::sleep(AFTER_WAKE);
        resume();
    });
}

fn resume() {
    let mut off = OFF_SINCE.lock().unwrap_or_else(|e| e.into_inner());
    if off.take().is_some() {
        drop(off);
        let msg = set(true);
        eprintln!("orbd-guest: {msg}");
    }
}

/// Turns the watchdogs back on if no wake does (see the module docs).
fn fallback() {
    let mut last = Instant::now();
    let mut jumped: Option<Instant> = None;
    loop {
        std::thread::sleep(TICK);
        let now = Instant::now();
        if now.duration_since(last) > TICK * 3 {
            jumped = Some(now);
        }
        last = now;
        let Some(since) = *OFF_SINCE.lock().unwrap_or_else(|e| e.into_inner()) else {
            return;
        };
        let due = match jumped {
            Some(j) if j >= since => now.duration_since(j) >= AFTER_JUMP,
            _ => now.duration_since(since) >= WITHOUT_JUMP,
        };
        if due {
            resume();
            return;
        }
    }
}
