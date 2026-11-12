mod common;
use common::*;
use std::io::Write;
use std::time::Duration;

/// Hook commands append their name to `hooks.log`.
fn with_wake(c: &Cluster, extra: &str, fail_wake: bool) -> std::path::PathBuf {
    let log = c.root().join("hooks.log");
    let exit = if fail_wake { "; exit 1" } else { "" };
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(c.root().join("coordinator.yaml"))
        .unwrap();
    write!(
        f,
        "wake:\n  command: [sh, -c, \"echo wake >> {log}{exit}\"]\n{extra}",
        log = log.display()
    )
    .unwrap();
    log
}

fn hooks(log: &std::path::Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

#[test]
fn sleeps_when_idle_and_wakes_for_a_spawn() {
    let mut c = Cluster::new(&["agent-a"], 2);
    let log = with_wake(
        &c,
        &format!(
            "  timeout_secs: 60\n  sleep_command: [sh, -c, \"echo sleep >> {}\"]\n  \
             sleep_after_idle_secs: 5\n",
            c.root().join("hooks.log").display()
        ),
        false,
    );
    c.start_all();

    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "first spawn");
    assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause");
    assert_eq!(hooks(&log), "", "no hook runs while an orb is in use");

    wait_until(Duration::from_secs(30), "sleep hook", || {
        hooks(&log) == "sleep\n"
    });
    // The sleep command turns the host off.
    c.terminate_agent("agent-a", Duration::from_secs(30));

    let job = c.dispatch_bg("spawn", "amp-1", &[]);
    wait_until(Duration::from_secs(30), "wake hook", || {
        hooks(&log) == "sleep\nwake\n"
    });
    c.start_agent("agent-a", "");
    let job = job.join().unwrap();
    assert_ok(&job, "spawn after wake");
    assert!(job.stderr.contains("waking"), "stderr:\n{}", job.stderr);

    let s = c.only_orb("agent-a");
    assert!(s.running);
    assert_eq!(
        s.counters.restores, 1,
        "the orb resumes from its checkpoint"
    );
    assert_eq!(
        hooks(&log),
        "sleep\nwake\n",
        "the sleeping host is not slept again"
    );
}

#[test]
fn spawn_fails_when_no_agent_connects_after_the_wake() {
    let mut c = Cluster::new(&["agent-a"], 2);
    let log = with_wake(&c, "  timeout_secs: 3\n", true);
    c.start_all();
    c.terminate_agent("agent-a", Duration::from_secs(30));

    let job = c.dispatch("spawn", "amp-1", &[]);
    assert_ne!(job.code, 0, "spawn without an agent must fail");
    assert!(
        job.stderr.contains(
            "no agent connected within 3s of the wake command (it failed: exit status: 1"
        ),
        "stderr:\n{}",
        job.stderr
    );
    assert!(hooks(&log).starts_with("wake\n"));
}

/// A sleep command that returns while the agent is still connected: the spawn waits for
/// the agent to disconnect instead of landing on a host that is going down, then wakes it.
#[test]
fn spawn_after_a_non_blocking_sleep_waits_for_the_agent_to_go() {
    let mut c = Cluster::new(&["agent-a"], 2);
    let log = with_wake(
        &c,
        &format!(
            "  timeout_secs: 60\n  sleep_command: [sh, -c, \"echo sleep >> {}\"]\n  \
             sleep_after_idle_secs: 2\n",
            c.root().join("hooks.log").display()
        ),
        false,
    );
    c.start_all();

    wait_until(Duration::from_secs(30), "sleep hook", || {
        hooks(&log) == "sleep\n"
    });
    let job = c.dispatch_bg("spawn", "amp-1", &[]);
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !job.is_finished(),
        "spawn must wait while the agent is going down"
    );
    assert_eq!(hooks(&log), "sleep\n", "no wake until the agent has gone");

    c.terminate_agent("agent-a", Duration::from_secs(30));
    wait_until(Duration::from_secs(30), "wake hook", || {
        hooks(&log) == "sleep\nwake\n"
    });
    c.start_agent("agent-a", "");
    let job = job.join().unwrap();
    assert_ok(&job, "spawn after the host came back");
    assert!(job.stderr.contains("waking"), "stderr:\n{}", job.stderr);
}

/// A slow sleep command is not killed before `hook_timeout_secs`.
#[test]
fn hook_timeout_is_configurable() {
    let mut c = Cluster::new(&["agent-a"], 2);
    let log = with_wake(
        &c,
        &format!(
            "  sleep_command: [sh, -c, \"sleep 3; echo sleep >> {}\"]\n  \
             sleep_after_idle_secs: 1\n  hook_timeout_secs: 2\n",
            c.root().join("hooks.log").display()
        ),
        false,
    );
    c.start_all();
    wait_until(Duration::from_secs(20), "sleep hook killed", || {
        c.logs().contains("timed out after 2s")
    });
    assert_eq!(hooks(&log), "", "the command was killed before it finished");
}
