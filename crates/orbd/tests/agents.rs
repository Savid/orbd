//! Agent enrollment and removal through real processes.

mod common;
use common::*;
use std::process::Stdio;
use std::time::Duration;

/// Runs an agent that is expected to give up at once; returns its log.
fn refused_agent(c: &Cluster, id: &str, token: &str) -> String {
    let status = c
        .agent_command(id, token, "")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!status.status.success(), "agent {id} must not start");
    String::from_utf8_lossy(&status.stderr).into_owned()
}

/// A join token enrolls one agent, once, before it expires; and is never logged.
#[test]
fn join_tokens_are_single_use_and_expire() {
    let mut c = Cluster::new(&["agent-a"], 1);
    c.start_all();

    // Reuse: a second host presenting agent-a's token (its own, different key).
    let token = c.join_token("agent-b");
    c.start_agent_with_token("agent-b", &token);
    c.wait_connected(2);
    let err = refused_agent(&c, "agent-b-copy", &token);
    assert!(err.contains("already used"), "{err}");

    let j = c.admin(&["join-token", "agent-c", "--ttl-secs", "1"]);
    assert_ok(&j, "join-token");
    std::thread::sleep(Duration::from_millis(1500));
    let err = refused_agent(&c, "agent-c", &j.stdout);
    assert!(err.contains("expired"), "{err}");

    // An id that is already enrolled gets no new token.
    let again = c.admin(&["join-token", "agent-a"]);
    assert_ne!(again.code, 0);
    assert!(
        again.stderr.contains("already registered"),
        "{}",
        again.stderr
    );

    assert_ok(
        &c.dispatch("spawn", "amp-1", &[]),
        "spawn after enrollments",
    );
    assert!(!c.logs().contains(&token), "join token leaked into logs");
}

/// An agent can dial any of the coordinator's URLs (`public_url` or `extra_urls`): one
/// picked for its join token, or one set later with `ORBD_COORDINATOR_URL`, without
/// enrolling again. The coordinator's certificate names every host.
#[test]
fn agents_dial_any_coordinator_url() {
    let mut c = Cluster::new(&["agent-a"], 1);
    c.start_all();
    let extra = format!("https://127.0.0.1:{}", c.control_port());

    let bad = c.admin(&[
        "join-token",
        "agent-b",
        "--url",
        "https://elsewhere.example:1",
    ]);
    assert_ne!(bad.code, 0);
    assert!(bad.stderr.contains("extra_urls"), "{}", bad.stderr);

    let j = c.admin(&["join-token", "agent-b", "--url", &extra]);
    assert_ok(&j, "join-token --url");
    c.start_agent_with_token("agent-b", &j.stdout);
    c.wait_connected(2);

    c.terminate_agent("agent-a", Duration::from_secs(30));
    c.wait_connected(1);
    c.agent_env
        .push(("ORBD_COORDINATOR_URL".into(), extra.clone()));
    c.start_agent("agent-a", "");
    c.wait_connected(2);
    assert!(
        c.logs()
            .contains("dialing the coordinator at an override URL"),
        "agent-a did not use ORBD_COORDINATOR_URL"
    );
}

/// `orbd agent remove` cuts the agent off for good: its session ends, it cannot
/// reconnect, and its orbs stay recorded on it (unavailable, never moved elsewhere).
#[test]
fn removed_agent_cannot_connect_and_keeps_its_orbs() {
    let mut c = Cluster::new(&["agent-a", "agent-b"], 1);
    c.start_all();
    assert_ok(&c.dispatch("spawn", "amp-x", &[]), "spawn x");
    let home = if c.fake_orbs("agent-a").is_empty() {
        "agent-b"
    } else {
        "agent-a"
    };

    assert_ok(&c.admin(&["agent", "remove", home]), "agent remove");
    c.wait_connected(1);
    let list = c.admin(&["agent", "list"]);
    assert!(
        list.stdout.contains(&format!("{home}\tremoved")),
        "{}",
        list.stdout
    );

    // The still-running agent process keeps retrying and is refused every time.
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(c.connected_agents(), Some(1));
    assert!(
        c.logs().contains("not an active agent"),
        "refusal not logged"
    );

    let job = c.dispatch("spawn", "amp-x", &[]);
    assert_eq!(job.code, 75, "orb on a removed agent: {}", job.stderr);
    assert!(job.stderr.contains("BackendUnavailable"), "{}", job.stderr);
    let other = if home == "agent-a" {
        "agent-b"
    } else {
        "agent-a"
    };
    assert!(c.fake_orbs(other).is_empty(), "orb must not be re-placed");

    let rejoin = c.admin(&["join-token", home]);
    assert_ne!(rejoin.code, 0, "a removed id is never reused");
}
