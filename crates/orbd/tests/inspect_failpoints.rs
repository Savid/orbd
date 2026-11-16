//! The operator CLI around failures injected on the agent: an orb that is starting is
//! not reported as blocked by itself, and a delete that fails stays visible and is not
//! reported as "refused". Needs `--features failpoints`.
#![cfg(feature = "failpoints")]

mod common;
use common::*;
use serde_json::Value;
use std::time::Duration;

fn start(c: &mut Cluster, failpoints: &str) {
    c.start_coordinator("");
    c.start_agent("agent-a", failpoints);
    c.wait_connected(1);
}

fn json(job: &Job, what: &str) -> Value {
    assert_ok(job, what);
    serde_json::from_str(&job.stdout).unwrap_or_else(|e| panic!("{what}: {e}: {}", job.stdout))
}

/// While a wake is admitted and in flight, the orb holds its own reservation: it is
/// "starting", not blocked by itself, and `status --check` stays healthy even though an
/// earlier wake of it was refused.
#[test]
fn a_waking_orb_is_not_blocked_by_its_own_reservation() {
    let mut c = Cluster::new(&["agent-a"], 2);
    start(&mut c, "fake::start::delay=return(3000)");
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn 1");
    assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause 1");
    assert_ok(&c.dispatch("spawn", "amp-2", &[]), "spawn 2");
    assert_ok(&c.dispatch("spawn", "amp-3", &[]), "spawn 3");
    assert_eq!(c.dispatch("spawn", "amp-1", &[]).code, 1, "refused: full");
    assert_ok(&c.dispatch("pause", "amp-2", &[]), "pause 2");

    let wake = c.dispatch_bg("spawn", "amp-1", &[]);
    wait_until(Duration::from_secs(10), "the wake in flight", || {
        let o = c.admin(&["orb", "show", "amp-1", "--json"]);
        o.stdout.contains("\"open_command\": {")
    });
    let one = json(&c.admin(&["orb", "show", "amp-1", "--json"]), "show");
    assert_eq!(one["open_command"]["action"], "spawn");
    assert_eq!(one["wake_blockers"], serde_json::json!([]), "{one}");
    let check = c.admin(&["status", "--check"]);
    assert_ok(&wake.join().unwrap(), "wake");
    assert_eq!(check.code, 0, "{}", check.stdout);
}

/// A delete that fails on the agent exits 1 (it ran; not "refused, nothing done"), and
/// the orb stays listed as deleting, an error in `status`, until a forced delete retries
/// it.
#[test]
fn a_failed_delete_stays_visible() {
    let mut c = Cluster::new(&["agent-a"], 2);
    start(&mut c, "fake::delete=return");
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn");
    assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause");

    let del = c.admin(&["orb", "delete", "T-1", "--force", "--json"]);
    assert_eq!(del.code, 1, "{}", del.stderr);
    let err: Value = serde_json::from_str(del.stderr.trim()).unwrap();
    assert_eq!(err["error"]["kind"], "failed");

    let one = json(&c.admin(&["orb", "show", "amp-1", "--json"]), "show");
    assert_eq!(one["state"], "deleting");
    let status = json(&c.admin(&["status", "--json"]), "status");
    assert_eq!(status["healthy"], false);
    assert_eq!(
        status["problems"][0]["kind"], "orb_delete_failed",
        "{status}"
    );
    assert_eq!(status["orb_counts"]["deleting"], 1);
    let list = c.admin(&["orb", "list"]);
    assert!(list.stdout.contains("delete failed"), "{}", list.stdout);
}
