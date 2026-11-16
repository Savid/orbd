//! The operator CLI on the coordinator (`orbd status`, `orbd orb list|show`): what an
//! operator or a coding agent needs to see why an orb is stuck, as text and as JSON,
//! with stable exit codes.

mod common;
use common::*;
use serde_json::Value;

fn json(job: &Job, what: &str) -> Value {
    assert_ok(job, what);
    serde_json::from_str(&job.stdout).unwrap_or_else(|e| panic!("{what}: {e}: {}", job.stdout))
}

fn orb<'a>(list: &'a Value, id: &str) -> &'a Value {
    list["orbs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["amp_orb_id"] == id)
        .unwrap_or_else(|| panic!("{id} not in {list}"))
}

/// An asleep orb whose agent is full cannot wake: `status`, `orb list` and `orb show`
/// say so with the numbers and what to do, and stop saying so once it woke.
#[test]
fn a_stuck_orb_is_visible_and_explained() {
    let mut c = Cluster::new(&["agent-a"], 2);
    c.start_all();
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn 1");
    assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause 1");
    assert_ok(&c.dispatch("spawn", "amp-2", &[]), "spawn 2");
    assert_ok(&c.dispatch("spawn", "amp-3", &[]), "spawn 3");
    let refused = c.dispatch("spawn", "amp-1", &[]);
    assert_eq!(refused.code, 1, "agent-a is full: {}", refused.stderr);

    let list = json(&c.admin(&["--json", "orb", "list"]), "orb list --json");
    assert_eq!(list["orbs"].as_array().unwrap().len(), 3);
    let one = orb(&list, "amp-1");
    assert_eq!(one["state"], "asleep");
    assert_eq!(one["thread_id"], "T-1");
    assert_eq!(one["agent"], "agent-a");
    assert_eq!(one["orb_type"], OFFERING);
    assert_eq!(
        (one["arch"].as_str(), one["runtime"].as_str()),
        (Some("amd64"), Some("fake"))
    );
    assert_eq!(one["memory_bytes"], 2u64 << 30);
    assert_eq!(one["failures_since_success"], 1);
    assert_eq!(one["failures"][0]["action"], "spawn");
    assert_eq!(one["failures"][0]["code"], "insufficient_memory");
    assert!(one["failures"][0]["operation_id"].is_null(), "{one}");
    let blocker = one["wake_blockers"][0].as_str().unwrap();
    assert!(
        blocker.starts_with("memory: needs 2.0 GiB, 0.0 GiB free of 4.0 GiB"),
        "{blocker}"
    );
    let two = orb(&list, "amp-2");
    assert_eq!(two["state"], "running");
    assert_eq!(two["wake_blockers"].as_array().unwrap().len(), 0);
    assert_eq!(two["failures_since_success"], 0);
    assert!(two["last_active_unix_ms"].as_u64().unwrap() > 0);

    let text = c.admin(&["orb", "list"]);
    assert_ok(&text, "orb list");
    let lines: Vec<&str> = text.stdout.lines().collect();
    assert!(lines[0].starts_with("ORB    STATE"), "{}", text.stdout);
    assert!(
        lines[1].starts_with("amp-1  asleep") && lines[1].ends_with("can't wake: memory, vCPUs"),
        "{}",
        text.stdout
    );

    let problems = json(
        &c.admin(&["--json", "orb", "list", "--problems"]),
        "--problems",
    );
    let ids: Vec<&str> = problems["orbs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["amp_orb_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["amp-1"]);
    let running = json(
        &c.admin(&[
            "--json", "orb", "list", "--state", "running", "--agent", "agent-a",
        ]),
        "--state running",
    );
    assert_eq!(running["orbs"].as_array().unwrap().len(), 2);

    let show = c.admin(&["orb", "show", "amp-1"]);
    assert_ok(&show, "orb show");
    for want in [
        "thread      T-1",
        "wake check  would be refused: memory: needs 2.0 GiB",
        "failing     1 spawn failures since its last successful spawn:",
        "COMMANDS (latest first)",
        "AMP REQUESTS",
        "spawn failed: InsufficientMemory",
        "NEXT",
        "orbs never move to another agent",
    ] {
        assert!(
            show.stdout.contains(want),
            "{want:?} missing:\n{}",
            show.stdout
        );
    }
    // By thread id, as JSON.
    let one = json(&c.admin(&["--json", "orb", "show", "T-1"]), "orb show T-1");
    assert_eq!(one["amp_orb_id"], "amp-1");
    let actions: Vec<&str> = one["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, ["pause", "spawn"], "latest first");
    assert_eq!(one["commands"][0]["result"], "paused (memory checkpoint)");
    assert_eq!(one["requests"][0]["result"], "failed");
    assert!(!one["hints"].as_array().unwrap().is_empty());

    // Errors: exit code by kind; JSON on stderr with --json.
    let ambiguous = c.admin(&["orb", "show", "amp-"]);
    assert_eq!(ambiguous.code, 2, "{}", ambiguous.stderr);
    assert!(
        ambiguous.stderr.contains("matches 3 orbs"),
        "{}",
        ambiguous.stderr
    );
    let missing = c.admin(&["--json", "orb", "show", "amp-9"]);
    assert_eq!(missing.code, 3, "{}", missing.stderr);
    let err: Value = serde_json::from_str(missing.stderr.trim()).unwrap();
    assert_eq!(err["error"]["kind"], "not_found");
    assert_eq!(err["error"]["exit_code"], 3);
    let in_use = c.admin(&["orb", "delete", "amp-2", "--min-asleep-mins", "0"]);
    assert_eq!(
        in_use.code, 4,
        "a running orb is refused: {}",
        in_use.stderr
    );
    assert!(in_use.stderr.contains("hint: "), "{}", in_use.stderr);

    let status = json(&c.admin(&["--json", "status"]), "status --json");
    assert_eq!(status["healthy"], false);
    assert_eq!(status["orbs"]["running"], 2);
    assert_eq!(status["orbs"]["asleep"], 1);
    let agent = &status["agents"][0];
    assert_eq!(
        (agent["agent_id"].as_str(), agent["state"].as_str()),
        (Some("agent-a"), Some("connected"))
    );
    assert_eq!(agent["memory_booked_bytes"], 4u64 << 30);
    let kinds: Vec<(&str, &str)> = status["problems"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["kind"].as_str().unwrap(), p["subject"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds[0], ("orb_cannot_wake", "amp-1"), "{kinds:?}");
    let check = c.admin(&["status", "--check"]);
    assert_eq!(check.code, 6, "{}", check.stderr);
    assert!(
        check.stdout.contains("PROBLEMS") && check.stdout.contains("amp-1 cannot wake on agent-a"),
        "{}",
        check.stdout
    );
    let agents = json(&c.admin(&["--json", "agent", "list"]), "agent list --json");
    assert_eq!(agents["agents"][0]["running_orbs"], 2);

    // Room made: it wakes, and nothing is wrong any more.
    assert_ok(&c.dispatch("pause", "amp-2", &[]), "pause 2");
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "wake 1");
    let status = json(&c.admin(&["--json", "status"]), "status after wake");
    assert_eq!(status["healthy"], true, "{status}");
    let list = json(&c.admin(&["--json", "orb", "list"]), "orb list after wake");
    assert_eq!(orb(&list, "amp-1")["failures_since_success"], 0);
    assert_ok(&c.admin(&["status", "--check"]), "status --check");
}

/// A disconnected agent is an error in `status`, and its orbs say why they cannot wake.
#[test]
fn a_disconnected_agent_is_reported() {
    let mut c = Cluster::new(&["agent-a"], 2);
    c.start_all();
    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "spawn");
    assert_ok(&c.dispatch("pause", "amp-1", &[]), "pause");
    c.kill_agent("agent-a");
    wait_until(
        std::time::Duration::from_secs(10),
        "agent marked disconnected",
        || {
            let s = c.admin(&["--json", "status"]);
            s.stdout.contains("agent_disconnected")
        },
    );
    let one = json(&c.admin(&["--json", "orb", "show", "amp-1"]), "orb show");
    let blocker = one["wake_blockers"][0].as_str().unwrap();
    assert!(blocker.starts_with("agent-a is unavailable"), "{blocker}");
}
