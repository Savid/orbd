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

/// An overflow agent (`ORBD_OVERFLOW`) gets a new orb only when no other agent fits it,
/// even with more room than they have.
#[test]
fn overflow_agents_take_new_orbs_only_when_the_others_are_full() {
    let mut c = Cluster::new(&["agent-a"], 2);
    c.start_all();
    c.start_agent_with_env(
        "spare",
        &[
            ("ORBD_OVERFLOW", "true"),
            ("ORBD_CAPACITY_VCPUS", "16"),
            ("ORBD_CAPACITY_MEMORY_MIB", "16384"),
        ],
    );
    c.wait_connected(2);
    wait_until(Duration::from_secs(20), "spare reported its disk", || {
        c.metrics()
            .unwrap_or_default()
            .contains("orbd_agent_disk_free_bytes{agent=\"spare\"}")
    });
    let list = c.admin(&["agent", "list"]);
    assert!(
        list.stdout.contains("spare\tconnected (overflow)"),
        "{}",
        list.stdout
    );

    for orb in ["amp-1", "amp-2"] {
        assert_ok(&c.dispatch("spawn", orb, &[]), orb);
    }
    assert_eq!(c.fake_orbs("agent-a").len(), 2, "agent-a fills first");
    assert!(c.fake_orbs("spare").is_empty(), "spare stays empty");

    assert_ok(&c.dispatch("spawn", "amp-3", &[]), "amp-3");
    assert_eq!(
        c.fake_orbs("spare").len(),
        1,
        "agent-a is full: spare takes it"
    );
}

/// Agents report their architecture and orbs only go to agents of theirs. An amd64
/// offering spilling to an arm64 one puts a new orb on the arm64 agent once the amd64
/// one is full, and the orb stays there; an arm64 offering never uses an amd64 agent.
#[test]
fn new_orbs_spill_across_architectures_and_stay_on_theirs() {
    let mut c = Cluster::new(&["amd"], 1);
    let path = c.root().join("coordinator.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap();
    let head = yaml.split("offerings:").next().unwrap();
    let fake = "runtime: fake\n    resources: { vcpus: 2, memory_mib: 2048, disk_gib: 4 }";
    std::fs::write(
        &path,
        format!(
            "{head}offerings:\n  - id: {OFFERING}\n    {fake}\n    spill_to: [{OFFERING}@arm64]\n\
             \x20 - id: {OFFERING}@arm64\n    {fake}\n    arch: arm64\n\
             \x20 - id: arm-only\n    {fake}\n    arch: arm64\n"
        ),
    )
    .unwrap();
    c.set_agent_yaml(
        "mac",
        "runtime:\n  fake:\n    memory_preserving_sleep: true\n    arch: arm64\n    \
         disk: { free_gib: 1000, total_gib: 2000 }\n",
    );
    c.start_all();
    c.start_agent_with_env(
        "mac",
        &[
            ("ORBD_CAPACITY_VCPUS", "4"),
            ("ORBD_CAPACITY_MEMORY_MIB", "4096"),
        ],
    );
    c.wait_connected(2);
    // Orbs on an agent that still have a disk.
    let orbs = |c: &Cluster, agent: &str| c.fake_orbs(agent).iter().filter(|o| o.disk).count();

    assert_ok(&c.dispatch("spawn", "amp-1", &[]), "amp-1");
    assert_eq!(orbs(&c, "amd"), 1, "amd64 first");
    assert_ok(&c.dispatch("spawn", "amp-2", &[]), "amp-2");
    assert_eq!(orbs(&c, "mac"), 1, "amd is full: the arm64 agent takes it");

    // Room on amd again; the arm64 orb wakes where it lives.
    assert_ok(&c.dispatch("delete", "amp-1", &[]), "delete amp-1");
    assert_ok(&c.dispatch("pause", "amp-2", &[]), "pause amp-2");
    assert_ok(&c.dispatch("spawn", "amp-2", &[]), "wake amp-2");
    assert!(c.only_orb("mac").running, "amp-2 woke on mac");

    // arm64 only: the Mac, never amd, even with the Mac full and amd empty.
    c.offering = "arm-only".into();
    assert_ok(&c.dispatch("spawn", "amp-3", &[]), "amp-3");
    assert_eq!(orbs(&c, "mac"), 2);
    let full = c.dispatch("spawn", "amp-4", &[]);
    assert_ne!(full.code, 0, "amp-4 must not be placed:\n{}", full.stdout);
    assert_eq!(orbs(&c, "amd"), 0, "an arm64 orb went to amd");
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

/// `ORBD_IMAGE_ALLOW` is the agent's own: a spawn of another image fails naming the
/// setting before the runtime sees it, whatever the coordinator placed there.
#[test]
fn agents_refuse_images_their_allowlist_does_not_name() {
    let mut c = Cluster::new(&["agent-a"], 2);
    c.agent_env.push((
        "ORBD_IMAGE_ALLOW".into(),
        "example.invalid/amp-orb:stable, example.invalid/tools/*".into(),
    ));
    c.start_all();

    // The cluster's spawns name example.invalid/amp-orb:latest.
    let refused = c.dispatch("spawn", "amp-1", &[]);
    assert_ne!(refused.code, 0, "{}", refused.stdout);
    let out = format!("{}{}", refused.stdout, refused.stderr);
    assert!(
        out.contains(
            "example.invalid/amp-orb:latest is not allowed on this agent (ORBD_IMAGE_ALLOW)"
        ),
        "{out}"
    );
    assert!(
        c.fake_orbs("agent-a").iter().all(|o| !o.disk),
        "the runtime never created a disk"
    );

    for (orb, image) in [
        ("amp-2", "example.invalid/amp-orb:stable"),
        ("amp-3", "example.invalid/tools/orb:1"),
    ] {
        assert_ok(&c.dispatch("spawn", orb, &[("ORB_IMAGE", image)]), image);
    }
    assert!(
        c.logs()
            .contains("only images ORBD_IMAGE_ALLOW lists are prepared and run")
    );
}

/// An orb type with restricted egress (`egress`) goes only to agents that enforce it
/// (here a fake runtime with `egress_policy`), never to one that does not (as Docker and
/// macOS agents, and fake runtimes by default), and an orb of it does not wake on its
/// host once that host no longer enforces it. Orb types without `egress` go anywhere.
#[test]
fn restricted_egress_goes_only_to_agents_that_enforce_it() {
    let mut c = Cluster::new(&["open"], 4);
    let path = c.root().join("coordinator.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap();
    let head = yaml.split("offerings:").next().unwrap();
    let fake = "runtime: fake\n    resources: { vcpus: 2, memory_mib: 2048, disk_gib: 4 }";
    std::fs::write(
        &path,
        format!(
            "{head}offerings:\n  - id: {OFFERING}\n    {fake}\n    \
             egress: {{ domains: [ampcode.com, \"*.ampcode.com\"], allow: [\"tcp:203.0.113.0/24:443\"] }}\n\
             \x20 - id: plain\n    {fake}\n"
        ),
    )
    .unwrap();
    let agent_yaml = |enforces: bool| {
        format!(
            "runtime:\n  fake:\n    memory_preserving_sleep: true\n    egress_policy: {enforces}\n    \
             disk: {{ free_gib: 1000, total_gib: 2000 }}\n"
        )
    };
    c.set_agent_yaml("open", &agent_yaml(false));
    c.start_all();

    let refused = c.dispatch("spawn", "amp-1", &[]);
    assert_ne!(
        refused.code, 0,
        "a restricted orb went to an agent that does not enforce it"
    );
    assert!(c.fake_orbs("open").is_empty());
    c.offering = "plain".into();
    assert_ok(&c.dispatch("spawn", "amp-2", &[]), "unrestricted");
    assert_eq!(c.fake_orbs("open").len(), 1);

    c.set_agent_yaml("strict", &agent_yaml(true));
    c.start_agent("strict", "");
    c.wait_connected(2);
    wait_until(Duration::from_secs(20), "strict reported its disk", || {
        c.metrics()
            .unwrap_or_default()
            .contains("orbd_agent_disk_free_bytes{agent=\"strict\"}")
    });
    c.offering = OFFERING.into();
    assert_ok(&c.dispatch("spawn", "amp-3", &[]), "restricted");
    assert_eq!(c.fake_orbs("strict").len(), 1, "the agent that enforces it");
    assert_eq!(c.fake_orbs("open").len(), 1, "only the unrestricted orb");

    // Its host stops enforcing it (e.g. downgraded): it stays asleep there.
    assert_ok(&c.dispatch("pause", "amp-3", &[]), "pause");
    c.kill_agent("strict");
    c.set_agent_yaml("strict", &agent_yaml(false));
    c.start_agent("strict", "");
    c.wait_connected(2);
    let job = c.dispatch("spawn", "amp-3", &[]);
    assert_ne!(
        job.code, 0,
        "a restricted orb woke on a host that does not enforce it"
    );
    let out = format!("{}{}", job.stdout, job.stderr);
    assert!(out.contains("restricted egress"), "{out}");
    assert!(!c.only_orb("strict").running);
    assert_ok(&c.dispatch("delete", "amp-3", &[]), "delete");
}
