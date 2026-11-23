//! Coordinator configuration (`orbd coordinator`, default `/etc/orbd/orbd.yaml`).
//!
//! `config_version: v2` describes what orbs need; orbd picks where they run:
//!
//! ```yaml
//! config_version: v2
//! public_url: https://coordinator.example:7443
//! provider: { token_file: /etc/orbd/tokens/provider }
//! orb_types:                      # named as orb types in Amp; the first is the default
//!   - { id: 2vcpu-4gb, vcpus: 2, memory_mib: 4096, disk_gib: 40 }
//!   - { id: kvm-4vcpu-8gb, vcpus: 4, memory_mib: 8192, disk_gib: 40, kvm: true }
//!   - id: untrusted-4vcpu-8gb       # restricted egress: only what `egress` lists
//!     vcpus: 4
//!     memory_mib: 8192
//!     disk_gib: 40
//!     egress: { domains: [ampcode.com, "*.ampcode.com"], allow: ["tcp:140.82.112.0/20:22"] }
//! ```
//!
//! Without `config_version` (v1) the file lists `offerings`, each pinned to a runtime,
//! and `providers`. A v2 file is turned into v1
//! offerings at load (see [`CoordinatorConfig::normalize`]), so everything after loading
//! sees one form.
//!
//! The coordinator serves one Amp endpoint, one agent fleet and optionally Boat
//! (`boat:`, offerings with `runtime: boat`); pause policy and capability requirements
//! follow from each offering's runtime.

use super::{ConfigError, ResourcesConfig, load_yaml};
use crate::model::{
    AmpEndpointId, Arch, BackendId, BackendProfileId, CapabilityRequirements,
    CheckpointFailurePolicy, ExecutionTarget, NestedKvmRequirement, Offering, OfferingId,
    PausePolicy, RuntimeKind, SnapshotRequirement, SpecTemplate,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Id of the single Amp endpoint (orb identity is scoped by it).
pub const AMP_ENDPOINT: &str = "amp";
/// Id of the single agent-fleet backend (recorded in every orb's location).
pub const FLEET_BACKEND: &str = "fleet";
/// Id of the Boat backend (recorded in the location of every Boat orb).
pub const BOAT_BACKEND: &str = "boat";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorConfig {
    /// `v2` for `provider` and `orb_types`; absent or `v1` for `offerings` and `providers`.
    #[serde(default)]
    pub config_version: ConfigVersion,
    /// URL agents dial, e.g. `https://coordinator.example:7443`. Join tokens carry it, and
    /// its host is the name on the coordinator's certificate.
    pub public_url: String,
    /// Other URLs that reach the same listener, for agents that cannot dial `public_url`
    /// (e.g. a Tailscale or VPN address). Their hosts are also named on the certificate.
    /// `orbd join-token --url` puts one in a token; `ORBD_COORDINATOR_URL` moves an
    /// enrolled agent to one without enrolling again.
    #[serde(default)]
    pub extra_urls: Vec<String>,
    /// AgentControl listener (TLS).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Database, keys, CA and the local dispatch/admin sockets.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_amp_url")]
    pub amp_url: String,
    /// Prometheus listener, e.g. `127.0.0.1:9464`. Disabled when absent.
    pub metrics_listen: Option<SocketAddr>,
    /// Heartbeat interval sent to agents in `Welcome`.
    #[serde(default = "default_heartbeat_ms")]
    pub heartbeat_interval_ms: u64,
    /// Executable the generated `orbd-dispatch` wrapper runs as `<exe> dispatch`.
    /// Defaults to the running orbd binary; set it to a stable path (e.g.
    /// `/usr/local/bin/orbd`) if the binary is replaced in place on upgrade.
    pub dispatch_exe: Option<PathBuf>,
    /// Amp CLI used for `amp orb provider` children.
    #[serde(default = "default_amp_cli")]
    pub amp_cli: PathBuf,
    /// How often to run `amp update` for `amp_cli` (seconds; 0 disables). Providers are
    /// restarted onto a new version between jobs. The CLI never self-updates.
    #[serde(default = "default_amp_cli_update_interval")]
    pub amp_cli_update_interval_secs: u64,
    /// Disk held free on its host for each running orb to grow into (capped at the
    /// orb's disk size), on top of its next memory checkpoint. Sleeping orbs hold none.
    #[serde(default = "default_running_orb_disk_headroom_gib")]
    pub running_orb_disk_headroom_gib: u64,
    /// Orbs asleep longer than this many days are deleted (0 never deletes). Amp sends
    /// no delete when a thread is archived, only a pause, so this is what frees the
    /// disks of abandoned orbs. An orb woken after it was deleted starts fresh from the
    /// image: its files and processes are gone and Amp runs setup again.
    #[serde(default = "default_idle_orb_ttl_days")]
    pub idle_orb_ttl_days: u64,
    /// Boat (boat.dev) sandboxes: offerings with `runtime: boat` (v1), or orb types of a
    /// Boat size that `prefer` allows on Boat (v2).
    pub boat: Option<BoatConfig>,
    /// Commands that start and stop the agents' hosts.
    pub wake: Option<WakeConfig>,
    /// v1: each offering is one runtime and size. v2: generated from `orb_types`.
    #[serde(default)]
    pub offerings: Vec<OfferingConfig>,
    /// v1: Amp orb providers whose orb types are offerings. v2: generated from `provider`.
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    /// v2: the Amp orb provider serving every orb type.
    pub provider: Option<ProviderV2Config>,
    /// v2: where new orbs go, in order; default `[local, boat]`. Boat takes an orb type
    /// only without `kvm` and in a Boat size; local runs it on the agents, in QEMU with
    /// `kvm`, else in Firecracker. An orb stays where it was first placed.
    pub prefer: Option<Vec<Prefer>>,
    /// v2: what threads can ask for, named as orb types in Amp; the first is used when a
    /// spawn has none.
    #[serde(default)]
    pub orb_types: Vec<OrbTypeConfig>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigVersion {
    #[default]
    V1,
    V2,
}

/// v2 `provider:`: one Amp orb provider with orb types.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderV2Config {
    /// `AMP_ORB_PROVIDER_TOKEN` of the provider.
    pub token_file: PathBuf,
    /// Tokens of providers being retired. They are still served so their threads keep
    /// their orbs; a spawn of a new orb from one gets the default orb type. Drop them
    /// once those threads are gone.
    #[serde(default)]
    pub retired_token_files: Vec<PathBuf>,
}

/// v2: where new orbs may go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prefer {
    /// The agents.
    Local,
    /// Boat (needs `boat:`).
    Boat,
}

/// v2: one orb type: what an orb gets, not where it runs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrbTypeConfig {
    pub id: OfferingId,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_gib: u64,
    /// `/dev/kvm` in the orb: runs only in QEMU on the agents.
    #[serde(default)]
    pub kvm: bool,
    /// CPU architectures a new orb may get, in order: `amd64` (the default), `arm64`,
    /// or a list such as `[amd64, arm64]`. An orb keeps the one it was placed with for
    /// life. arm64 orbs run on arm64 agents (Apple Silicon Macs) in QEMU, without kvm;
    /// Amp's amp-orb image becomes amp-orb-arm64 there.
    #[serde(default = "default_archs", deserialize_with = "one_or_many")]
    pub arch: Vec<Arch>,
    /// Restricted egress: the orb reaches only names matching `domains` (resolved by its
    /// agent's DNS proxy) on `ports` (default `[tcp:443]`), the destinations `allow`
    /// names (private ones only where the agent's own `ORBD_EGRESS_ALLOW` allows them
    /// too), and nothing else. Runs only on agents that enforce it (Linux VM runtimes),
    /// never on Boat. See [`crate::model::egress`].
    #[serde(default)]
    pub egress: Option<crate::model::EgressPolicy>,
}

fn default_archs() -> Vec<Arch> {
    vec![Arch::Amd64]
}

/// `arch: arm64` or `arch: [amd64, arm64]`.
fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Arch>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(Arch),
        Many(Vec<Arch>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(a) => vec![a],
        OneOrMany::Many(v) => v,
    })
}

/// One Amp orb provider with orb types. Each orb type in Amp is named after the
/// offering it runs on; Amp passes the thread's type to every spawn as `ORB_TYPE`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Names the provider in logs and metrics; distinct from every offering id.
    pub id: String,
    /// `AMP_ORB_PROVIDER_TOKEN` for this provider's `amp orb provider` child.
    pub token_file: PathBuf,
    /// The offerings, named as orb types in Amp. The first is used when a spawn has no
    /// `ORB_TYPE` (the provider has no orb types in Amp).
    pub orb_types: Vec<OfferingId>,
}

/// `boat:`: runs orbs as Boat sandboxes, driven by the coordinator over Boat's API.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoatConfig {
    /// File holding the Boat API key (`boat_...`).
    pub api_key_file: PathBuf,
    /// What running Boat orbs may hold together (sleeping ones hold nothing): the
    /// spending cap. Keep it within the plan's "sandboxes at once".
    pub capacity: BoatCapacity,
    /// Boat stops a sandbox this long after it was created or resumed, in case Amp
    /// never pauses it (0 never stops it). The free trial allows at most 7200.
    #[serde(default = "default_boat_auto_stop")]
    pub auto_stop_secs: u64,
    #[serde(default = "default_boat_api_url")]
    pub api_url: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoatCapacity {
    pub vcpus: u32,
    pub memory_mib: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeConfig {
    /// Argv, no shell. Run when a spawn finds no agent; the spawn waits for one.
    pub command: Vec<String>,
    /// At most 200, to fit Amp's job budget.
    #[serde(default = "default_wake_timeout")]
    pub timeout_secs: u64,
    /// Sleeping orbs do not count as activity.
    pub sleep_command: Option<Vec<String>>,
    #[serde(default)]
    pub sleep_after_idle_secs: u64,
    /// Either command is killed after this long.
    #[serde(default = "default_hook_timeout")]
    pub hook_timeout_secs: u64,
}

fn default_hook_timeout() -> u64 {
    120
}

fn default_wake_timeout() -> u64 {
    180
}

/// Longest `wake.timeout_secs`: Amp's job budget, less time to start the orb.
pub const MAX_WAKE_TIMEOUT_SECS: u64 = 200;

fn default_boat_auto_stop() -> u64 {
    24 * 60 * 60
}

fn default_boat_api_url() -> String {
    "https://boat.dev/api/v1".into()
}

/// Where an offering's orbs run: a fleet runtime on the agents, or Boat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferingRuntime {
    Fake,
    Docker,
    Qemu,
    Firecracker,
    Boat,
}

impl OfferingRuntime {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fake => "fake",
            Self::Docker => "docker",
            Self::Qemu => "qemu",
            Self::Firecracker => "firecracker",
            Self::Boat => "boat",
        }
    }

    fn fleet(self) -> Option<RuntimeKind> {
        match self {
            Self::Fake => Some(RuntimeKind::Fake),
            Self::Docker => Some(RuntimeKind::Docker),
            Self::Qemu => Some(RuntimeKind::Qemu),
            Self::Firecracker => Some(RuntimeKind::Firecracker),
            Self::Boat => None,
        }
    }
}

fn default_running_orb_disk_headroom_gib() -> u64 {
    10
}

fn default_idle_orb_ttl_days() -> u64 {
    30
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 7443))
}

pub(crate) fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/orbd")
}

fn default_amp_url() -> String {
    "https://ampcode.com".into()
}

fn default_heartbeat_ms() -> u64 {
    5_000
}

fn default_amp_cli_update_interval() -> u64 {
    6 * 60 * 60
}

fn default_amp_cli() -> PathBuf {
    PathBuf::from("amp")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferingConfig {
    pub id: OfferingId,
    pub runtime: OfferingRuntime,
    /// For `runtime: boat`, the vCPUs and memory of a Boat size (see
    /// [`crate::backend::boat::SIZES`]).
    pub resources: ResourcesConfig,
    /// Offerings that take a new orb, in order, when no host of this one can. Each must
    /// be like-for-like: `/dev/kvm` in the orb on both or neither, and at least these
    /// vCPUs and memory. The architecture may differ: the orb gets the one it is placed
    /// with. Spill targets' own spill_to lists are not followed.
    #[serde(default)]
    pub spill_to: Vec<OfferingId>,
    /// CPU architecture of the orbs (default amd64); only agents of that architecture
    /// take them. arm64 orbs run in QEMU, without `/dev/kvm`.
    #[serde(default)]
    pub arch: Arch,
    /// Restricted egress, as an orb type's `egress` (QEMU, Firecracker and fake only).
    #[serde(default)]
    pub egress: Option<crate::model::EgressPolicy>,
}

impl OfferingConfig {
    /// Pause policy and requirements are what the runtime is for: VM runtimes keep
    /// memory across sleep (falling back to a cold stop) and QEMU gives amd64 orbs
    /// `/dev/kvm`; Docker and Boat sleep to disk. Every runtime releases compute while
    /// paused.
    pub fn to_offering(&self) -> Result<Offering, ConfigError> {
        let pause_policy = match self.runtime {
            OfferingRuntime::Docker | OfferingRuntime::Boat => PausePolicy::DiskOnly,
            OfferingRuntime::Qemu | OfferingRuntime::Firecracker | OfferingRuntime::Fake => {
                PausePolicy::MemoryPreserving {
                    on_failure: CheckpointFailurePolicy::ColdStop,
                }
            }
        };
        let arm64 = self.arch == Arch::Arm64;
        if arm64 && !matches!(self.runtime, OfferingRuntime::Qemu | OfferingRuntime::Fake) {
            return Err(ConfigError::Invalid(format!(
                "offering {}: arm64 orbs run in QEMU (runtime: qemu)",
                self.id
            )));
        }
        if self.egress.is_some()
            && !matches!(
                self.runtime,
                OfferingRuntime::Qemu | OfferingRuntime::Firecracker | OfferingRuntime::Fake
            )
        {
            return Err(ConfigError::Invalid(format!(
                "offering {}: egress is enforced only for VM orbs on the agents (runtime: qemu \
                 or firecracker), not {}",
                self.id,
                self.runtime.as_str()
            )));
        }
        // Hypervisor.framework does not nest: arm64 orbs get no /dev/kvm.
        let nested_kvm = match self.runtime {
            OfferingRuntime::Qemu if !arm64 => NestedKvmRequirement::GuestDevice,
            _ => NestedKvmRequirement::NotRequired,
        };
        let (backend, target) = match self.runtime.fleet() {
            Some(runtime) => (FLEET_BACKEND, ExecutionTarget::Fleet { runtime }),
            None => {
                let r = self.resources;
                let size =
                    crate::backend::boat::size_for(r.vcpus, r.memory_mib).ok_or_else(|| {
                        ConfigError::Invalid(format!(
                            "offering {}: Boat has no size with {} vCPUs and {} MiB; use one of {}",
                            self.id,
                            r.vcpus,
                            r.memory_mib,
                            crate::backend::boat::describe_sizes()
                        ))
                    })?;
                (
                    BOAT_BACKEND,
                    ExecutionTarget::Provider {
                        profile: BackendProfileId::new(size.name),
                    },
                )
            }
        };
        Ok(Offering {
            id: self.id.clone(),
            amp_endpoint: AmpEndpointId::new(AMP_ENDPOINT),
            backend_id: BackendId::new(backend),
            spill_to: self.spill_to.clone(),
            spec: SpecTemplate {
                target,
                resources: self.resources.to_resources()?,
                requirements: CapabilityRequirements {
                    release_compute_when_paused: true,
                    nested_kvm,
                    project_snapshots: SnapshotRequirement::NotRequired,
                    arch: self.arch,
                    egress: self.egress.clone(),
                },
                pause_policy,
            },
        })
    }
}

/// Why an orb of `from` cannot run as `to`, or None if `to` is like-for-like: `/dev/kvm`
/// in the orb on both or neither, the same egress policy, and at least as much compute.
/// Sleep may differ: an
/// orb spilled to Boat keeps its disk across a pause but not its processes. So may the
/// architecture: a new orb has none yet.
fn unlike(from: &SpecTemplate, to: &SpecTemplate) -> Option<String> {
    let kvm = |s: &SpecTemplate| s.requirements.nested_kvm != NestedKvmRequirement::NotRequired;
    let (a, b) = (from.resources, to.resources);
    if kvm(from) != kvm(to) {
        Some(format!(
            "one gives orbs /dev/kvm and the other does not ({} vs {})",
            if kvm(from) { "kvm" } else { "no kvm" },
            if kvm(to) { "kvm" } else { "no kvm" }
        ))
    } else if from.requirements.egress != to.requirements.egress {
        Some("their egress policies differ".into())
    } else if b.vcpus < a.vcpus || b.memory_bytes < a.memory_bytes {
        Some(format!(
            "it is smaller ({} vCPUs / {} MiB vs {} / {})",
            b.vcpus,
            b.memory_bytes / crate::model::MIB,
            a.vcpus,
            a.memory_bytes / crate::model::MIB
        ))
    } else {
        None
    }
}

impl CoordinatorConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut cfg: Self = load_yaml(path)?;
        cfg.normalize()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Turns a v2 file into v1 offerings and providers. Each orb type becomes an
    /// offering with its id on the first place `prefer` and its `arch` list allow,
    /// spilling to the others (hidden offerings `<id>@<runtime>`, `<id>@arm64`).
    /// Within a place, archs go in the orb type's order. An orb records the orb type it
    /// was created as, wherever it was placed. The provider and each retired token serve
    /// every orb type.
    pub fn normalize(&mut self) -> Result<(), ConfigError> {
        let inv = |m: &str| Err(ConfigError::Invalid(m.into()));
        if self.config_version == ConfigVersion::V1 {
            if self.provider.is_some() || self.prefer.is_some() || !self.orb_types.is_empty() {
                return inv("provider, prefer and orb_types need config_version: v2");
            }
            return Ok(());
        }
        if !self.offerings.is_empty() || !self.providers.is_empty() {
            return inv(
                "config_version v2 has orb_types and provider instead of offerings and providers",
            );
        }
        let Some(provider) = &self.provider else {
            return inv("config_version v2 needs a provider");
        };
        if self.orb_types.is_empty() {
            return inv("orb_types is empty");
        }
        let prefer = match self.prefer.clone() {
            Some(p) => {
                if p.is_empty() || p.iter().enumerate().any(|(i, x)| p[..i].contains(x)) {
                    return inv("prefer lists local and boat, each at most once");
                }
                if p.contains(&Prefer::Boat) && self.boat.is_none() {
                    return inv("prefer: boat needs a `boat:` section");
                }
                p
            }
            None => vec![Prefer::Local, Prefer::Boat],
        };
        for t in &self.orb_types {
            let bad = |m: &str| Err(ConfigError::Invalid(format!("orb type {}: {m}", t.id)));
            if let Some(Err(e)) = t.egress.as_ref().map(|p| p.check_config()) {
                return bad(&e);
            }
            let archs = &t.arch;
            if archs.is_empty()
                || archs
                    .iter()
                    .enumerate()
                    .any(|(i, a)| archs[..i].contains(a))
            {
                return bad("arch lists amd64 and arm64, each at most once");
            }
            if t.kvm && archs.contains(&Arch::Arm64) {
                return bad("kvm orbs are amd64 only (Apple Silicon does not nest)");
            }
            // Boat runs amd64 orbs without kvm and restricted egress, in its own sizes.
            let boat = !t.kvm
                && t.egress.is_none()
                && archs.contains(&Arch::Amd64)
                && self.boat.is_some()
                && crate::backend::boat::size_for(t.vcpus, t.memory_mib).is_some();
            // On the agents: kvm and arm64 orbs in QEMU, other amd64 orbs in Firecracker.
            let local = |a: Arch| match a {
                Arch::Amd64 if !t.kvm => OfferingRuntime::Firecracker,
                _ => OfferingRuntime::Qemu,
            };
            let mut places: Vec<(OfferingRuntime, Arch)> = Vec::new();
            for p in &prefer {
                match p {
                    Prefer::Local => places.extend(archs.iter().map(|&a| (local(a), a))),
                    Prefer::Boat if boat => places.push((OfferingRuntime::Boat, Arch::Amd64)),
                    Prefer::Boat => {}
                }
            }
            if places.is_empty() {
                return bad(&format!(
                    "nowhere in prefer can run it (Boat runs no kvm, no arm64, no egress and \
                     only {})",
                    crate::backend::boat::describe_sizes()
                ));
            }
            let id = |i: usize, (r, a): (OfferingRuntime, Arch)| match (i, a) {
                (0, _) => t.id.clone(),
                (_, Arch::Amd64) => OfferingId::new(format!("{}@{}", t.id, r.as_str())),
                _ => OfferingId::new(format!("{}@{}", t.id, a.as_str())),
            };
            for (i, &(runtime, arch)) in places.iter().enumerate() {
                self.offerings.push(OfferingConfig {
                    id: id(i, (runtime, arch)),
                    runtime,
                    resources: ResourcesConfig {
                        vcpus: t.vcpus,
                        memory_mib: t.memory_mib,
                        disk_gib: t.disk_gib,
                    },
                    spill_to: match i {
                        0 => places
                            .iter()
                            .enumerate()
                            .skip(1)
                            .map(|(j, &p)| id(j, p))
                            .collect(),
                        _ => vec![],
                    },
                    arch,
                    egress: t.egress.clone(),
                });
            }
        }
        let types: Vec<OfferingId> = self.orb_types.iter().map(|t| t.id.clone()).collect();
        let tokens = std::iter::once(&provider.token_file).chain(&provider.retired_token_files);
        for (i, token_file) in tokens.enumerate() {
            self.providers.push(ProviderConfig {
                id: match i {
                    0 => "provider".into(),
                    _ => format!("retired-{i}"),
                },
                token_file: token_file.clone(),
                orb_types: types.clone(),
            });
        }
        Ok(())
    }

    /// Every URL agents may dial: `public_url` first, then `extra_urls` (duplicates dropped).
    pub fn agent_urls(&self) -> Vec<String> {
        let mut urls = vec![self.public_url.clone()];
        for u in &self.extra_urls {
            if !urls.contains(u) {
                urls.push(u.clone());
            }
        }
        urls
    }

    /// Structural validation. Capability validation against the backend happens when
    /// it is constructed (see `coordinator`).
    pub fn validate(&self) -> Result<(), ConfigError> {
        let inv = |m: String| Err(ConfigError::Invalid(m));
        crate::pki::url_host(&self.public_url)
            .map_err(|e| ConfigError::Invalid(format!("public_url: {e}")))?;
        for u in &self.extra_urls {
            crate::pki::url_host(u)
                .map_err(|e| ConfigError::Invalid(format!("extra_urls: {e}")))?;
        }
        if self.heartbeat_interval_ms == 0 {
            return inv("heartbeat_interval_ms must be > 0".into());
        }
        if self.offerings.is_empty() {
            return inv("no offerings (or orb_types, with config_version: v2)".into());
        }
        let mut offerings = HashSet::new();
        for o in &self.offerings {
            if !offerings.insert(o.id.as_str()) {
                return inv(format!("duplicate offering {}", o.id));
            }
            let r = o.resources;
            if r.vcpus == 0 || r.memory_mib == 0 || r.disk_gib == 0 {
                return inv(format!("offering {}: resources must be non-zero", o.id));
            }
            o.to_offering()?;
            if let Some(Err(e)) = o.egress.as_ref().map(|p| p.check_config()) {
                return inv(format!("offering {}: {e}", o.id));
            }
            if o.runtime == OfferingRuntime::Boat && self.boat.is_none() {
                return inv(format!(
                    "offering {}: runtime boat needs a `boat:` section",
                    o.id
                ));
            }
        }
        for o in &self.offerings {
            let from = o.to_offering()?;
            for (i, id) in o.spill_to.iter().enumerate() {
                if o.spill_to[..i].contains(id) {
                    return inv(format!("offering {}: spill_to lists {id} twice", o.id));
                }
                let Some(t) = self.offering(id.as_str()) else {
                    return inv(format!(
                        "offering {}: spill_to {id} is not an offering",
                        o.id
                    ));
                };
                if t.id == o.id {
                    return inv(format!("offering {}: spill_to names itself", o.id));
                }
                if let Some(why) = unlike(&from.spec, &t.to_offering()?.spec) {
                    return inv(format!("offering {}: cannot spill to {id}: {why}", o.id));
                }
            }
        }
        if let Some(b) = &self.boat
            && (b.capacity.vcpus == 0 || b.capacity.memory_mib == 0)
        {
            return inv("boat.capacity must be non-zero".into());
        }
        if let Some(w) = &self.wake {
            if w.command.is_empty() {
                return inv("wake.command is empty".into());
            }
            if !(1..=MAX_WAKE_TIMEOUT_SECS).contains(&w.timeout_secs) {
                return inv(format!(
                    "wake.timeout_secs must be between 1 and {MAX_WAKE_TIMEOUT_SECS}"
                ));
            }
            if !(1..=3600).contains(&w.hook_timeout_secs) {
                return inv("wake.hook_timeout_secs must be between 1 and 3600".into());
            }
            match (&w.sleep_command, w.sleep_after_idle_secs) {
                (Some(c), _) if c.is_empty() => {
                    return inv("wake.sleep_command is empty".into());
                }
                (Some(_), 0) => {
                    return inv("wake.sleep_command needs sleep_after_idle_secs".into());
                }
                (None, s) if s > 0 => {
                    return inv("wake.sleep_after_idle_secs needs sleep_command".into());
                }
                _ => {}
            }
        }
        let mut providers = HashSet::new();
        for p in &self.providers {
            if offerings.contains(p.id.as_str()) || !providers.insert(p.id.as_str()) {
                return inv(format!(
                    "provider {}: the id is already an offering or provider",
                    p.id
                ));
            }
            if p.orb_types.is_empty() {
                return inv(format!("provider {}: orb_types is empty", p.id));
            }
            for (i, t) in p.orb_types.iter().enumerate() {
                if p.orb_types[..i].contains(t) {
                    return inv(format!("provider {}: orb_types lists {t} twice", p.id));
                }
                if self.offering(t.as_str()).is_none() {
                    return inv(format!(
                        "provider {}: orb type {t} is not an offering",
                        p.id
                    ));
                }
            }
        }
        // Amp splits one token's jobs between all the providers polling with it.
        let mut tokens = HashSet::new();
        for t in self.providers.iter().map(|p| &p.token_file) {
            if !tokens.insert(t) {
                return inv(format!(
                    "provider token file {} is used twice; each provider needs its own token",
                    t.display()
                ));
            }
        }
        Ok(())
    }

    pub fn offering(&self, id: &str) -> Option<&OfferingConfig> {
        self.offerings.iter().find(|o| o.id.as_str() == id)
    }

    pub fn db_path(&self) -> PathBuf {
        self.state_dir.join("coordinator.sqlite")
    }

    /// Local socket for `orbd dispatch`.
    pub fn dispatch_socket(&self) -> PathBuf {
        self.state_dir.join("dispatch.sock")
    }

    /// Local socket for `orbd join-token` and `orbd agent list/remove`.
    pub fn admin_socket(&self) -> PathBuf {
        self.state_dir.join("admin.sock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offering(id: &str, runtime: OfferingRuntime, vcpus: u32, memory_mib: u64) -> Offering {
        OfferingConfig {
            id: OfferingId::new(id),
            runtime,
            resources: ResourcesConfig {
                vcpus,
                memory_mib,
                disk_gib: 20,
            },
            spill_to: vec![],
            arch: Arch::Amd64,
            egress: None,
        }
        .to_offering()
        .unwrap()
    }

    #[test]
    fn extra_urls_are_checked_and_follow_public_url() {
        let load = |extra: &str| {
            let yaml = format!(
                "config_version: v2\npublic_url: https://c.example:7443\n{extra}\
                 provider: {{ token_file: /t/p }}\n\
                 orb_types:\n  - {{ id: a, vcpus: 2, memory_mib: 2048, disk_gib: 10 }}\n"
            );
            let mut c = serde_saphyr::from_str::<CoordinatorConfig>(&yaml).unwrap();
            c.normalize().unwrap();
            c.validate().map(|()| c.agent_urls())
        };
        assert_eq!(load("").unwrap(), vec!["https://c.example:7443".to_owned()]);
        assert_eq!(
            load("extra_urls: [https://100.64.0.1:7443, https://c.example:7443]\n").unwrap(),
            vec![
                "https://c.example:7443".to_owned(),
                "https://100.64.0.1:7443".to_owned()
            ]
        );
        let err = load("extra_urls: [http://c.ts.net:7443]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("extra_urls"), "{err}");
    }

    #[test]
    fn provider_orb_types_must_be_offerings_with_their_own_token() {
        let check = |providers: &str| {
            let yaml = format!(
                "public_url: https://c.example:7443\n\
                 offerings:\n  - id: qemu-4vcpu-8gb\n    runtime: qemu\n    \
                 resources: {{ vcpus: 4, memory_mib: 8192, disk_gib: 40 }}\n\
                 providers:\n  - {{ id: other, token_file: /t/qemu, orb_types: [qemu-4vcpu-8gb] }}\n\
                 {providers}"
            );
            serde_saphyr::from_str::<CoordinatorConfig>(&yaml)
                .unwrap()
                .validate()
                .err()
                .map(|e| e.to_string())
        };
        let ok = "  - { id: homelab, token_file: /t/homelab, orb_types: [qemu-4vcpu-8gb] }\n";
        assert_eq!(check(ok), None);
        let unknown = "  - { id: homelab, token_file: /t/homelab, orb_types: [gpu] }\n";
        assert!(
            check(unknown)
                .unwrap()
                .contains("orb type gpu is not an offering")
        );
        let shared = "  - { id: homelab, token_file: /t/qemu, orb_types: [qemu-4vcpu-8gb] }\n";
        assert!(check(shared).unwrap().contains("/t/qemu is used twice"));
    }

    fn load_str(yaml: &str) -> Result<CoordinatorConfig, String> {
        let mut c: CoordinatorConfig = serde_saphyr::from_str(yaml).map_err(|e| e.to_string())?;
        c.normalize().map_err(|e| e.to_string())?;
        c.validate().map_err(|e| e.to_string())?;
        Ok(c)
    }

    const V2: &str = "config_version: v2\npublic_url: https://c.example:7443\n\
        boat: { api_key_file: /t/boat, capacity: { vcpus: 8, memory_mib: 16384 } }\n\
        provider: { token_file: /t/p, retired_token_files: [/t/old-a, /t/old-b] }\n";

    /// Each orb type is an offering named after it, placed where `prefer` says first and
    /// spilling to the rest; kvm runs only in QEMU, Boat only takes its own sizes.
    #[test]
    fn v2_orb_types_become_offerings_in_prefer_order() {
        let yaml = format!(
            "{V2}prefer: [boat, local]\norb_types:\n\
             \x20 - {{ id: small, vcpus: 2, memory_mib: 4096, disk_gib: 20 }}\n\
             \x20 - {{ id: odd, vcpus: 1, memory_mib: 2048, disk_gib: 20 }}\n\
             \x20 - {{ id: kvm, vcpus: 4, memory_mib: 8192, disk_gib: 30, kvm: true }}\n"
        );
        let c = load_str(&yaml).unwrap();
        let got: Vec<_> = c
            .offerings
            .iter()
            .map(|o| {
                (
                    o.id.as_str(),
                    o.runtime,
                    o.spill_to.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                )
            })
            .collect();
        use OfferingRuntime::*;
        assert_eq!(
            got,
            vec![
                ("small", Boat, vec!["small@firecracker"]),
                ("small@firecracker", Firecracker, vec![]),
                ("odd", Firecracker, vec![]),
                ("kvm", Qemu, vec![]),
            ]
        );
        assert_eq!(c.offering("kvm").unwrap().resources.disk_gib, 30);
        let providers: Vec<_> = c
            .providers
            .iter()
            .map(|p| (p.id.as_str(), p.token_file.to_str().unwrap()))
            .collect();
        assert_eq!(
            providers,
            vec![
                ("provider", "/t/p"),
                ("retired-1", "/t/old-a"),
                ("retired-2", "/t/old-b")
            ]
        );
        for p in &c.providers {
            let types: Vec<_> = p.orb_types.iter().map(|t| t.as_str()).collect();
            assert_eq!(types, ["small", "odd", "kvm"], "{}", p.id);
        }

        // Default prefer: the agents first, Boat as overflow.
        let yaml = format!(
            "{V2}orb_types:\n  - {{ id: small, vcpus: 2, memory_mib: 4096, disk_gib: 20 }}\n"
        );
        let c = load_str(&yaml).unwrap();
        assert_eq!(c.offerings[0].runtime, Firecracker);
        assert_eq!(c.offerings[0].spill_to, [OfferingId::new("small@boat")]);
    }

    /// `arch` lists the architectures a new orb may get, in order: arm64 in QEMU without
    /// kvm, amd64 as before, Boat (amd64 only) after the agents. amd64 specs serialize
    /// as before (no `arch` key), so recorded orbs keep their digests.
    #[test]
    fn v2_orb_type_archs() {
        let yaml = format!(
            "{V2}orb_types:\n\
             \x20 - {{ id: small, vcpus: 2, memory_mib: 4096, disk_gib: 20, arch: [amd64, arm64] }}\n\
             \x20 - {{ id: mac, vcpus: 2, memory_mib: 4096, disk_gib: 20, arch: arm64 }}\n"
        );
        let c = load_str(&yaml).unwrap();
        let got: Vec<_> = c
            .offerings
            .iter()
            .map(|o| {
                let spill: Vec<_> = o.spill_to.iter().map(|s| s.as_str()).collect();
                (o.id.as_str(), o.runtime, o.arch, spill)
            })
            .collect();
        use {Arch::*, OfferingRuntime::*};
        assert_eq!(
            got,
            vec![
                (
                    "small",
                    Firecracker,
                    Amd64,
                    vec!["small@arm64", "small@boat"]
                ),
                ("small@arm64", Qemu, Arm64, vec![]),
                ("small@boat", Boat, Amd64, vec![]),
                ("mac", Qemu, Arm64, vec![]),
            ]
        );
        let req = |id: &str| {
            c.offering(id)
                .unwrap()
                .to_offering()
                .unwrap()
                .spec
                .requirements
        };
        assert_eq!(req("mac").nested_kvm, NestedKvmRequirement::NotRequired);
        let json = serde_json::to_string(&req("small")).unwrap();
        assert!(!json.contains("arch"), "{json}");

        for bad in ["[]", "[arm64, arm64]", "x86", "arm64, kvm: true"] {
            let yaml = format!(
                "{V2}orb_types:\n  - {{ id: a, vcpus: 2, memory_mib: 4096, disk_gib: 20, arch: {bad} }}\n"
            );
            assert!(load_str(&yaml).is_err(), "{bad}");
        }
    }

    /// An orb type's `egress` is validated when the file is loaded and recorded in the
    /// specs of all its offerings; it keeps the orb type off Boat (and v1 offerings out
    /// of Docker and Boat), spill targets must have the same policy, and unrestricted
    /// orb types' specs are as before.
    #[test]
    fn v2_orb_type_egress() {
        let yaml = format!(
            "{V2}orb_types:\n\
             \x20 - id: untrusted\n    vcpus: 2\n    memory_mib: 4096\n    disk_gib: 20\n    \
             arch: [amd64, arm64]\n    egress:\n      domains: [ampcode.com, \"*.ampcode.com\"]\n      \
             allow: [\"tcp:203.0.113.0/24:443\"]\n\
             \x20 - {{ id: open, vcpus: 2, memory_mib: 4096, disk_gib: 20 }}\n"
        );
        let c = load_str(&yaml).unwrap();
        let got: Vec<_> = c
            .offerings
            .iter()
            .map(|o| {
                let spill: Vec<_> = o.spill_to.iter().map(|s| s.as_str()).collect();
                (o.id.as_str(), o.runtime, spill)
            })
            .collect();
        use OfferingRuntime::*;
        assert_eq!(
            got,
            vec![
                ("untrusted", Firecracker, vec!["untrusted@arm64"]),
                ("untrusted@arm64", Qemu, vec![]),
                ("open", Firecracker, vec!["open@boat"]),
                ("open@boat", Boat, vec![]),
            ]
        );
        let req = |id: &str| {
            c.offering(id)
                .unwrap()
                .to_offering()
                .unwrap()
                .spec
                .requirements
        };
        let policy = req("untrusted").egress.unwrap();
        assert_eq!(req("untrusted@arm64").egress.as_ref(), Some(&policy));
        let (domains, ports, allow) = policy.parts();
        assert_eq!(domains, ["ampcode.com", "*.ampcode.com"]);
        assert_eq!(ports, ["tcp:443"], "the default");
        assert_eq!(allow, ["tcp:203.0.113.0/24:443"]);
        assert_eq!(req("open").egress, None);
        let json = serde_json::to_string(&req("open")).unwrap();
        assert!(!json.contains("egress"), "{json}");

        let bad = |egress: &str, prefer: &str, want: &str| {
            let yaml = format!(
                "{V2}{prefer}orb_types:\n  - {{ id: a, vcpus: 2, memory_mib: 4096, disk_gib: 20, \
                 egress: {egress} }}\n"
            );
            let e = load_str(&yaml).expect_err(egress);
            assert!(e.contains(want), "{egress}: {e}");
        };
        bad("{ domains: [\"*\"] }", "", "egress.domains");
        bad("{ domains: [\"*.com\"] }", "", "wildcard");
        bad("{ domains: [\"*.co.uk\"] }", "", "anyone can have names");
        bad(
            "{ domains: [\"*.ts.net\"] }",
            "",
            "orb type a: egress.domains",
        );
        bad("{ domains: [a.com, A.com] }", "", "twice");
        bad("{ domains: [a.com], ports: [] }", "", "ports is empty");
        bad(
            "{ domains: [a.com], ports: [\"icmp:1\"] }",
            "",
            "egress.ports",
        );
        bad("{ allow: [\"tcp:169.254.169.254\"] }", "", "link-local");
        bad("{ domain: [a.com] }", "", "unknown field");
        bad(
            "{ domains: [a.com] }",
            "prefer: [boat]\n",
            "nowhere in prefer",
        );
        // `egress: {}` reaches nothing but the proxy, which answers nothing.
        let yaml = format!(
            "{V2}orb_types:\n  - {{ id: a, vcpus: 2, memory_mib: 4096, disk_gib: 20, egress: {{}} }}\n"
        );
        let c = load_str(&yaml).unwrap();
        let p = c.offerings[0].egress.as_ref().unwrap();
        assert!(p.domains.is_empty() && p.allow.is_empty());

        // v1: VM runtimes only, and spill targets with the same policy.
        let v1 = |runtime: &str, egress: &str, spill: &str| {
            load_str(&format!(
                "public_url: https://c.example:7443\n\
                 boat: {{ api_key_file: /t/boat, capacity: {{ vcpus: 8, memory_mib: 16384 }} }}\n\
                 offerings:\n\
                 \x20 - {{ id: a, runtime: {runtime}, resources: {{ vcpus: 2, memory_mib: 4096, disk_gib: 20 }}, \
                 egress: {{ domains: [a.com] }}, spill_to: [{spill}] }}\n\
                 \x20 - {{ id: b, runtime: firecracker, resources: {{ vcpus: 2, memory_mib: 4096, disk_gib: 20 }}{egress} }}\n"
            ))
        };
        assert!(v1("firecracker", ", egress: { domains: [a.com] }", "b").is_ok());
        assert!(v1("qemu", "", "").is_ok());
        assert!(v1("fake", "", "").is_ok());
        for runtime in ["docker", "boat"] {
            let e = v1(runtime, "", "").unwrap_err();
            assert!(e.contains("egress is enforced only"), "{runtime}: {e}");
        }
        let e = v1("firecracker", "", "b").unwrap_err();
        assert!(e.contains("egress policies differ"), "{e}");
        let e = v1("firecracker", ", egress: { domains: [b.com] }", "b").unwrap_err();
        assert!(e.contains("egress policies differ"), "{e}");
    }

    #[test]
    fn v2_refuses_what_it_cannot_place_and_v1_fields() {
        let only_boat = format!(
            "{V2}prefer: [boat]\norb_types:\n  - {{ id: kvm, vcpus: 4, memory_mib: 8192, disk_gib: 20, kvm: true }}\n"
        );
        assert!(
            load_str(&only_boat)
                .unwrap_err()
                .contains("orb type kvm: nowhere")
        );
        let mixed = format!(
            "{V2}orb_types:\n  - {{ id: a, vcpus: 2, memory_mib: 4096, disk_gib: 20 }}\n\
             offerings:\n  - {{ id: b, runtime: qemu, resources: {{ vcpus: 2, memory_mib: 4096, disk_gib: 20 }} }}\n"
        );
        assert!(
            load_str(&mixed)
                .unwrap_err()
                .contains("instead of offerings")
        );
        let v1 = "public_url: https://c.example:7443\nprovider: { token_file: /t/p }\n\
                  offerings:\n  - { id: b, runtime: qemu, resources: { vcpus: 2, memory_mib: 4096, disk_gib: 20 } }\n";
        assert!(
            load_str(v1)
                .unwrap_err()
                .contains("need config_version: v2")
        );
        // A retired token must not be the provider's own.
        let shared = "config_version: v2\npublic_url: https://c.example:7443\n\
                      provider: { token_file: /t/p, retired_token_files: [/t/p] }\n\
                      orb_types:\n  - { id: a, vcpus: 2, memory_mib: 4096, disk_gib: 20 }\n";
        assert!(load_str(shared).unwrap_err().contains("/t/p is used twice"));
    }

    #[test]
    fn wake_needs_a_command_and_sleep_settings_together() {
        let check = |wake: &str| {
            load_str(&format!(
                "public_url: https://c.example:7443\n\
                 offerings:\n  - id: fake-2vcpu-2gb\n    runtime: fake\n    \
                 resources: {{ vcpus: 2, memory_mib: 2048, disk_gib: 4 }}\n\
                 wake:\n{wake}"
            ))
            .err()
        };
        assert_eq!(check("  command: [start-host]\n"), None);
        assert_eq!(
            check(
                "  command: [start-host]\n  sleep_command: [stop-host]\n  \
                 sleep_after_idle_secs: 7200\n"
            ),
            None
        );
        let err = |wake: &str, want: &str| {
            let e = check(wake).expect("refused");
            assert!(e.contains(want), "{e}");
        };
        err("  command: []\n", "wake.command is empty");
        err(
            "  command: [start-host]\n  hook_timeout_secs: 0\n",
            "hook_timeout_secs must be between 1 and 3600",
        );
        err(
            "  command: [start-host]\n  timeout_secs: 0\n",
            "between 1 and 200",
        );
        err(
            "  command: [start-host]\n  timeout_secs: 300\n",
            "between 1 and 200",
        );
        err(
            "  command: [start-host]\n  sleep_command: [stop-host]\n",
            "needs sleep_after_idle_secs",
        );
        err(
            "  command: [start-host]\n  sleep_after_idle_secs: 60\n",
            "needs sleep_command",
        );
        err(
            "  command: [start-host]\n  sleep_command: []\n  sleep_after_idle_secs: 60\n",
            "wake.sleep_command is empty",
        );
    }

    #[test]
    fn spill_targets_must_be_like_for_like() {
        use OfferingRuntime::*;
        let fc = offering("fc", Firecracker, 1, 2048);
        let qemu = offering("qemu", Qemu, 2, 4096);
        let boat = offering("boat", Boat, 2, 4096);
        // No /dev/kvm on either side, and Boat is at least as big.
        assert_eq!(unlike(&fc.spec, &boat.spec), None);
        // QEMU orbs have /dev/kvm; Boat sandboxes do not.
        let why = unlike(&qemu.spec, &boat.spec).unwrap();
        assert!(why.contains("/dev/kvm"), "{why}");
        // Smaller is never a spill target.
        let big_fc = offering("fc-big", Firecracker, 4, 8192);
        assert!(
            unlike(&big_fc.spec, &boat.spec)
                .unwrap()
                .contains("smaller")
        );
    }
}
