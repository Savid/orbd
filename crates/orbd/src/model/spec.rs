//! Offerings and the immutable spec recorded for each orb.

use super::artifact::ProjectSnapshotRef;
use super::identity::{AmpEndpointId, BackendId, BackendProfileId, OfferingId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    /// Test runtime with durable fake state and failpoints.
    Fake,
    /// Systemd container; routing tests only (pause loses processes).
    Docker,
    /// QEMU q35 VM with nested KVM and memory-preserving sleep.
    Qemu,
    /// Firecracker microVM; fast wake, no nested KVM.
    Firecracker,
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fake => "fake",
            Self::Docker => "docker",
            Self::Qemu => "qemu",
            Self::Firecracker => "firecracker",
        }
    }
}

/// Exact integer resource quantities.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Resources {
    pub vcpus: u32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
}

impl Resources {
    pub fn checked_add(self, o: Self) -> Option<Self> {
        Some(Self {
            vcpus: self.vcpus.checked_add(o.vcpus)?,
            memory_bytes: self.memory_bytes.checked_add(o.memory_bytes)?,
            disk_bytes: self.disk_bytes.checked_add(o.disk_bytes)?,
        })
    }

    pub fn saturating_sub(self, o: Self) -> Self {
        Self {
            vcpus: self.vcpus.saturating_sub(o.vcpus),
            memory_bytes: self.memory_bytes.saturating_sub(o.memory_bytes),
            disk_bytes: self.disk_bytes.saturating_sub(o.disk_bytes),
        }
    }
}

/// Where an offering executes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ExecutionTarget {
    /// Agent fleet backend: an agent's local runtime.
    Fleet { runtime: RuntimeKind },
    /// API backend (E2B, exe.dev, ...): a backend-specific profile. Not implemented yet.
    Provider { profile: BackendProfileId },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedKvmRequirement {
    #[default]
    NotRequired,
    /// `/dev/kvm` inside the orb.
    GuestDevice,
    /// `/dev/kvm` inside the orb and nested guests survive sleep.
    GuestDeviceAndPreservedNestedState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SnapshotRequirement {
    NotRequired,
    Required {
        scope: super::capability::SnapshotScope,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityRequirements {
    /// Paused orbs must not hold compute (host RAM / billed compute).
    pub release_compute_when_paused: bool,
    pub nested_kvm: NestedKvmRequirement,
    pub project_snapshots: SnapshotRequirement,
    /// CPU architecture of the orb (its image and host). Left out of amd64 specs, so
    /// specs recorded before it existed serialize (and digest) unchanged.
    #[serde(default, skip_serializing_if = "Arch::is_amd64")]
    pub arch: Arch,
    /// Restricted egress (the orb type's `egress`): the orb reaches only what the policy
    /// lists, on an agent that enforces it. Recorded when the orb is created, so it is
    /// restricted for life; the policy an agent applies at each launch is the orb type's
    /// current one ([`super::OrbDefinition::egress`]). Left out when unrestricted, so
    /// such specs serialize (and digest) as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<super::EgressPolicy>,
}

/// CPU architecture of an orb and of the hosts that can run it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    #[default]
    Amd64,
    Arm64,
}

impl Arch {
    /// This build's architecture.
    pub const HOST: Arch = if cfg!(target_arch = "aarch64") {
        Arch::Arm64
    } else {
        Arch::Amd64
    };

    pub const fn as_str(self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
        }
    }

    pub fn is_amd64(&self) -> bool {
        *self == Arch::Amd64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointFailurePolicy {
    /// Leave the orb running and fail the pause.
    KeepRunning,
    /// Cold-stop the orb and fail the pause with an explicit process-loss result.
    ColdStop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum PausePolicy {
    /// Pause stops the orb; processes are lost (reported, not an error).
    DiskOnly,
    /// Pause saves memory; processes resume on wake.
    MemoryPreserving { on_failure: CheckpointFailurePolicy },
}

/// The per-offering template, copied into each orb's [`OrbSpec`] when first placed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpecTemplate {
    pub target: ExecutionTarget,
    pub resources: Resources,
    pub requirements: CapabilityRequirements,
    pub pause_policy: PausePolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offering {
    pub id: OfferingId,
    pub amp_endpoint: AmpEndpointId,
    pub backend_id: BackendId,
    pub spec: SpecTemplate,
    /// Offerings that take a new orb, in order, when this offering's hosts cannot.
    /// An orb lives where it was placed: a spilled orb resumes on the spill target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spill_to: Vec<OfferingId>,
}

/// How a new orb's disk is created. Resolved once, before first execution.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum InitialDiskSource {
    /// Image reference as given by Amp; the location must have it prepared.
    Image { image_ref: String },
    /// A project snapshot the location holds. `image_ref` is the spawn's image, used
    /// instead when the snapshot turns out to be missing on the host.
    ProjectSnapshot {
        snapshot: ProjectSnapshotRef,
        image_ref: String,
    },
}

/// Immutable spec recorded for an orb. Later spawns never change it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrbSpec {
    pub template: SpecTemplate,
    pub initial_disk: InitialDiskSource,
}

/// Hex sha256 of a canonical serialization.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpecDigest(pub String);

impl OrbSpec {
    /// Digest over the canonical JSON form (struct field order is fixed by the type).
    pub fn digest(&self) -> SpecDigest {
        let json = serde_json::to_vec(self).expect("OrbSpec serializes");
        SpecDigest(hex::encode(Sha256::digest(json)))
    }
}

pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;
