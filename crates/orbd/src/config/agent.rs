//! Agent configuration. Agents need no file: identity comes from the join token,
//! runtime and capacity are detected, and [`AgentSection`] is filled from flags/env.
//! The optional YAML file (`orbd agent --config agent.yaml`) holds advanced runtime and
//! image settings.

use super::{ConfigError, load_yaml};
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// From flags/env, never from the file.
    #[serde(skip)]
    pub agent: AgentSection,
    #[serde(default)]
    pub runtime: RuntimesConfig,
    /// Image preparation for VM runtimes (OCI image → ext4 root disk). Defaults to the
    /// tools baked into orbd's container image.
    #[serde(default = "default_images")]
    pub images: Option<ImagesConfig>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent: AgentSection::default(),
            runtime: RuntimesConfig::default(),
            images: default_images(),
        }
    }
}

fn default_images() -> Option<ImagesConfig> {
    Some(ImagesConfig {
        guest_helper: default_guest_helper(),
        umoci: default_umoci(),
        mkfs_ext4: default_mkfs_ext4(),
        builder: default_builder(),
        prewarm: default_prewarm(),
        refresh_interval_secs: default_refresh_secs(),
        static_images: Vec::new(),
    })
}

fn default_prewarm() -> Vec<String> {
    vec![AMP_ORB_IMAGE.into()]
}

/// Amp's orb image; agents prepare it at startup unless configured otherwise.
pub const AMP_ORB_IMAGE: &str = "us-central1-docker.pkg.dev/amp-prod-0/amp-orb/amp-orb:latest";

/// Where orbd's container image installs the guest kernel and `orbd-guest` (on macOS,
/// where `/usr/share` is read-only: `/usr/local/share/orbd`, kernel `Image`).
pub const DEFAULT_GUEST_KERNEL: &str = if cfg!(target_os = "macos") {
    "/usr/local/share/orbd/Image"
} else {
    "/usr/share/orbd/bzImage"
};
pub const DEFAULT_GUEST_HELPER: &str = if cfg!(target_os = "macos") {
    "/usr/local/share/orbd/orbd-guest"
} else {
    "/usr/share/orbd/orbd-guest"
};

/// The image builder macOS agents use by default (see [`ImagesConfig::builder`]); built
/// from `guest/builder/Dockerfile`.
pub const DEFAULT_IMAGE_BUILDER: &str = "orbd-image-builder:umoci-0.6.0";

/// `[images]`: turns Amp's OCI image into a bootable root disk with orbd's guest
/// integration. Prepared images live under `<state_dir>/images/`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagesConfig {
    /// Static `orbd-guest` binary (musl, the host's architecture) installed into every
    /// prepared image.
    #[serde(default = "default_guest_helper")]
    pub guest_helper: PathBuf,
    /// `umoci` binary; must be the pinned version (see `orbd doctor`).
    #[serde(default = "default_umoci")]
    pub umoci: PathBuf,
    #[serde(default = "default_mkfs_ext4")]
    pub mkfs_ext4: PathBuf,
    /// Docker image that runs umoci and mkfs.ext4 for each build instead of the host
    /// (`docker run`, no network, only the build's work directory shared); `umoci` and
    /// `mkfs_ext4` are then unused. Default on macOS: [`DEFAULT_IMAGE_BUILDER`] (built
    /// from `guest/builder/Dockerfile`, never pulled); elsewhere none.
    #[serde(default = "default_builder")]
    pub builder: Option<String>,
    /// Images prepared in the background at startup, so the first spawn does not fail
    /// with ImageNotReady while a multi-GB image is pulled and converted. Defaults to
    /// Amp's orb image.
    #[serde(default = "default_prewarm")]
    pub prewarm: Vec<String>,
    /// How often a tag (e.g. `:latest`) is resolved again; the previously prepared
    /// image keeps serving until the new digest is ready.
    #[serde(default = "default_refresh_secs")]
    pub refresh_interval_secs: u64,
    /// Prebuilt raw ext4 root disks by image reference, used instead of preparing
    /// images (development and KVM tests).
    #[serde(default)]
    pub static_images: Vec<StaticImage>,
}

fn default_guest_helper() -> PathBuf {
    DEFAULT_GUEST_HELPER.into()
}

fn default_umoci() -> PathBuf {
    "umoci".into()
}

fn default_mkfs_ext4() -> PathBuf {
    "mkfs.ext4".into()
}

fn default_builder() -> Option<String> {
    cfg!(target_os = "macos").then(|| DEFAULT_IMAGE_BUILDER.into())
}

fn default_refresh_secs() -> u64 {
    3600
}

#[derive(Debug, Default)]
pub struct AgentSection {
    /// Holds `agent.sqlite`, the agent's identity, images, orb disks, checkpoints.
    pub state_dir: PathBuf,
    /// Sockets, locks, process metadata (`<state_dir>/run`).
    pub run_dir: PathBuf,
    /// Seals accepted guest env for crash recovery; generated on first start.
    pub secret_key_file: PathBuf,
    /// Overrides for the detected capacity ceiling.
    pub capacity: CapacityOverrides,
    /// DNS servers written into orbs. Never the host's resolvers: a local stub such as
    /// Tailscale's 100.100.100.100 is unreachable from orbs.
    pub dns_servers: Vec<String>,
    /// The network VM orbs see.
    pub guest_network: GuestNetwork,
    /// Which private destinations VM orbs may reach (none by default).
    pub egress: Egress,
    pub metrics_listen: Option<SocketAddr>,
    /// Overrides the coordinator URL from enrollment (`ORBD_COORDINATOR_URL`).
    pub coordinator_url: Option<String>,
    /// New orbs come here only when no other agent fits them (`ORBD_OVERFLOW`).
    pub overflow: bool,
}

pub const DEFAULT_DNS: [&str; 2] = ["1.1.1.1", "9.9.9.9"];

/// The private IPv4 network a VM orb sees (every VM has its own): the guest is host `.15`
/// and its gateway host `.2`, as with QEMU's user networking. Fixed per orb when it is
/// created, so changing it affects only new orbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestNetwork {
    network: Ipv4Addr,
    prefix: u8,
}

impl GuestNetwork {
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn gateway(&self) -> Ipv4Addr {
        self.host(2)
    }

    pub fn guest(&self) -> Ipv4Addr {
        self.host(15)
    }

    fn host(&self, n: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) + n)
    }

    fn mask(prefix: u8) -> u32 {
        u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
    }

    fn overlaps(&self, other: Ipv4Addr, other_prefix: u8) -> bool {
        let mask = Self::mask(self.prefix.min(other_prefix));
        u32::from(self.network) & mask == u32::from(other) & mask
    }
}

impl Default for GuestNetwork {
    fn default() -> Self {
        Self {
            network: Ipv4Addr::new(10, 0, 2, 0),
            prefix: 24,
        }
    }
}

impl std::fmt::Display for GuestNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl std::str::FromStr for GuestNetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| format!("{s}: expected a network such as 10.0.2.0/24"))?;
        let network: Ipv4Addr = addr.parse().map_err(|e| format!("{s}: {e}"))?;
        let prefix: u8 = prefix.parse().map_err(|e| format!("{s}: {e}"))?;
        // `.15` must be a host address, not the broadcast address.
        if prefix > 27 {
            return Err(format!("{s}: the prefix must be /27 or shorter"));
        }
        if u32::from(network) & !Self::mask(prefix) != 0 {
            return Err(format!("{s}: host bits are set"));
        }
        let net = Self { network, prefix };
        // Link-local carries orbd's own transit addresses (and cloud metadata).
        for (reserved, len) in [
            (Ipv4Addr::new(0, 0, 0, 0), 8),
            (Ipv4Addr::new(127, 0, 0, 0), 8),
            (Ipv4Addr::new(169, 254, 0, 0), 16),
            (Ipv4Addr::new(224, 0, 0, 0), 3),
        ] {
            if net.overlaps(reserved, len) {
                return Err(format!("{s}: overlaps reserved {reserved}/{len}"));
            }
        }
        Ok(net)
    }
}

/// Which private destinations VM orbs may reach. By default orbs get the internet only:
/// [`PRIVATE_NETS`] (the host's LAN, a tailnet's CGNAT range, loopback, multicast and
/// reserved space) is dropped for their traffic, except what `allow` names and the
/// orbs' DNS servers (port 53). Link-local (cloud metadata) and IPv6 stay blocked, and
/// the agent's own traffic is never affected.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Egress {
    /// Orbs may reach every private destination (`ORBD_ALLOW_PRIVATE_EGRESS`).
    pub allow_private: bool,
    /// Private destinations orbs may reach anyway (`ORBD_EGRESS_ALLOW`).
    pub allow: Vec<EgressRule>,
}

/// IPv4 destinations VM orbs do not reach unless [`Egress`] allows them (link-local is
/// blocked separately, always).
pub const PRIVATE_NETS: [&str; 10] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressProto {
    Tcp,
    Udp,
    /// Every protocol; with ports, TCP or UDP to them.
    Any,
}

/// One allowed destination: `<proto>:<address>[:<ports>]`, e.g. `udp:192.168.2.201:41641`
/// (Tailscale to a LAN host), `tcp:10.0.0.0/8:8000-8100`, `any:192.168.2.0/24` (every
/// protocol and port), `tcp:*:443` (`*`: any address). `proto` is tcp, udp or any;
/// ports are one port or a range; without them, every port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressRule {
    pub proto: EgressProto,
    pub net: Ipv4Addr,
    pub prefix: u8,
    /// Inclusive range; `None` for every port.
    pub ports: Option<(u16, u16)>,
}

impl std::fmt::Display for EgressRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto = match self.proto {
            EgressProto::Tcp => "tcp",
            EgressProto::Udp => "udp",
            EgressProto::Any => "any",
        };
        write!(f, "{proto}:")?;
        match self.prefix {
            0 => write!(f, "*")?,
            32 => write!(f, "{}", self.net)?,
            p => write!(f, "{}/{p}", self.net)?,
        }
        match self.ports {
            None => Ok(()),
            Some((a, b)) if a == b => write!(f, ":{a}"),
            Some((a, b)) => write!(f, ":{a}-{b}"),
        }
    }
}

impl std::str::FromStr for EgressRule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = |why: &str| {
            format!(
                "{s:?}: {why} (expected <tcp|udp|any>:<address or CIDR or *>[:<port or range>], \
                 e.g. udp:192.168.2.201:41641)"
            )
        };
        let mut parts = s.trim().split(':');
        let (Some(proto), Some(addr), ports, None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad("wrong number of parts"));
        };
        let proto = match proto.to_ascii_lowercase().as_str() {
            "tcp" => EgressProto::Tcp,
            "udp" => EgressProto::Udp,
            "any" | "*" => EgressProto::Any,
            _ => return Err(bad("protocol must be tcp, udp or any")),
        };
        let (net, prefix) = match addr {
            "*" => (Ipv4Addr::UNSPECIFIED, 0),
            a => {
                let (ip, prefix) = match a.split_once('/') {
                    Some((ip, p)) => (ip, p.parse::<u8>().map_err(|_| bad("bad prefix"))?),
                    None => (a, 32),
                };
                let ip: Ipv4Addr = ip.parse().map_err(|_| bad("bad IPv4 address"))?;
                if prefix > 32 {
                    return Err(bad("prefix above /32"));
                }
                let mask = GuestNetwork::mask(prefix);
                if u32::from(ip) & !mask != 0 {
                    return Err(bad("host bits are set"));
                }
                (ip, prefix)
            }
        };
        let ports = match ports {
            None | Some("") | Some("*") => None,
            Some(p) => {
                let (a, b) = p.split_once('-').unwrap_or((p, p));
                let a: u16 = a.parse().map_err(|_| bad("bad port"))?;
                let b: u16 = b.parse().map_err(|_| bad("bad port"))?;
                if a == 0 || a > b {
                    return Err(bad("ports must be 1-65535, low to high"));
                }
                Some((a, b))
            }
        };
        Ok(Self {
            proto,
            net,
            prefix,
            ports,
        })
    }
}

impl AgentSection {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            run_dir: state_dir.join("run"),
            secret_key_file: state_dir.join("secret.key"),
            state_dir,
            capacity: CapacityOverrides::default(),
            dns_servers: DEFAULT_DNS.map(String::from).to_vec(),
            guest_network: GuestNetwork::default(),
            egress: Egress::default(),
            metrics_listen: None,
            coordinator_url: None,
            overflow: false,
        }
    }
}

/// Per-field overrides of the detected capacity.
#[derive(Clone, Copy, Debug, Default)]
pub struct CapacityOverrides {
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u64>,
    /// Limit on what orbd allocates under the state directory (default: the
    /// filesystem's size).
    pub disk_gib: Option<u64>,
    /// Free space to keep on the state directory's filesystem (default: max(10 GiB,
    /// 5% of it)).
    pub disk_reserve_gib: Option<u64>,
    /// Memory to keep available on the host (default: max(4 GiB, 10% of it)).
    pub memory_reserve_gib: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimesConfig {
    pub fake: Option<FakeRuntimeConfig>,
    pub docker: Option<DockerRuntimeConfig>,
    pub qemu: Option<QemuRuntimeConfig>,
    pub firecracker: Option<FirecrackerRuntimeConfig>,
}

/// QEMU VMs with memory-preserving sleep (q35 with nested KVM on Linux, `virt` under
/// Hypervisor.framework on Apple Silicon). Every field has a default matching orbd's
/// container image (or a macOS install), so a zero-config agent needs none of them.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QemuRuntimeConfig {
    /// `qemu-system-x86_64` (`qemu-system-aarch64` on arm64); a bare name is looked up
    /// on PATH.
    #[serde(default = "default_qemu")]
    pub qemu: PathBuf,
    #[serde(default = "default_qemu_img")]
    pub qemu_img: PathBuf,
    /// Guest kernel (bzImage, or arm64 `Image`; everything built in). Its digest is pinned
    /// in each checkpoint: a replaced kernel makes sleeping orbs cold-boot on their next
    /// spawn.
    #[serde(default = "default_kernel")]
    pub kernel: PathBuf,
    /// Delegated cgroup v2 directory; each QEMU runs in `<cgroup_parent>/orbd-<orb>`,
    /// outside the agent's cgroup, so stopping the agent service leaves VMs running.
    pub cgroup_parent: Option<PathBuf>,
    /// A group QEMU runs with, through `orbd-netgroup` (on PATH, setgid to it): host
    /// firewall rules for that group (macOS pf `group`) then confine orb traffic without
    /// touching the agent's own. The runtime refuses to start while it is not setgid.
    pub network_group: Option<String>,
    /// DNS servers delivered to guests (from `agent.dns_servers`).
    #[serde(skip)]
    pub dns_servers: Vec<String>,
    /// Network for new orbs (from `agent.guest_network`).
    #[serde(skip)]
    pub guest_network: GuestNetwork,
}

impl Default for QemuRuntimeConfig {
    fn default() -> Self {
        Self {
            qemu: default_qemu(),
            qemu_img: default_qemu_img(),
            kernel: default_kernel(),
            cgroup_parent: None,
            network_group: None,
            dns_servers: Vec::new(),
            guest_network: GuestNetwork::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticImage {
    pub image_ref: String,
    pub rootfs: PathBuf,
}

/// Firecracker microVMs: fast wake from lazily loaded memory, no `/dev/kvm` inside.
/// Every field has a default matching orbd's container image.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerRuntimeConfig {
    /// `firecracker`; a bare name is looked up on PATH.
    #[serde(default = "default_firecracker")]
    pub firecracker: PathBuf,
    /// Guest kernel, the same one QEMU boots. Only cold boots read it.
    #[serde(default = "default_kernel")]
    pub kernel: PathBuf,
    /// As for QEMU: each VMM runs in `<cgroup_parent>/orbd-<orb>`.
    pub cgroup_parent: Option<PathBuf>,
    /// DNS servers delivered to guests (from `agent.dns_servers`).
    #[serde(skip)]
    pub dns_servers: Vec<String>,
    /// Network for new orbs (from `agent.guest_network`).
    #[serde(skip)]
    pub guest_network: GuestNetwork,
    /// Private destinations orbs may reach (from `agent.egress`).
    #[serde(skip)]
    pub egress: Egress,
}

impl Default for FirecrackerRuntimeConfig {
    fn default() -> Self {
        Self {
            firecracker: default_firecracker(),
            kernel: default_kernel(),
            cgroup_parent: None,
            dns_servers: Vec::new(),
            guest_network: GuestNetwork::default(),
            egress: Egress::default(),
        }
    }
}

fn default_firecracker() -> PathBuf {
    "firecracker".into()
}

fn default_qemu() -> PathBuf {
    orbd_qemu::probe::QEMU_SYSTEM.into()
}
fn default_qemu_img() -> PathBuf {
    "qemu-img".into()
}
fn default_kernel() -> PathBuf {
    DEFAULT_GUEST_KERNEL.into()
}

/// Test runtime with durable fake state. Never enable in production.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeRuntimeConfig {
    /// Advertise memory-preserving sleep (to exercise that path).
    #[serde(default)]
    pub memory_preserving_sleep: bool,
    /// Report this filesystem instead of the state directory's real one, so tests do
    /// not depend on the host's free space.
    pub disk: Option<FakeDisk>,
    /// The architecture it reports (default amd64, whatever the host's), to test
    /// placement by architecture.
    #[serde(default)]
    pub arch: crate::model::Arch,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeDisk {
    pub free_gib: u64,
    pub total_gib: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerRuntimeConfig {
    /// Docker API endpoint; defaults to the local socket.
    pub docker_host: Option<String>,
    /// DNS servers written into orbs (from `agent.dns_servers`).
    #[serde(skip)]
    pub dns_servers: Vec<String>,
    /// Docker network for orb containers; defaults to Docker's bridge.
    pub network: Option<String>,
    /// Images pulled in the background at startup when missing, so the first spawn
    /// does not fail with ImageNotReady while a multi-GB pull runs. Defaults to Amp's
    /// orb image.
    #[serde(default = "default_prewarm")]
    pub prewarm_images: Vec<String>,
}

impl Default for DockerRuntimeConfig {
    fn default() -> Self {
        Self {
            docker_host: None,
            dns_servers: Vec::new(),
            network: None,
            prewarm_images: default_prewarm(),
        }
    }
}

impl AgentConfig {
    /// Reads the optional advanced-settings file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        load_yaml(path)
    }

    pub fn db_path(&self) -> PathBuf {
        self.agent.state_dir.join("agent.sqlite")
    }
}

#[cfg(test)]
mod tests {
    use super::{EgressProto, EgressRule, GuestNetwork};

    #[test]
    fn egress_rules_parse_and_print() {
        for (input, printed, proto, prefix, ports) in [
            (
                "udp:192.168.2.201:41641",
                "udp:192.168.2.201:41641",
                EgressProto::Udp,
                32,
                Some((41641, 41641)),
            ),
            (
                "tcp:10.0.0.0/8:8000-8100",
                "tcp:10.0.0.0/8:8000-8100",
                EgressProto::Tcp,
                8,
                Some((8000, 8100)),
            ),
            (
                "any:192.168.2.0/24",
                "any:192.168.2.0/24",
                EgressProto::Any,
                24,
                None,
            ),
            (
                "TCP:*:443",
                "tcp:*:443",
                EgressProto::Tcp,
                0,
                Some((443, 443)),
            ),
            (
                "*:100.64.0.0/10:*",
                "any:100.64.0.0/10",
                EgressProto::Any,
                10,
                None,
            ),
        ] {
            let r: EgressRule = input.parse().unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(
                (r.proto, r.prefix, r.ports),
                (proto, prefix, ports),
                "{input}"
            );
            assert_eq!(r.to_string(), printed);
            assert_eq!(printed.parse::<EgressRule>().unwrap(), r, "round trip");
        }
        for bad in [
            "",
            "192.168.2.201:41641",   // no protocol
            "icmp:192.168.2.201",    // unknown protocol
            "udp:192.168.2.201:1:2", // too many parts
            "udp:192.168.2.1/24:53", // host bits
            "udp:192.168.2.0/33",    // prefix
            "udp:host.lan:53",       // names: addresses only
            "udp:fd00::1:53",        // IPv4 only
            "tcp:10.0.0.1:0",        // port 0
            "tcp:10.0.0.1:90-80",    // range backwards
            "tcp:10.0.0.1:70000",    // out of range
        ] {
            assert!(bad.parse::<EgressRule>().is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn guest_network_parsing() {
        let n: GuestNetwork = "172.31.0.0/16".parse().unwrap();
        assert_eq!(n.to_string(), "172.31.0.0/16");
        assert_eq!(n.gateway().to_string(), "172.31.0.2");
        assert_eq!(n.guest().to_string(), "172.31.0.15");
        assert_eq!(GuestNetwork::default().to_string(), "10.0.2.0/24");
        for bad in [
            "10.0.2.0",       // no prefix
            "10.0.2.1/24",    // host bits
            "10.0.2.0/28",    // .15 would be broadcast
            "169.254.8.0/24", // orbd's transit network
            "160.0.0.0/4",    // contains link-local
            "127.1.0.0/16",   // loopback
            "10.0.2.0/33",
        ] {
            assert!(bad.parse::<GuestNetwork>().is_err(), "{bad}");
        }
        assert!("10.0.2.0/27".parse::<GuestNetwork>().is_ok());
    }
}
