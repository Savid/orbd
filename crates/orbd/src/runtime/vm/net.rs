//! Agent-local network attachment for one VM, chosen when the orb's disk is created and
//! persisted in its recipe; a sleeping VM is always restored with the attachment (and
//! MAC) it was saved with. Guests see the agent's guest network as it was when the orb
//! was created (default `10.0.2.15/24` via `10.0.2.2`), applied by the guest helper from
//! `Wake.network`.
//!
//! * `User`: QEMU's built-in slirp. No host privileges, guest-initiated traffic only,
//!   not filtered by orbd: macOS QEMU orbs (fenced by pf). Linux agents refuse the QEMU
//!   orbs orbd 0.2.8 and earlier created with it.
//! * `Tap`: every Linux VM orb. A per-orb network namespace `orbd-<orb>` holding the VM's `tap0`
//!   (the guest's gateway, e.g. `10.0.2.2/24`) and one end of a veth pair; the other
//!   end, `orbd<i>`, sits in the agent's namespace with a `/30` from `169.254.0.0/16`
//!   (`i` is a durable per-host index). The namespace masquerades the guest behind its
//!   veth address and the agent's namespace masquerades that onwards, so guests share
//!   addresses and only leave through NAT. nftables table `inet orbd` drops orb → agent
//!   traffic (except replies), orb ↔ orb forwarding, IPv6, packets conntrack cannot
//!   track or that did not come through an orb's namespace (they would leave un-NATed,
//!   e.g. with a spoofed source), cloud metadata, and orb → private destinations (the
//!   LAN, a tailnet, ...) that the agent's [`Egress`] does not allow. The VMM runs inside
//!   the namespace and sees nothing but its TAP, which is persistent and, for a jailed
//!   VMM, owned by the orb's uid (the only way an unprivileged process attaches to it).
//!
//! `Tap` is built with `ip` and `nft` run with fixed arguments; every step is
//! idempotent, so `adopt` repairs what is missing (after a host reboot) without touching
//! what a running VMM uses.
//!
//! With the egress flow log on ([`Egress::flow_log`]), the table also logs the first
//! packets of every new orb flow with the egress policy's verdict to NFLOG (see
//! [`super::flowlog`]): a chain mirroring the decision rules, entered once per new flow
//! under a rate limit, logs instead of deciding, so the decision itself is unchanged.
//! Without it the table has no log rules (it is replaced whole when a runtime starts).

use super::jail::Ids;
use crate::config::agent::{Egress, EgressProto, GuestNetwork};
use orbd_proto::guest::v1 as gpb;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use crate::model::OrbId;

/// Typed backend; serialized into the VM recipe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NetBackend {
    /// QEMU built-in slirp: no host privileges, guest-initiated traffic only.
    User,
    /// TAP in the orb's own network namespace (see the module docs).
    Tap { netns: String, index: u32 },
}

/// Durable per-orb attachment metadata (stable across sleep).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetAttachment {
    pub backend: NetBackend,
    pub mac: String,
    pub ipv4_cidr: String,
    pub ipv4_gateway: String,
    pub mtu: u32,
}

/// The TAP device inside an orb's namespace.
pub const TAP: &str = "tap0";
/// Highest `Tap` index: 169.254.0.0/16 in /30s, from index 1.
const MAX_INDEX: u32 = 16383;

/// Serializes index allocation within this agent.
static ALLOCATION: Mutex<()> = Mutex::new(());

impl NetAttachment {
    /// Slirp attachment for a new QEMU orb.
    pub fn user(orb: OrbId, network: GuestNetwork) -> Self {
        Self::with_backend(orb, network, NetBackend::User)
    }

    /// Allocates a durable index for `orb` (`<state>/net/<index>` names its owner, so a
    /// retry after a crash finds it again) and builds the orb's namespace, its TAP owned
    /// by `owner` (a jailed VMM's ids). Undone by [`release`].
    pub fn tap(
        orb: OrbId,
        state_dir: &Path,
        network: GuestNetwork,
        owner: Option<Ids>,
    ) -> Result<Self, String> {
        let index = allocate(&state_dir.join("net"), orb)?;
        let att = Self::with_backend(
            orb,
            network,
            NetBackend::Tap {
                netns: format!("orbd-{orb}"),
                index,
            },
        );
        att.adopt(owner)?;
        Ok(att)
    }

    fn with_backend(orb: OrbId, network: GuestNetwork, backend: NetBackend) -> Self {
        Self {
            backend,
            mac: stable_mac(orb),
            ipv4_cidr: format!("{}/{}", network.guest(), network.prefix()),
            ipv4_gateway: network.gateway().to_string(),
            mtu: 1500,
        }
    }

    /// The guest's network address and prefix length, from its recorded address.
    fn subnet(&self) -> Result<(Ipv4Addr, u8), String> {
        let bad = || format!("bad guest address {:?}", self.ipv4_cidr);
        let (addr, prefix) = self.ipv4_cidr.split_once('/').ok_or_else(bad)?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| bad())?;
        let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 32).ok_or_else(bad)?;
        let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
        Ok((Ipv4Addr::from(u32::from(addr) & mask), prefix))
    }

    /// Makes sure the host side exists before a (re)launch, creating only what is
    /// missing. With `owner` (the VMM to launch is jailed) a TAP owned by anyone else is
    /// created again for it; only call it so while no VMM uses the TAP.
    pub fn adopt(&self, owner: Option<Ids>) -> Result<(), String> {
        match &self.backend {
            NetBackend::User => Ok(()),
            NetBackend::Tap { netns, index } => {
                let (net, prefix) = self.subnet()?;
                build_namespace(
                    netns,
                    *index,
                    &format!("{}/{prefix}", self.ipv4_gateway),
                    &format!("{net}/{prefix}"),
                    owner,
                )
            }
        }
    }

    pub fn is_tap(&self) -> bool {
        matches!(self.backend, NetBackend::Tap { .. })
    }

    /// The namespace the VMM must run in.
    pub fn netns_path(&self) -> Option<PathBuf> {
        match &self.backend {
            NetBackend::User => None,
            NetBackend::Tap { netns, .. } => Some(Path::new("/run/netns").join(netns)),
        }
    }

    /// Guest-visible QEMU arguments (part of the device topology recorded in manifests).
    pub fn qemu_args(&self) -> Result<Vec<String>, String> {
        let netdev = match self.backend {
            NetBackend::User => {
                let (net, prefix) = self.subnet()?;
                let guest = self.ipv4_cidr.split('/').next().unwrap_or_default();
                format!(
                    "user,id=net0,ipv6=off,net={net}/{prefix},host={},dhcpstart={guest}",
                    self.ipv4_gateway
                )
            }
            NetBackend::Tap { .. } => format!("tap,id=net0,ifname={TAP},script=no,downscript=no"),
        };
        Ok(vec![
            "-netdev".into(),
            netdev,
            "-device".into(),
            format!("virtio-net-pci,id=net0dev,netdev=net0,mac={}", self.mac),
        ])
    }

    /// Static addressing for `Wake.network`; DNS is explicit config, never the host's
    /// resolv.conf.
    pub fn guest_config(&self, dns_servers: &[String]) -> gpb::NetworkConfig {
        gpb::NetworkConfig {
            dns_servers: dns_servers.to_vec(),
            search_domains: Vec::new(),
            mac: self.mac.clone(),
            ipv4_cidr: self.ipv4_cidr.clone(),
            ipv4_gateway: self.ipv4_gateway.clone(),
            mtu: self.mtu,
        }
    }
}

/// IPv4 destinations orbs do not reach unless [`Egress`] allows them: RFC 6890's
/// special-purpose addresses that are not globally reachable (private, shared/CGNAT
/// and so tailnets, loopback, documentation, benchmarking, multicast, reserved,
/// broadcast). Link-local is in [`ALWAYS_BLOCKED`].
const PRIVATE_NETS: [&str; 14] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

/// Never reachable from orbs, whatever [`Egress`] allows (except their DNS servers on
/// port 53): link-local (cloud metadata), Azure's WireServer, Alibaba Cloud's metadata
/// and the host's Tailscale resolver.
const ALWAYS_BLOCKED: [&str; 4] = [
    "169.254.0.0/16",
    "168.63.129.16",
    "100.100.100.200",
    "100.100.100.100",
];

/// New orb flows a second (and their burst) the kernel logs for the flow log, for all
/// orbs together; more are only counted (`flowlog_unlogged`).
pub const FLOW_LOG_RATE: u32 = 2000;
const FLOW_LOG_BURST: u32 = 4000;
/// The same for each orb (by its veth address), so one orb opening connections as fast
/// as it can uses up only its own share, not every other orb's log.
pub const FLOW_LOG_ORB_RATE: u32 = 200;
const FLOW_LOG_ORB_BURST: u32 = 400;

/// Enables forwarding in the agent's namespace and installs orbd's nftables table
/// (replaced atomically; nothing else is touched). Run once before any `Tap` VM starts.
pub fn prepare_host(egress: &Egress, dns_servers: &[String]) -> Result<(), String> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| format!("enabling IPv4 forwarding: {e}"))?;
    nft(&host_table(egress, dns_servers))?;
    if egress.allow_private {
        tracing::warn!(
            "VM orbs may reach every private destination, the host's LAN included \
             (ORBD_ALLOW_PRIVATE_EGRESS)"
        );
    } else {
        let allowed: Vec<String> = egress.allow.iter().map(|r| r.to_string()).collect();
        tracing::info!(
            allowed = %allowed.join(","),
            dns = %dns_servers.join(","),
            "VM orbs reach the internet, their DNS servers and only these private \
             destinations (more with ORBD_EGRESS_ALLOW)"
        );
    }
    Ok(())
}

/// One rule of the egress decision for orb traffic: what it matches, whether it
/// accepts, and its comment.
struct Rule {
    matches: String,
    accept: bool,
    comment: Option<String>,
}

/// The egress decision for orb traffic past the sanity checks, in order (see the module
/// docs); what no rule matches is accepted.
fn egress_rules(egress: &Egress, dns_servers: &[String]) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut rule = |matches: String, accept: bool, comment: Option<String>| {
        rules.push(Rule {
            matches,
            accept,
            comment,
        })
    };
    rule(r#"oifname "orbd*""#.into(), false, None);
    // Orbs resolve through the agent's DNS servers, wherever those are (a link-local
    // resolver too, so before ALWAYS_BLOCKED).
    for d in dns_servers
        .iter()
        .filter_map(|d| d.parse::<std::net::Ipv4Addr>().ok())
    {
        rule(
            format!("ip daddr {d} meta l4proto {{ tcp, udp }} th dport 53"),
            true,
            Some("dns".into()),
        );
    }
    rule(
        format!("ip daddr {{ {} }}", ALWAYS_BLOCKED.join(", ")),
        false,
        None,
    );
    if !egress.allow_private {
        for r in &egress.allow {
            let net = format!("{}/{}", r.net, r.prefix);
            let ports = r.ports.map(|(a, b)| match a == b {
                true => a.to_string(),
                false => format!("{a}-{b}"),
            });
            let what = match (r.proto, ports) {
                (EgressProto::Tcp, Some(p)) => format!(" tcp dport {p}"),
                (EgressProto::Udp, Some(p)) => format!(" udp dport {p}"),
                (EgressProto::Any, Some(p)) => format!(" meta l4proto {{ tcp, udp }} th dport {p}"),
                (EgressProto::Tcp, None) => " meta l4proto tcp".into(),
                (EgressProto::Udp, None) => " meta l4proto udp".into(),
                (EgressProto::Any, None) => String::new(),
            };
            rule(format!("ip daddr {net}{what}"), true, Some(r.to_string()));
        }
        rule(
            format!("ip daddr {{ {} }}", PRIVATE_NETS.join(", ")),
            false,
            None,
        );
    }
    rules
}

/// Orb traffic must come from the address of the veth it arrives on (an orb namespace
/// cannot pass as another orb's).
const ANTI_SPOOF: &str = r#"iifname "orbd*" fib saddr . iif oif missing drop"#;

/// orbd's nftables table for `egress`: see the module docs.
fn host_table(egress: &Egress, dns_servers: &[String]) -> String {
    use super::flowlog::{GROUP, PREFIX_ACCEPT, PREFIX_DROP, SNAPLEN};
    let decisions = egress_rules(egress, dns_servers);
    let comment = |r: &Rule| match &r.comment {
        Some(c) => format!(" comment \"{c}\""),
        None => String::new(),
    };
    let mut forward = String::new();
    for r in &decisions {
        let verdict = if r.accept { "accept" } else { "drop" };
        forward.push_str(&format!(
            "        iifname \"orbd*\" {} {verdict}{}\n",
            r.matches,
            comment(r)
        ));
    }
    let (mut log_input, mut log_forward, mut extra) = (String::new(), String::new(), String::new());
    if egress.flow_log {
        let log = |prefix: &str| format!("log group {GROUP} snaplen {SNAPLEN} prefix \"{prefix}\"");
        // New flows pass the gate (each orb's own limit, then one for all orbs) to be
        // logged; flows over either are counted instead.
        log_input = "        iifname \"orbd*\" ct state new jump flowlog_input\n".into();
        log_forward = "        iifname \"orbd*\" ct state new jump flowlog_gate\n".into();
        let mut mirror = String::new();
        for r in &decisions {
            let prefix = if r.accept { PREFIX_ACCEPT } else { PREFIX_DROP };
            mirror.push_str(&format!(
                "        {} {} return{}\n",
                r.matches,
                log(prefix),
                comment(r)
            ));
        }
        let gate = format!(
            "        update @flowlog_orbs {{ ip saddr limit rate over {FLOW_LOG_ORB_RATE}/second \
             burst {FLOW_LOG_ORB_BURST} packets }} counter name \"flowlog_unlogged\" return\n        \
             limit name \"flowlog_all\" counter name \"flowlog_unlogged\" return\n"
        );
        extra = format!(
            "    counter flowlog_unlogged {{ }}\n    limit flowlog_all {{ rate over {FLOW_LOG_RATE}/second \
             burst {FLOW_LOG_BURST} packets }}\n    set flowlog_orbs {{\n        type ipv4_addr\n        \
             size 65535\n        flags dynamic,timeout\n        timeout 1m\n    }}\n    chain \
             flowlog_input {{\n{gate}        {}\n    }}\n    chain flowlog_gate {{\n{gate}        \
             jump flowlog\n    }}\n    chain flowlog {{\n{mirror}        {}\n    }}\n",
            log(PREFIX_DROP),
            log(PREFIX_ACCEPT)
        );
    }
    format!(
        r#"table inet orbd
delete table inet orbd
table inet orbd {{
{extra}    chain input {{
        type filter hook input priority filter; policy accept;
        {ANTI_SPOOF}
        iifname "orbd*" ct state established,related accept
{log_input}        iifname "orbd*" drop
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        {ANTI_SPOOF}
        iifname "orbd*" meta nfproto ipv6 drop
        iifname "orbd*" ct state invalid,untracked drop
        iifname "orbd*" ip saddr != 169.254.0.0/16 drop
{log_forward}{forward}    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        iifname "orbd*" oifname != "orbd*" masquerade
    }}
}}
"#
    )
}

/// New orb flows the kernel did not log for the flow log (over [`FLOW_LOG_ORB_RATE`] or
/// [`FLOW_LOG_RATE`]) since orbd's table was installed; None without the flow log or
/// `nft`.
pub fn flow_log_unlogged() -> Option<u64> {
    let out = Command::new("nft")
        .args(["list", "counter", "inet", "orbd", "flowlog_unlogged"])
        .output()
        .ok()?;
    out.status.success().then_some(())?;
    counter_packets(&String::from_utf8_lossy(&out.stdout))
}

/// `packets <n>` of an `nft list counter` listing.
fn counter_packets(listing: &str) -> Option<u64> {
    let mut words = listing.split_whitespace();
    words.find(|w| *w == "packets")?;
    words.next()?.parse().ok()
}

/// The network index whose namespace side has `addr` (its orb's traffic leaves with that
/// source), if it is one.
pub fn index_of(addr: Ipv4Addr) -> Option<u32> {
    let [a, b, c, d] = addr.octets();
    if (a, b) != (169, 254) || d % 4 != 2 {
        return None;
    }
    let i = u32::from(c) * 64 + u32::from(d) / 4;
    ((1..=MAX_INDEX).contains(&i) && i / 64 != 169).then_some(i)
}

/// The orb holding network index `index` on this host.
pub fn owner(state_dir: &Path, index: u32) -> Option<OrbId> {
    let owner = std::fs::read_to_string(state_dir.join("net").join(index.to_string())).ok()?;
    OrbId::parse(owner.trim()).ok()
}

/// Releases everything `orb` holds on the host (namespace, index), also what a create
/// left behind before its recipe was published. Idempotent; call once no VMM runs.
pub fn release(orb: OrbId, state_dir: &Path) {
    let netns = format!("orbd-{orb}");
    let path = Path::new("/run/netns").join(&netns);
    if !is_netns(&path) {
        let _ = std::fs::remove_file(&path);
    } else if let Err(e) = ip(&["netns", "delete", &netns]) {
        tracing::warn!(%netns, error = %e, "removing network namespace");
    }
    let dir = state_dir.join("net");
    let _g = ALLOCATION.lock().unwrap_or_else(|e| e.into_inner());
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        if std::fs::read_to_string(e.path()).is_ok_and(|o| o.trim() == orb.to_string()) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// `<dir>/<index>` files name their orb. Returns the orb's existing index or the
/// lowest free one, durably claimed.
fn allocate(dir: &Path, orb: OrbId) -> Result<u32, String> {
    let _g = ALLOCATION.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let owner = orb.to_string();
    let mut used = std::collections::HashSet::new();
    for e in std::fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
        let Some(i) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if std::fs::read_to_string(e.path()).is_ok_and(|o| o.trim() == owner) {
            return Ok(i);
        }
        used.insert(i);
    }
    // 169.254.169.0/24 (cloud metadata) is never handed out, nor an index whose
    // interface exists (left by an earlier agent whose state was wiped).
    let index = (1..=MAX_INDEX)
        .filter(|i| i / 64 != 169)
        .find(|i| !used.contains(i) && !Path::new(&format!("/sys/class/net/orbd{i}")).exists())
        .ok_or("no free network index")?;
    super::fsutil::write_atomic(&dir.join(index.to_string()), owner.as_bytes())
        .map_err(|e| format!("claiming network index {index}: {e}"))?;
    Ok(index)
}

/// Host-side (`.1`) and namespace-side (`.2`) addresses of index `i`'s /30.
fn transit(i: u32) -> (String, String) {
    let (a, b) = (i / 64, (i % 64) * 4);
    (
        format!("169.254.{a}.{}", b + 1),
        format!("169.254.{a}.{}", b + 2),
    )
}

/// The table in an orb's namespace (`subnet` is the guest's, e.g. `10.0.2.0/24`): what
/// leaves through the veth is masqueraded behind its address. Packets conntrack finds
/// invalid (e.g. a TCP segment outside the window), which would leave un-NATed, and
/// guest packets from outside its subnet are dropped.
fn ns_table(subnet: &str) -> String {
    let checks = format!(
        "        ct state invalid drop\n        iifname \"{TAP}\" ip saddr != {subnet} drop\n"
    );
    format!(
        r#"table ip orbd
delete table ip orbd
table ip orbd {{
    chain input {{
        type filter hook input priority filter; policy accept;
{checks}    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
{checks}    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" masquerade
    }}
}}
"#
    )
}

/// `gateway` is the TAP's address, e.g. `10.0.2.2/24`, in the guest's `subnet`; `owner`
/// the jailed VMM's ids.
fn build_namespace(
    netns: &str,
    index: u32,
    gateway: &str,
    subnet: &str,
    owner: Option<Ids>,
) -> Result<(), String> {
    let host_if = format!("orbd{index}");
    let (host_addr, ns_addr) = transit(index);
    let path = Path::new("/run/netns").join(netns);
    if !is_netns(&path) {
        // A name left without its mount (the agent's container restarted) is stale.
        let _ = std::fs::remove_file(&path);
        ip(&["netns", "add", netns])?;
    }
    let exists = |args: &[&str]| {
        Command::new("ip")
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    };
    let tap_exists = exists(&["-n", netns, "link", "show", TAP]);
    if tap_exists
        && let Some(o) = owner
        && tap_owner(netns)? != Some((Some(u64::from(o.uid)), Some(u64::from(o.gid))))
    {
        // An unprivileged VMM attaches only to a TAP it owns, and the owner of a TAP
        // cannot change while it exists (e.g. one built before VMMs were jailed). One
        // whose owner `ip` does not show (an older iproute2) is built again too: no VMM
        // is attached now.
        ip(&["-n", netns, "link", "delete", TAP])?;
        build_tap(netns, owner)?;
    } else if !tap_exists {
        build_tap(netns, owner)?;
    }
    if !exists(&["link", "show", &host_if]) {
        // A leftover peer in the namespace (crash mid-setup) blocks the new pair.
        if exists(&["-n", netns, "link", "show", "eth0"]) {
            ip(&["-n", netns, "link", "delete", "eth0"])?;
        }
        ip(&[
            "link", "add", &host_if, "type", "veth", "peer", "name", "eth0", "netns", netns,
        ])?;
    }
    ip(&[
        "addr",
        "replace",
        &format!("{host_addr}/30"),
        "dev",
        &host_if,
    ])?;
    ip(&["link", "set", &host_if, "up"])?;
    for args in [
        vec!["addr", "replace", gateway, "dev", TAP],
        vec!["link", "set", TAP, "up"],
        vec!["link", "set", "lo", "up"],
        vec!["addr", "replace", &format!("{ns_addr}/30"), "dev", "eth0"],
        vec!["link", "set", "eth0", "up"],
        vec!["route", "replace", "default", "via", &host_addr],
    ] {
        let mut full = vec!["-n", netns];
        full.extend(args);
        ip(&full)?;
    }
    in_netns(netns, || {
        for (key, value) in [
            ("net/ipv4/ip_forward", "1"),
            ("net/ipv6/conf/all/disable_ipv6", "1"),
            ("net/ipv6/conf/default/disable_ipv6", "1"),
        ] {
            std::fs::write(Path::new("/proc/sys").join(key), value)
                .map_err(|e| format!("{key}: {e}"))?;
        }
        nft(&ns_table(subnet))
    })
}

/// A persistent TAP in `netns`, owned by `owner` if given.
fn build_tap(netns: &str, owner: Option<Ids>) -> Result<(), String> {
    let mut args: Vec<String> = ["-n", netns, "tuntap", "add", "dev", TAP, "mode", "tap"]
        .map(String::from)
        .into();
    if let Some(o) = owner {
        args.extend([
            "user".into(),
            o.uid.to_string(),
            "group".into(),
            o.gid.to_string(),
        ]);
    }
    ip(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

/// A TAP's owner and group (None each: anyone with `CAP_NET_ADMIN`).
type TapOwner = (Option<u64>, Option<u64>);

/// The TAP's owner and group in `netns`, or None if `ip` does not show them.
fn tap_owner(netns: &str) -> Result<Option<TapOwner>, String> {
    let out = Command::new("ip")
        .args(["-j", "-d", "-n", netns, "link", "show", TAP])
        .output()
        .map_err(|e| format!("ip: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ip -n {netns} link show {TAP}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(parse_tap_owner(&out.stdout))
}

/// `user` and `group` from `ip -j -d link show` of a TAP (absent when unset; a name
/// where the id has one, which never matches a jail's id).
fn parse_tap_owner(json: &[u8]) -> Option<TapOwner> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    let info = v.get(0)?.get("linkinfo")?;
    if info.get("info_kind")?.as_str()? != "tun" {
        return None;
    }
    let data = info.get("info_data")?;
    let id = |k: &str| data.get(k).map(|v| v.as_u64().unwrap_or(u64::MAX));
    Some((id("user"), id("group")))
}

/// Whether `path` is a mounted network namespace (not just a leftover name).
fn is_netns(path: &Path) -> bool {
    const NSFS_MAGIC: i64 = 0x6e73_6673;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: statfs fills a zeroed struct for a valid C string.
    unsafe {
        let mut st: nix::libc::statfs = std::mem::zeroed();
        nix::libc::statfs(c.as_ptr(), &mut st) == 0 && st.f_type as i64 == NSFS_MAGIC
    }
}

/// Network namespaces are Linux-only (`Tap` attachments are never built elsewhere).
#[cfg(not(target_os = "linux"))]
fn in_netns<T: Send>(
    netns: &str,
    _f: impl FnOnce() -> Result<T, String> + Send,
) -> Result<T, String> {
    Err(format!("joining {netns}: network namespaces need Linux"))
}

/// Runs `f` on a thread that has joined `netns`; commands it starts run there too.
#[cfg(target_os = "linux")]
fn in_netns<T: Send>(
    netns: &str,
    f: impl FnOnce() -> Result<T, String> + Send,
) -> Result<T, String> {
    let path = Path::new("/run/netns").join(netns);
    let ns = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::thread::scope(|s| {
        s.spawn(|| {
            // SAFETY: setns on this (short-lived) thread only; the fd is valid.
            if unsafe { nix::libc::setns(ns.as_raw_fd(), nix::libc::CLONE_NEWNET) } < 0 {
                return Err(format!(
                    "joining {netns}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            f()
        })
        .join()
        .map_err(|_| "network namespace thread panicked".to_owned())?
    })
}

fn ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Applies an nftables script atomically.
fn nft(script: &str) -> Result<(), String> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft: {e}"))?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(script.as_bytes())
        .map_err(|e| format!("nft: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("nft: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nft: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// QEMU's OUI plus three bytes derived from the orb id.
fn stable_mac(orb: OrbId) -> String {
    let h = Sha256::digest(orb.0.as_bytes());
    format!("52:54:00:{:02x}:{:02x}:{:02x}", h[0], h[1], h[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn egress(allow: &[&str]) -> Egress {
        Egress::new(
            false,
            &allow.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn forward(t: &str) -> Vec<String> {
        let fwd = t.split("chain forward").nth(1).unwrap();
        let fwd = fwd.split("chain postrouting").next().unwrap();
        fwd.lines()
            .map(str::trim)
            .filter(|l| l.starts_with("iifname"))
            .map(|l| l.trim_start_matches("iifname \"orbd*\" ").to_owned())
            .collect()
    }

    #[test]
    fn private_destinations_are_dropped_except_allowed_ones() {
        let t = host_table(
            &egress(&[
                "udp:192.168.2.201:41641",
                "any:10.1.0.0/16:80-90",
                "any:172.20.0.0/16",
                "",
            ]),
            &[
                "1.1.1.1".into(),
                "169.254.169.253".into(),
                "2606:4700::1111".into(),
            ],
        );
        assert_eq!(
            forward(&t),
            [
                "fib saddr . iif oif missing drop",
                "meta nfproto ipv6 drop",
                "ct state invalid,untracked drop",
                "ip saddr != 169.254.0.0/16 drop",
                r#"oifname "orbd*" drop"#,
                r#"ip daddr 1.1.1.1 meta l4proto { tcp, udp } th dport 53 accept comment "dns""#,
                r#"ip daddr 169.254.169.253 meta l4proto { tcp, udp } th dport 53 accept comment "dns""#,
                "ip daddr { 169.254.0.0/16, 168.63.129.16, 100.100.100.200, 100.100.100.100 } drop",
                r#"ip daddr 192.168.2.201/32 udp dport 41641 accept comment "udp:192.168.2.201:41641""#,
                r#"ip daddr 10.1.0.0/16 meta l4proto { tcp, udp } th dport 80-90 accept comment "any:10.1.0.0/16:80-90""#,
                r#"ip daddr 172.20.0.0/16 accept comment "any:172.20.0.0/16""#,
                "ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 172.16.0.0/12, \
                 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, \
                 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } drop",
            ]
        );
        // Everything private allowed: metadata, spoofing, invalid packets and IPv6 are
        // still dropped.
        let open = forward(&host_table(&Egress::new(true, &[]).unwrap(), &[]));
        assert!(!open.iter().any(|l| l.contains("10.0.0.0/8")), "{open:?}");
        assert!(open.iter().any(|l| l.contains("168.63.129.16")), "{open:?}");
        assert!(
            open.iter().any(|l| l.contains("ct state invalid")),
            "{open:?}"
        );
    }

    /// The table loads into nftables, in a throwaway user and network namespace. Skipped
    /// where unprivileged user namespaces or nft are unavailable, unless
    /// `ORBD_TEST_NFT=1` (CI) requires it.
    #[cfg(target_os = "linux")]
    #[test]
    fn host_table_loads() {
        use std::io::Write;
        let probe = Command::new("unshare")
            .args(["-rn", "nft", "list", "ruleset"])
            .output();
        if !probe.is_ok_and(|o| o.status.success()) {
            assert!(
                std::env::var("ORBD_TEST_NFT").is_err(),
                "ORBD_TEST_NFT is set but `unshare -rn nft` does not work"
            );
            eprintln!("skipped: no unprivileged network namespace with nft");
            return;
        }
        let logged = |mut e: Egress| {
            e.flow_log = true;
            e
        };
        for e in [
            egress(&[]),
            egress(&[
                "udp:192.168.2.201:41641",
                "any:10.1.0.0/16:80-90",
                "tcp:172.16.0.0/12",
                "udp:10.0.0.0/8",
            ]),
            Egress::new(true, &[]).unwrap(),
            logged(egress(&[
                "udp:192.168.2.201:41641",
                "any:10.1.0.0/16:80-90",
            ])),
            logged(Egress::new(true, &[]).unwrap()),
        ] {
            let script = host_table(&e, &["1.1.1.1".into(), "10.0.0.53".into()]);
            let mut child = Command::new("unshare")
                .args(["-rn", "sh", "-c", "nft -f - && nft list table inet orbd"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "{}\n{script}",
                String::from_utf8_lossy(&out.stderr)
            );
            let listed = String::from_utf8_lossy(&out.stdout);
            assert!(listed.contains("168.63.129.16"), "{listed}");
            // (Listed as `oif` or, by newer nft, `check`.)
            assert!(listed.contains("fib saddr . iif"), "{listed}");
        }
        // And an orb namespace's table.
        let script = ns_table("10.0.2.0/24");
        let mut child = Command::new("unshare")
            .args(["-rn", "sh", "-c", "nft -f - && nft list table ip orbd"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}\n{script}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("ct state invalid drop"));
    }

    /// With the flow log, new orb flows pass a chain that mirrors the decision rules one
    /// for one and only logs; the decision rules are unchanged, and without the flow log
    /// nothing logs.
    #[test]
    fn flow_log_mirrors_the_egress_decision() {
        let dns = ["1.1.1.1".to_string()];
        let mut e = egress(&["udp:192.168.2.201:41641", "tcp:10.0.0.0/8:8000-8100"]);
        let plain = host_table(&e, &dns);
        assert!(
            !plain.contains("log") && !plain.contains("flowlog"),
            "{plain}"
        );
        e.flow_log = true;
        let t = host_table(&e, &dns);
        assert_eq!(forward(&t), {
            let mut want = forward(&plain);
            want.splice(4..4, ["ct state new jump flowlog_gate".into()]);
            want
        });
        // The gate: each orb's limit, then all orbs', each counting what it holds back.
        let gate = |name: &str| -> Vec<String> {
            t.split(&format!("chain {name} {{"))
                .nth(1)
                .unwrap()
                .lines()
                .map(str::trim)
                .take_while(|l| *l != "}")
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let held = [
            "update @flowlog_orbs { ip saddr limit rate over 200/second burst 400 packets } \
             counter name \"flowlog_unlogged\" return"
                .to_string(),
            "limit name \"flowlog_all\" counter name \"flowlog_unlogged\" return".to_string(),
        ];
        assert_eq!(
            gate("flowlog_gate"),
            [&held[..], &["jump flowlog".into()]].concat()
        );
        assert!(t.contains("limit flowlog_all { rate over 2000/second burst 4000 packets }"));
        let chain: Vec<&str> = t
            .split("chain flowlog {")
            .nth(1)
            .unwrap()
            .lines()
            .map(str::trim)
            .take_while(|l| *l != "}")
            .collect();
        let decisions: Vec<String> = forward(&plain)[4..].to_vec();
        let log = |p: &str| format!("log group 4731 snaplen 64 prefix \"{p}\"");
        let mirrored: Vec<String> = decisions
            .iter()
            .map(|d| {
                let (accept, rest) = match d.split_once(" accept") {
                    Some((m, c)) => (true, (m, c)),
                    None => (false, d.split_once(" drop").unwrap()),
                };
                let prefix = if accept { "orbd:a" } else { "orbd:d" };
                format!("{} {} return{}", rest.0, log(prefix), rest.1)
            })
            .collect();
        let chain: Vec<String> = chain
            .iter()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();
        assert_eq!(chain[..chain.len() - 1], mirrored[..], "{t}");
        assert_eq!(
            chain.last().unwrap(),
            &log("orbd:a"),
            "the policy accepts the rest"
        );
        // Orb to agent: logged as dropped, through the same gate.
        let input = t.split("chain input {").nth(1).unwrap();
        assert!(
            input.contains("iifname \"orbd*\" ct state new jump flowlog_input"),
            "{input}"
        );
        assert_eq!(
            gate("flowlog_input"),
            [&held[..], &[log("orbd:d")]].concat()
        );
    }

    #[test]
    fn flows_name_their_network_index() {
        for i in [1, 2, 63, 64, 1000, MAX_INDEX] {
            let (host, ns) = transit(i);
            assert_eq!(index_of(ns.parse().unwrap()), Some(i), "{ns}");
            assert_eq!(index_of(host.parse().unwrap()), None, "{host}");
        }
        // Index 0 and the cloud metadata /24 are never handed out.
        for not in ["10.0.2.15", "169.254.0.2", "169.254.0.1", "169.254.169.254"] {
            assert_eq!(index_of(not.parse().unwrap()), None, "{not}");
        }
        let dir = tempfile::tempdir().unwrap();
        let orb = OrbId::generate();
        let i = allocate(&dir.path().join("net"), orb).unwrap();
        assert_eq!(owner(dir.path(), i), Some(orb));
        assert_eq!(owner(dir.path(), i + 1), None);
        assert_eq!(
            counter_packets(
                "table inet orbd {\n\tcounter flowlog_unlogged {\n\t\tpackets 42 bytes 2520\n\t}\n}\n"
            ),
            Some(42)
        );
        assert_eq!(counter_packets("nothing"), None);
    }

    /// Orb traffic is checked against the veth it arrives on, to the agent and through
    /// it, before anything else (the flow log included).
    #[test]
    fn orbs_cannot_pass_as_each_other() {
        for flow_log in [false, true] {
            let mut e = egress(&[]);
            e.flow_log = flow_log;
            let t = host_table(&e, &["1.1.1.1".into()]);
            for chain in ["input", "forward"] {
                let first = t
                    .split(&format!("chain {chain} {{"))
                    .nth(1)
                    .unwrap()
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .nth(1);
                assert_eq!(first, Some(ANTI_SPOOF), "{chain}: {t}");
            }
        }
        // In the orb's namespace: no invalid packet leaves un-NATed, and the guest only
        // sends from its own subnet.
        let ns = ns_table("10.0.2.0/24");
        for chain in ["input", "forward"] {
            let rules: Vec<&str> = ns
                .split(&format!("chain {chain} {{"))
                .nth(1)
                .unwrap()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take_while(|l| *l != "}")
                .skip(1)
                .collect();
            assert_eq!(
                rules,
                [
                    "ct state invalid drop",
                    r#"iifname "tap0" ip saddr != 10.0.2.0/24 drop"#
                ],
                "{ns}"
            );
        }
        assert!(ns.contains(r#"oifname "eth0" masquerade"#));
    }

    #[test]
    fn tap_owner_from_ip_json() {
        let owned = br#"[{"ifname":"tap0","linkinfo":{"info_kind":"tun","info_data":{"type":"tap","pi":false,"vnet_hdr":false,"multi_queue":false,"persist":true,"user":1300000001,"group":1300000001}}}]"#;
        assert_eq!(
            parse_tap_owner(owned),
            Some((Some(1_300_000_001), Some(1_300_000_001)))
        );
        let unowned = br#"[{"ifname":"tap0","linkinfo":{"info_kind":"tun","info_data":{"type":"tap","persist":true}}}]"#;
        assert_eq!(parse_tap_owner(unowned), Some((None, None)));
        let named = br#"[{"linkinfo":{"info_kind":"tun","info_data":{"user":"root"}}}]"#;
        assert_eq!(parse_tap_owner(named), Some((Some(u64::MAX), None)));
        assert_eq!(parse_tap_owner(b"[]"), None);
        assert_eq!(
            parse_tap_owner(br#"[{"linkinfo":{"info_kind":"veth"}}]"#),
            None
        );
    }

    #[test]
    fn attachment_follows_the_guest_network() {
        let orb = OrbId(uuid::Uuid::nil());
        // Orbs created with the default network keep the arguments their checkpoints
        // were saved with.
        let default = NetAttachment::user(orb, GuestNetwork::default());
        assert_eq!(
            default.qemu_args().unwrap()[1],
            "user,id=net0,ipv6=off,net=10.0.2.0/24,host=10.0.2.2,dhcpstart=10.0.2.15"
        );

        let att = NetAttachment::user(orb, "192.168.240.0/20".parse().unwrap());
        assert_eq!(
            att.qemu_args().unwrap()[1],
            "user,id=net0,ipv6=off,net=192.168.240.0/20,host=192.168.240.2,dhcpstart=192.168.240.15"
        );
        let cfg = att.guest_config(&[]);
        assert_eq!(cfg.ipv4_cidr, "192.168.240.15/20");
        assert_eq!(cfg.ipv4_gateway, "192.168.240.2");
    }
}
