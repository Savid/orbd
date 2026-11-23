//! Agent-local network attachment for one VM, chosen when the orb's disk is created and
//! persisted in its recipe; a sleeping VM is always restored with the attachment (and
//! MAC) it was saved with. Guests see the agent's guest network as it was when the orb
//! was created (default `10.0.2.15/24` via `10.0.2.2`), applied by the guest helper from
//! `Wake.network`.
//!
//! * `User`: QEMU's built-in slirp. No host privileges, guest-initiated traffic only,
//!   not filtered by orbd: macOS QEMU orbs (fenced by pf), never Linux ones.
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
//!
//! An orb whose type restricts egress ([`EgressPolicy`], see [`super::egress`]) is
//! decided by a chain of its own instead, `egress<i>`, which the forward chain enters
//! through the map `egress_chains` (keyed by the orb's veth address) before any other
//! decision: established flows continue if they carry the conntrack mark of the orb's
//! current launch (which every accepted flow gets), so none of the index's earlier orb
//! or of an earlier policy does; the always-blocked destinations are dropped; the
//! policy's `allow` rules accept (private destinations only as far as the agent's own
//! [`Egress`] allows them too); other private destinations are dropped (so no name can
//! open them); the addresses the agent's DNS proxy resolved for the orb's allowlisted
//! names (set `resolved<i>`, each with a timeout) accept on the policy's ports;
//! everything else is dropped. Both ends go through `egress_accept` and `egress_drop`,
//! which log restricted verdicts for the flow log. The proxy listens on [`DNS_PROXY`] on
//! the agent's loopback, reachable (port 53) only from restricted orbs (set
//! `egress_orbs`), at most [`DNS_RATE`] packets a second each; their namespace sends
//! what the guest asks its gateway on port 53 there; the table `arp orbd` keeps the agent
//! from answering ARP for that address elsewhere. These chains are installed when such
//! an orb launches, and with the table for every restricted orb on the host (from
//! `<orb>/egress.json` or its recipe, keeping what the sets held), so an agent restart
//! never leaves one open.

use super::jail::Ids;
use crate::config::agent::{Egress, EgressProto, EgressRule, GuestNetwork};
use crate::model::EgressPolicy;
use crate::model::egress::PortProto;
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
    /// The same, for an orb with restricted egress, which it keeps for life (see
    /// [`super::egress`]). A variant of its own so that agents from before restricted
    /// egress cannot read the recipe, and so never start such an orb unrestricted (and
    /// their garbage collection, which reads every recipe, deletes nothing).
    RestrictedTap { netns: String, index: u32 },
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
    /// `restricted`: the orb's egress is restricted for life ([`NetBackend::RestrictedTap`]).
    pub fn tap(
        orb: OrbId,
        state_dir: &Path,
        network: GuestNetwork,
        owner: Option<Ids>,
        restricted: bool,
    ) -> Result<Self, String> {
        let index = allocate(&state_dir.join("net"), orb)?;
        let netns = format!("orbd-{orb}");
        let backend = match restricted {
            true => NetBackend::RestrictedTap { netns, index },
            false => NetBackend::Tap { netns, index },
        };
        let att = Self::with_backend(orb, network, backend);
        att.adopt(owner, restricted)?;
        Ok(att)
    }

    /// The namespace and network index of a TAP attachment.
    fn tap_parts(&self) -> Option<(&str, u32)> {
        match &self.backend {
            NetBackend::Tap { netns, index } | NetBackend::RestrictedTap { netns, index } => {
                Some((netns, *index))
            }
            NetBackend::User => None,
        }
    }

    /// Whether the recipe restricts the orb's egress for life.
    pub fn is_restricted(&self) -> bool {
        matches!(self.backend, NetBackend::RestrictedTap { .. })
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
    /// created again for it; only call it so while no VMM uses the TAP. `restricted`:
    /// the guest's DNS queries to its gateway go to the agent's DNS proxy.
    pub fn adopt(&self, owner: Option<Ids>, restricted: bool) -> Result<(), String> {
        let Some((netns, index)) = self.tap_parts() else {
            return Ok(());
        };
        let (net, prefix) = self.subnet()?;
        build_namespace(
            netns,
            index,
            &format!("{}/{prefix}", self.ipv4_gateway),
            &format!("{net}/{prefix}"),
            owner,
            (restricted || self.is_restricted()).then_some(self.ipv4_gateway.as_str()),
        )
    }

    /// The network index of a TAP attachment.
    pub fn index(&self) -> Option<u32> {
        self.tap_parts().map(|(_, i)| i)
    }

    pub fn is_tap(&self) -> bool {
        self.tap_parts().is_some()
    }

    /// The namespace the VMM must run in.
    pub fn netns_path(&self) -> Option<PathBuf> {
        self.tap_parts()
            .map(|(netns, _)| Path::new("/run/netns").join(netns))
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
            NetBackend::Tap { .. } | NetBackend::RestrictedTap { .. } => {
                format!("tap,id=net0,ifname={TAP},script=no,downscript=no")
            }
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

/// Where the agent's DNS proxy for restricted orbs listens: the host side of network
/// index 0, which is never handed out, on the agent's loopback.
pub const DNS_PROXY: Ipv4Addr = Ipv4Addr::new(169, 254, 0, 1);

/// A CIDR's network and prefix length; a malformed one (never, the lists are constant)
/// is the whole address space, so it errs on blocking.
fn cidr(s: &str) -> (Ipv4Addr, u8) {
    let (net, prefix) = s.split_once('/').unwrap_or((s, "32"));
    match (net.parse::<Ipv4Addr>(), prefix.parse::<u8>()) {
        (Ok(n), Ok(p)) if p <= 32 => (n, p),
        _ => (Ipv4Addr::UNSPECIFIED, 0),
    }
}

/// Whether network `outer` contains network `inner`.
fn contains(outer: (Ipv4Addr, u8), inner: (Ipv4Addr, u8)) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(outer.1)).unwrap_or(0);
    outer.1 <= inner.1 && u32::from(inner.0) & mask == u32::from(outer.0) & mask
}

/// Whether a resolved address of an allowlisted name may be opened for a restricted
/// orb: not private or otherwise non-global ([`PRIVATE_NETS`]) and not always blocked
/// ([`ALWAYS_BLOCKED`]). The agent's own addresses are never reached through forwarding
/// (its input chain drops orb traffic but DNS to the proxy). The nftables chain checks
/// the same lists again.
pub fn openable(addr: Ipv4Addr) -> bool {
    !PRIVATE_NETS
        .iter()
        .chain(ALWAYS_BLOCKED.iter())
        .any(|c| contains(cidr(c), (addr, 32)))
}

/// What rules `a` and `b` both allow, if anything.
fn intersect(a: &EgressRule, b: &EgressRule) -> Option<EgressRule> {
    let proto = match (a.proto, b.proto) {
        (EgressProto::Any, p) | (p, EgressProto::Any) => p,
        (x, y) if x == y => x,
        _ => return None,
    };
    let (net, prefix) = if contains((a.net, a.prefix), (b.net, b.prefix)) {
        (b.net, b.prefix)
    } else if contains((b.net, b.prefix), (a.net, a.prefix)) {
        (a.net, a.prefix)
    } else {
        return None;
    };
    let ports = match (a.ports, b.ports) {
        (None, p) | (p, None) => p,
        (Some((a1, a2)), Some((b1, b2))) => {
            let (lo, hi) = (a1.max(b1), a2.min(b2));
            if lo > hi {
                return None;
            }
            Some((lo, hi))
        }
    };
    Some(EgressRule {
        proto,
        net,
        prefix,
        ports,
    })
}

/// A restricted orb in orbd's table: its network index and policy, the conntrack mark of
/// its launch (only its own flows count as established), and addresses its proxy opened
/// to keep (with the seconds they have left).
pub struct Restricted<'a> {
    pub index: u32,
    pub policy: &'a EgressPolicy,
    pub mark: u32,
    pub opened: &'a [(Ipv4Addr, u32)],
}

/// Size of each restricted orb's set of resolved addresses (the DNS proxy keeps fewer).
pub const RESOLVED_MAX: usize = 4096;
/// Packets a second (and their burst) one orb may send to the DNS proxy; more are
/// dropped before the proxy sees them.
pub const DNS_RATE: u32 = 300;
const DNS_BURST: u32 = 600;

/// New orb flows a second (and their burst) the kernel logs for the flow log, for all
/// orbs together; more are only counted (`flowlog_unlogged`).
pub const FLOW_LOG_RATE: u32 = 2000;
const FLOW_LOG_BURST: u32 = 4000;
/// The same for each orb (by its veth address), so one orb opening connections as fast
/// as it can uses up only its own share, not every other orb's log.
pub const FLOW_LOG_ORB_RATE: u32 = 200;
const FLOW_LOG_ORB_BURST: u32 = 400;

/// Enables forwarding in the agent's namespace, gives its loopback [`DNS_PROXY`] and
/// installs orbd's nftables table with the chains of the `restricted` orbs on this host
/// (replaced atomically; nothing else is touched). Run once before any `Tap` VM starts.
pub fn prepare_host(
    egress: &Egress,
    dns_servers: &[String],
    restricted: &[Restricted<'_>],
) -> Result<(), String> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| format!("enabling IPv4 forwarding: {e}"))?;
    ip(&["addr", "replace", &format!("{DNS_PROXY}/32"), "dev", "lo"])?;
    nft(&host_table(egress, dns_servers, restricted))?;
    if let Err(e) = nft(&arp_table()) {
        tracing::warn!(
            error = %e,
            "no nftables ARP table (kernel without NF_TABLES_ARP?): this host may answer ARP \
             for {DNS_PROXY}, the DNS proxy's address, on its other interfaces"
        );
    }
    let allowed: Vec<String> = egress.allow.iter().map(|r| r.to_string()).collect();
    tracing::info!(
        allowed = %allowed.join(","),
        dns = %dns_servers.join(","),
        "VM orbs reach the internet, their DNS servers and only these private destinations \
         (more with ORBD_EGRESS_ALLOW)"
    );
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
    for r in &egress.allow {
        rule(rule_match(r), true, Some(r.to_string()));
    }
    rule(
        format!("ip daddr {{ {} }}", PRIVATE_NETS.join(", ")),
        false,
        None,
    );
    rules
}

/// Orb traffic must come from the address of the veth it arrives on (an orb namespace
/// cannot pass as another orb's).
const ANTI_SPOOF: &str = r#"iifname "orbd*" fib saddr . iif oif missing drop"#;

/// What `rule` matches, e.g. ` tcp dport 443` after `ip daddr <net>`.
fn rule_match(r: &EgressRule) -> String {
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
    format!("ip daddr {net}{what}")
}

/// What a restricted orb's `allow` rules accept, with comments: public destinations as
/// listed, private ones only as far as the agent's own [`Egress`] allows them too (the
/// agent's setting wins over the coordinator's).
fn allow_matches(policy: &EgressPolicy, agent: &Egress) -> Vec<(String, String)> {
    let private: Vec<(Ipv4Addr, u8)> = PRIVATE_NETS.iter().map(|c| cidr(c)).collect();
    let mut out = Vec::new();
    for r in &policy.allow {
        let net = (r.net, r.prefix);
        let overlaps = private
            .iter()
            .any(|p| contains(*p, net) || contains(net, *p));
        if !overlaps {
            out.push((rule_match(r), r.to_string()));
            continue;
        }
        if !private.iter().any(|p| contains(*p, net)) {
            out.push((
                format!(
                    "{} ip daddr != {{ {} }}",
                    rule_match(r),
                    PRIVATE_NETS.join(", ")
                ),
                format!("{r}, public part"),
            ));
        }
        for a in &agent.allow {
            if let Some(i) = intersect(r, a) {
                out.push((rule_match(&i), format!("{r}, as ORBD_EGRESS_ALLOW {a}")));
            }
        }
    }
    out
}

/// The rules of restricted orb `index`'s chain `egress<index>` (see the module docs).
/// Accepted flows get `mark`; established flows count only with it, so a flow of the
/// index's earlier orb, or of this orb under an earlier policy, is decided again. The
/// mark takes all 32 bits of the flow's conntrack mark: conntrack is per network
/// namespace, so in Docker (the agent's own namespace) nothing else sees it, but in a
/// namespace shared with other tools that mark flows, orbd overwrites their mark on
/// restricted orbs' flows (only those).
fn restricted_rules(index: u32, policy: &EgressPolicy, mark: u32, agent: &Egress) -> Vec<String> {
    let accept = format!("ct mark set {mark:#010x} goto egress_accept");
    let mut rules = vec![
        format!("ct state established,related ct mark {mark:#010x} accept"),
        format!(
            "ip daddr {{ {} }} goto egress_drop comment \"blocked\"",
            ALWAYS_BLOCKED.join(", ")
        ),
    ];
    for (m, comment) in allow_matches(policy, agent) {
        rules.push(format!("{m} {accept} comment \"{comment}\""));
    }
    rules.push(format!(
        "ip daddr {{ {} }} goto egress_drop comment \"private\"",
        PRIVATE_NETS.join(", ")
    ));
    if !policy.domains.is_empty() {
        for proto in [PortProto::Tcp, PortProto::Udp] {
            let ports: Vec<String> = policy
                .ports
                .iter()
                .filter(|p| p.proto == proto)
                .map(|p| match p.ports {
                    (a, b) if a == b => a.to_string(),
                    (a, b) => format!("{a}-{b}"),
                })
                .collect();
            if !ports.is_empty() {
                rules.push(format!(
                    "ip daddr @resolved{index} {} dport {{ {} }} {accept} comment \"domains\"",
                    proto.as_str(),
                    ports.join(", ")
                ));
            }
        }
    }
    rules.push("goto egress_drop".to_owned());
    rules
}

/// Restricted orb `index`'s set of resolved addresses, holding `opened`:
/// `set resolved<index> { ... }`.
fn resolved_set(index: u32, opened: &[(Ipv4Addr, u32)]) -> String {
    let elements: Vec<String> = opened
        .iter()
        .filter(|(_, t)| *t > 0)
        .map(|(a, t)| format!("{a} timeout {t}s"))
        .collect();
    let elements = match elements.is_empty() {
        true => String::new(),
        false => format!(" elements = {{ {} }};", elements.join(", ")),
    };
    format!(
        "set resolved{index} {{ type ipv4_addr; flags timeout; size {RESOLVED_MAX};{elements} }}"
    )
}

/// `add element` statements naming restricted orb `index` in `egress_orbs` and
/// `egress_chains`.
fn restricted_elements(index: u32) -> String {
    let (_, veth) = transit(index);
    format!(
        "add element inet orbd egress_orbs {{ {veth} }}\n\
         add element inet orbd egress_chains {{ {veth} : goto egress{index} }}\n"
    )
}

/// An nftables script that (re)installs restricted orb `r`'s chain into orbd's table,
/// for a launch; atomic. Its set of resolved addresses is emptied unless `keep` (its
/// policy did not change), and gets `r.opened`.
pub fn restrict_script(r: &Restricted<'_>, agent: &Egress, keep: bool) -> String {
    let index = r.index;
    let rules: String = restricted_rules(index, r.policy, r.mark, agent)
        .iter()
        .map(|l| format!("        {l}\n"))
        .collect();
    let flush = match keep {
        true => String::new(),
        false => format!("flush set inet orbd resolved{index}\n"),
    };
    format!(
        "add chain inet orbd egress{index}\n\
         flush chain inet orbd egress{index}\n\
         add {set}\n\
         {flush}\
         table inet orbd {{\n    chain egress{index} {{\n{rules}    }}\n}}\n{}{}",
        open_script(index, r.opened),
        restricted_elements(index),
        set = resolved_set(index, &[]).replacen("set ", "set inet orbd ", 1),
    )
}

/// An nftables script that removes restricted orb `index` from orbd's table, whatever
/// of it is there; atomic.
pub fn unrestrict_script(index: u32) -> String {
    let (_, veth) = transit(index);
    format!(
        "add chain inet orbd egress{index}\n\
         add {set}\n\
         {elements}\
         delete element inet orbd egress_chains {{ {veth} }}\n\
         delete element inet orbd egress_orbs {{ {veth} }}\n\
         flush chain inet orbd egress{index}\n\
         delete chain inet orbd egress{index}\n\
         delete set inet orbd resolved{index}\n",
        set = resolved_set(index, &[]).replacen("set ", "set inet orbd ", 1),
        elements = restricted_elements(index),
    )
}

/// An nftables script opening `addrs` for restricted orb `index` (its proxy resolved
/// them), each for its timeout in seconds; an address already open gets the new one.
pub fn open_script(index: u32, addrs: &[(Ipv4Addr, u32)]) -> String {
    let mut out = String::new();
    for (a, t) in addrs.iter().filter(|(_, t)| *t > 0) {
        // Adding an element that exists keeps its old timeout: add (so that it
        // exists), delete, and add it again, in one transaction.
        out.push_str(&format!(
            "add element inet orbd resolved{index} {{ {a} timeout {t}s }}\n\
             delete element inet orbd resolved{index} {{ {a} }}\n\
             add element inet orbd resolved{index} {{ {a} timeout {t}s }}\n"
        ));
    }
    out
}

/// Applies an nftables script (see [`restrict_script`] and the like).
pub fn apply_script(script: &str) -> Result<(), String> {
    nft(script)
}

/// The addresses open in each restricted orb's set in orbd's table now, by network
/// index, with the seconds they have left; empty if there is no table or it cannot be
/// read.
pub fn opened_sets() -> std::collections::HashMap<u32, Vec<(Ipv4Addr, u32)>> {
    let out = Command::new("nft")
        .args(["-j", "list", "table", "inet", "orbd"])
        .output();
    match out {
        Ok(o) if o.status.success() => parse_opened_sets(&o.stdout),
        _ => Default::default(),
    }
}

/// [`opened_sets`] from `nft -j list table` output.
fn parse_opened_sets(json: &[u8]) -> std::collections::HashMap<u32, Vec<(Ipv4Addr, u32)>> {
    let mut sets = std::collections::HashMap::new();
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(json) else {
        return sets;
    };
    for o in v["nftables"].as_array().into_iter().flatten() {
        let set = &o["set"];
        let Some(index) = set["name"]
            .as_str()
            .and_then(|n| n.strip_prefix("resolved"))
            .and_then(|i| i.parse::<u32>().ok())
        else {
            continue;
        };
        let elements: Vec<(Ipv4Addr, u32)> = set["elem"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| {
                let e = &e["elem"];
                let addr = e["val"].as_str()?.parse().ok()?;
                let left = e["expires"].as_u64().or_else(|| e["timeout"].as_u64())?;
                Some((addr, u32::try_from(left).ok()?))
            })
            .collect();
        sets.insert(index, elements);
    }
    sets
}

/// orbd's nftables table `inet orbd` for `egress` and the `restricted` orbs (see the
/// module docs).
fn host_table(egress: &Egress, dns_servers: &[String], restricted: &[Restricted<'_>]) -> String {
    use super::flowlog::{
        GROUP, PREFIX_ACCEPT, PREFIX_DROP, PREFIX_RESTRICTED_ACCEPT, PREFIX_RESTRICTED_DROP,
        SNAPLEN,
    };
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
    // Restricted orbs: their verdicts, logged through the gate like the others.
    let (mut log_accept, mut log_drop) = (String::new(), String::new());
    if egress.flow_log {
        log_accept = "        ct state new jump flowlog_restricted_accept\n".into();
        log_drop = "        ct state new jump flowlog_restricted_drop\n".into();
    }
    let mut restricted_chains = String::new();
    let mut elements = String::new();
    for r in restricted {
        let rules: String = restricted_rules(r.index, r.policy, r.mark, egress)
            .iter()
            .map(|l| format!("        {l}\n"))
            .collect();
        restricted_chains.push_str(&format!(
            "    {}\n    chain egress{} {{\n{rules}    }}\n",
            resolved_set(r.index, r.opened),
            r.index
        ));
        elements.push_str(&restricted_elements(r.index));
    }
    if egress.flow_log {
        let log = |prefix: &str| format!("log group {GROUP} snaplen {SNAPLEN} prefix \"{prefix}\"");
        // New flows pass the gate (each orb's own limit, then one for all orbs) to be
        // logged; flows over either are counted instead. A restricted orb's flows to the
        // agent are logged as restricted.
        log_input = "        iifname \"orbd*\" ip saddr @egress_orbs ct state new jump flowlog_restricted_drop\n        \
                     iifname \"orbd*\" ip saddr != @egress_orbs ct state new jump flowlog_input\n"
            .into();
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
             jump flowlog\n    }}\n    chain flowlog {{\n{mirror}        {}\n    }}\n    chain \
             flowlog_restricted_accept {{\n{gate}        {}\n    }}\n    chain \
             flowlog_restricted_drop {{\n{gate}        {}\n    }}\n",
            log(PREFIX_DROP),
            log(PREFIX_ACCEPT),
            log(PREFIX_RESTRICTED_ACCEPT),
            log(PREFIX_RESTRICTED_DROP),
        );
    }
    format!(
        r#"table inet orbd
delete table inet orbd
table inet orbd {{
{extra}    set egress_orbs {{ type ipv4_addr; }}
    map egress_chains {{ type ipv4_addr : verdict; }}
    set dns_clients {{ type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m; }}
    chain egress_accept {{
{log_accept}        accept
    }}
    chain egress_drop {{
{log_drop}        drop
    }}
{restricted_chains}    chain input {{
        type filter hook input priority filter; policy accept;
        {ANTI_SPOOF}
        iifname "orbd*" ip daddr {DNS_PROXY} meta l4proto {{ tcp, udp }} th dport 53 update @dns_clients {{ ip saddr limit rate over {DNS_RATE}/second burst {DNS_BURST} packets }} drop comment "dns proxy: over its rate"
        iifname "orbd*" ct state established,related accept
        iifname "orbd*" ip saddr @egress_orbs ip daddr {DNS_PROXY} meta l4proto {{ tcp, udp }} th dport 53 accept comment "dns proxy"
{log_input}        iifname "orbd*" drop
        ip daddr {DNS_PROXY} drop comment "dns proxy: restricted orbs only"
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        {ANTI_SPOOF}
        iifname "orbd*" meta nfproto ipv6 drop
        iifname "orbd*" ct state invalid,untracked drop
        iifname "orbd*" ip saddr != 169.254.0.0/16 drop
        iifname "orbd*" ip saddr vmap @egress_chains
{log_forward}{forward}    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        iifname "orbd*" oifname != "orbd*" masquerade
    }}
}}
{elements}"#
    )
}

/// The table `arp orbd`, which keeps the agent from answering ARP for [`DNS_PROXY`] on
/// its other interfaces (it is on the agent's loopback). Installed apart from orbd's
/// table: a kernel without nftables' ARP family (`NF_TABLES_ARP`) only lacks this.
fn arp_table() -> String {
    format!(
        r#"table arp orbd
delete table arp orbd
table arp orbd {{
    chain output {{
        type filter hook output priority filter; policy accept;
        arp operation reply arp saddr ip {DNS_PROXY} drop comment "the dns proxy's address is the agent's own"
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

/// The network indexes `<state>/net` records for `orb` (one, unless a crash left more).
pub fn indexes_of(state_dir: &Path, orb: OrbId) -> Vec<u32> {
    let owner = orb.to_string();
    let mut out: Vec<u32> = std::fs::read_dir(state_dir.join("net"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| std::fs::read_to_string(e.path()).is_ok_and(|o| o.trim() == owner))
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    out.sort();
    out
}

/// Releases everything `orb` holds on the host (namespace, index), also what a create
/// left behind before its recipe was published. Idempotent; call once no VMM runs.
pub fn release(orb: OrbId, state_dir: &Path) {
    super::egress::release(orb, state_dir);
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
/// guest packets from outside its subnet are dropped. With `dns_gateway` (a restricted
/// orb's gateway address), the guest's DNS queries to it go to the agent's proxy.
fn ns_table(subnet: &str, dns_gateway: Option<&str>) -> String {
    let checks = format!(
        "        ct state invalid drop\n        iifname \"{TAP}\" ip saddr != {subnet} drop\n"
    );
    let dns = match dns_gateway {
        Some(gw) => format!(
            "    chain prerouting {{\n        type nat hook prerouting priority dstnat; policy accept;\n        \
             iifname \"{TAP}\" ip daddr {gw} meta l4proto {{ tcp, udp }} th dport 53 dnat to {DNS_PROXY}\n    }}\n"
        ),
        None => String::new(),
    };
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
{dns}    chain postrouting {{
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
    dns_gateway: Option<&str>,
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
        // cannot change while it exists (e.g. one built with the jail off). One
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
        nft(&ns_table(subnet, dns_gateway))
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
        Egress::new(&allow.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
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

    fn policy(domains: &[&str], ports: &[&str], allow: &[&str]) -> EgressPolicy {
        let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        EgressPolicy::from_parts(&s(domains), &s(ports), &s(allow)).unwrap()
    }

    /// The rules of chain `name` in `t`.
    fn chain(t: &str, name: &str) -> Vec<String> {
        t.split(&format!("chain {name} {{"))
            .nth(1)
            .unwrap_or_else(|| panic!("no chain {name}: {t}"))
            .lines()
            .map(str::trim)
            .take_while(|l| *l != "}")
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
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
            &[],
        );
        assert_eq!(
            forward(&t),
            [
                "fib saddr . iif oif missing drop",
                "meta nfproto ipv6 drop",
                "ct state invalid,untracked drop",
                "ip saddr != 169.254.0.0/16 drop",
                "ip saddr vmap @egress_chains",
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
    }

    /// The table loads into nftables, in a throwaway user and network namespace. Skipped
    /// where unprivileged user namespaces or nft are unavailable, unless
    /// `ORBD_TEST_NFT=1` (CI) requires it.
    #[cfg(target_os = "linux")]
    #[test]
    fn host_table_loads() {
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
        let untrusted = policy(
            &["ampcode.com", "*.ampcode.com"],
            &["tcp:443", "tcp:8000-8100", "udp:443"],
            &[
                "tcp:203.0.113.0/24:443",
                "any:10.1.0.0/16",
                "udp:192.168.2.201:41641",
            ],
        );
        let addresses = policy(&[], &[], &["tcp:198.51.100.7"]);
        let kept = [
            (Ipv4Addr::new(34, 1, 2, 3), 500),
            (Ipv4Addr::new(34, 1, 2, 4), 9),
        ];
        let restricted = [
            Restricted {
                index: 1,
                policy: &untrusted,
                mark: 0xdead_beef,
                opened: &kept,
            },
            Restricted {
                index: 70,
                policy: &addresses,
                mark: 1,
                opened: &[],
            },
        ];
        for (e, restricted) in [
            (egress(&[]), &[][..]),
            (
                egress(&[
                    "udp:192.168.2.201:41641",
                    "any:10.1.0.0/16:80-90",
                    "tcp:172.16.0.0/12",
                    "udp:10.0.0.0/8",
                ]),
                &restricted[..],
            ),
            (
                logged(egress(&[
                    "udp:192.168.2.201:41641",
                    "any:10.1.0.0/16:80-90",
                ])),
                &restricted[..],
            ),
            (logged(egress(&[])), &restricted[..1]),
        ] {
            let script = host_table(&e, &["1.1.1.1".into(), "10.0.0.53".into()], restricted);
            let script = format!("{script}{}", arp_table());
            let listed = load(
                &script,
                "nft list table inet orbd && nft list table arp orbd",
            );
            assert!(listed.contains("168.63.129.16"), "{listed}");
            assert!(listed.contains("arp saddr ip 169.254.0.1 drop"), "{listed}");
            // (Listed as `oif` or, by newer nft, `check`.)
            assert!(listed.contains("fib saddr . iif"), "{listed}");
            for r in restricted {
                assert!(
                    listed.contains(&format!("chain egress{}", r.index)),
                    "{listed}"
                );
                assert!(
                    listed.contains(&format!("goto egress{}", r.index)),
                    "{listed}"
                );
                assert!(
                    listed.contains(&format!("ct mark {:#010x} accept", r.mark)),
                    "{listed}"
                );
            }
            if restricted.len() == 2 {
                // Carried over: the addresses the set held, with the time they had left.
                let set = listed.split("set resolved1 {").nth(1).unwrap();
                let set = set.split('}').next().unwrap();
                assert!(set.contains("34.1.2.3 timeout 8m20s"), "{set}");
                assert!(set.contains("34.1.2.4 timeout 9s"), "{set}");
            }
        }
        // What a table lists of its sets is what a rebuild carries over.
        let listed = load(
            &host_table(&egress(&[]), &[], &restricted),
            "nft -j list table inet orbd",
        );
        let sets = parse_opened_sets(listed.as_bytes());
        let mut one = sets[&1].clone();
        one.sort();
        assert_eq!(one.len(), 2);
        assert_eq!(one[0].0, Ipv4Addr::new(34, 1, 2, 3));
        assert!((490..=500).contains(&one[0].1), "{one:?}");
        assert_eq!(sets[&70], vec![]);
        // And an orb namespace's table, restricted too.
        for dns in [None, Some("10.0.2.2")] {
            let listed = load(&ns_table("10.0.2.0/24", dns), "nft list table ip orbd");
            assert!(listed.contains("ct state invalid drop"), "{listed}");
            assert_eq!(listed.contains("dnat"), dns.is_some(), "{listed}");
        }
        // Restricting an orb at its launch, opening what its proxy resolved (twice, with
        // a new timeout), restricting it again and lifting it (twice: idempotent), in
        // one namespace.
        let e = logged(egress(&[]));
        let table = host_table(&e, &["1.1.1.1".into()], &restricted[1..]);
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let five = |mark: u32| Restricted {
            index: 5,
            policy: &untrusted,
            mark,
            opened: &[],
        };
        let steps = [
            table,
            restrict_script(&five(1), &e, false),
            open_script(5, &[(a, 90), (Ipv4Addr::new(192, 0, 2, 2), 3000)]),
            open_script(5, &[(a, 600)]),
            "list set inet orbd resolved5\n".into(),
            // The policy is unchanged: the set is kept; a new mark.
            restrict_script(&five(2), &e, true),
            "list set inet orbd resolved5\n".into(),
            restrict_script(&five(3), &e, false),
            "list set inet orbd resolved5\n".into(),
            unrestrict_script(5),
            unrestrict_script(5),
            unrestrict_script(70),
            unrestrict_script(9),
            "list table inet orbd\n".into(),
        ];
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = String::from("set -e\n");
        for (i, step) in steps.iter().enumerate() {
            let f = dir.path().join(format!("{i}.nft"));
            std::fs::write(&f, step).unwrap();
            cmd.push_str(&format!("echo '-- {i}'; nft -f {}\n", f.display()));
        }
        let listed = load("", &cmd);
        let part = |i: usize| {
            listed
                .split(&format!("-- {i}\n"))
                .nth(1)
                .unwrap_or_default()
                .split("-- ")
                .next()
                .unwrap_or_default()
                .to_owned()
        };
        let opened = part(4);
        assert!(opened.contains("192.0.2.1 timeout 10m"), "{listed}");
        assert!(opened.contains("192.0.2.2 timeout 50m"), "{listed}");
        assert!(part(6).contains("192.0.2.1"), "same policy: kept\n{listed}");
        assert!(
            !part(8).contains("192.0.2."),
            "restricted again: emptied\n{listed}"
        );
        let end = part(13);
        assert!(
            !end.contains("egress5") && !end.contains("egress70"),
            "{end}"
        );
        assert!(!end.contains("resolved"), "{end}");
        assert!(end.contains("map egress_chains"), "{end}");
    }

    /// Runs `script` (if any) and then `then` with sh in a throwaway user and network
    /// namespace; their output.
    #[cfg(target_os = "linux")]
    fn load(script: &str, then: &str) -> String {
        use std::io::Write;
        let cmd = match script {
            "" => then.to_owned(),
            _ => format!("nft -f - && {then}"),
        };
        let mut child = Command::new("unshare")
            .args(["-rn", "sh", "-c", &cmd])
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
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "{}\n{stdout}\n{script}",
            String::from_utf8_lossy(&out.stderr)
        );
        stdout
    }

    /// A restricted orb is decided by its own chain, entered before every other egress
    /// decision: its own established flows (by the mark of its launch), then the
    /// always-blocked destinations, its `allow` rules, the private ranges (no name opens
    /// them), the addresses resolved for its names on its ports, and nothing else. Only
    /// restricted orbs reach the DNS proxy, at a bounded rate. Unrestricted orbs' rules
    /// are unchanged.
    #[test]
    fn restricted_orbs_reach_only_their_policy() {
        let p = policy(
            &["ampcode.com", "*.ampcode.com"],
            &["tcp:443", "tcp:8000-8100", "udp:443"],
            &["tcp:35.0.0.0/8:443", "any:34.0.0.0/8", "udp:10.9.0.0/16"],
        );
        let e = egress(&["udp:192.168.2.201:41641"]);
        let dns = ["1.1.1.1".to_string()];
        let restricted = [Restricted {
            index: 70,
            policy: &p,
            mark: 0x1234,
            opened: &[],
        }];
        let t = host_table(&e, &dns, &restricted);
        let accept = "ct mark set 0x00001234 goto egress_accept";
        assert_eq!(
            chain(&t, "egress70"),
            [
                "ct state established,related ct mark 0x00001234 accept".to_owned(),
                r#"ip daddr { 169.254.0.0/16, 168.63.129.16, 100.100.100.200, 100.100.100.100 } goto egress_drop comment "blocked""#.to_owned(),
                format!(r#"ip daddr 35.0.0.0/8 tcp dport 443 {accept} comment "tcp:35.0.0.0/8:443""#),
                format!(r#"ip daddr 34.0.0.0/8 {accept} comment "any:34.0.0.0/8""#),
                // (udp:10.9.0.0/16 is private, and the agent does not allow it.)
                "ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 172.16.0.0/12, \
                 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, \
                 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } goto egress_drop comment \"private\"".to_owned(),
                format!(r#"ip daddr @resolved70 tcp dport {{ 443, 8000-8100 }} {accept} comment "domains""#),
                format!(r#"ip daddr @resolved70 udp dport {{ 443 }} {accept} comment "domains""#),
                "goto egress_drop".to_owned(),
            ]
        );
        assert!(t.contains("set resolved70 { type ipv4_addr; flags timeout; size 4096; }"));
        // Index 70: 169.254.1.24/30, the orb's side .26.
        assert!(t.contains(
            "add element inet orbd egress_orbs { 169.254.1.26 }\n\
             add element inet orbd egress_chains { 169.254.1.26 : goto egress70 }\n"
        ));
        assert_eq!(chain(&t, "egress_accept"), ["accept"]);
        assert_eq!(chain(&t, "egress_drop"), ["drop"]);
        // Before the unrestricted decision; the rest as without restricted orbs.
        let plain = host_table(&e, &dns, &[]);
        assert_eq!(forward(&t), forward(&plain));
        assert_eq!(forward(&t)[4], "ip saddr vmap @egress_chains");
        let input = chain(&t, "input");
        assert_eq!(
            input[2],
            r#"iifname "orbd*" ip daddr 169.254.0.1 meta l4proto { tcp, udp } th dport 53 update @dns_clients { ip saddr limit rate over 300/second burst 600 packets } drop comment "dns proxy: over its rate""#
        );
        assert_eq!(
            input[3],
            r#"iifname "orbd*" ct state established,related accept"#
        );
        assert_eq!(
            input[4],
            r#"iifname "orbd*" ip saddr @egress_orbs ip daddr 169.254.0.1 meta l4proto { tcp, udp } th dport 53 accept comment "dns proxy""#
        );
        assert_eq!(input[5], r#"iifname "orbd*" drop"#);
        assert_eq!(
            input[6],
            r#"ip daddr 169.254.0.1 drop comment "dns proxy: restricted orbs only""#
        );
        // The agent does not answer ARP for the proxy's address (a table of its own).
        assert!(!t.contains("arp orbd"));
        assert!(arp_table().contains(
            "arp operation reply arp saddr ip 169.254.0.1 drop comment \"the dns proxy's address is the agent's own\""
        ));
        // An address-only policy opens no names.
        let only = policy(&[], &[], &["tcp:198.51.100.7"]);
        let rules = restricted_rules(3, &only, 9, &e);
        assert!(!rules.iter().any(|r| r.contains("@resolved3")), "{rules:?}");
        assert_eq!(rules.last().unwrap(), "goto egress_drop");
        // The scripts that install, fill and remove one at launch, delete and resolve.
        let r = restrict_script(&restricted[0], &e, false);
        assert!(r.starts_with(
            "add chain inet orbd egress70\nflush chain inet orbd egress70\n\
             add set inet orbd resolved70 { type ipv4_addr; flags timeout; size 4096; }\n\
             flush set inet orbd resolved70\n"
        ));
        assert!(r.contains("goto egress70 }"), "{r}");
        assert!(!restrict_script(&restricted[0], &e, true).contains("flush set"));
        let u = unrestrict_script(70);
        assert!(u.contains("delete element inet orbd egress_chains { 169.254.1.26 }"));
        assert!(u.ends_with("delete chain inet orbd egress70\ndelete set inet orbd resolved70\n"));
        assert_eq!(
            open_script(70, &[(Ipv4Addr::new(192, 0, 2, 1), 90)]),
            "add element inet orbd resolved70 { 192.0.2.1 timeout 90s }\n\
             delete element inet orbd resolved70 { 192.0.2.1 }\n\
             add element inet orbd resolved70 { 192.0.2.1 timeout 90s }\n"
        );
        // Flow log: restricted verdicts through the same gate, with their own prefixes.
        let mut logged = e.clone();
        logged.flow_log = true;
        let t = host_table(&logged, &dns, &restricted);
        assert_eq!(
            chain(&t, "egress_accept"),
            ["ct state new jump flowlog_restricted_accept", "accept"]
        );
        assert_eq!(
            chain(&t, "egress_drop"),
            ["ct state new jump flowlog_restricted_drop", "drop"]
        );
        let gate = chain(&t, "flowlog_restricted_drop");
        assert_eq!(gate[..2], chain(&t, "flowlog_gate")[..2]);
        assert_eq!(gate[2], r#"log group 4731 snaplen 64 prefix "orbd:rd""#);
        assert_eq!(
            chain(&t, "flowlog_restricted_accept")[2],
            r#"log group 4731 snaplen 64 prefix "orbd:ra""#
        );
        // The vmap comes before the flow log's jump, so the default mirror never logs a
        // restricted orb's flow.
        let fwd = forward(&t);
        let vmap = fwd.iter().position(|l| l.contains("vmap")).unwrap();
        let jump = fwd.iter().position(|l| l.contains("flowlog_gate")).unwrap();
        assert!(vmap < jump, "{fwd:?}");
    }

    /// A restricted orb's `allow` rules reach private destinations only as far as the
    /// agent's own settings allow them too; public ones as listed.
    #[test]
    fn private_allow_rules_need_the_agents_consent() {
        let p = policy(
            &[],
            &[],
            &[
                "tcp:10.0.0.0/8:443",
                "any:192.168.2.0/24",
                "tcp:100.0.0.0/8:22",
                "tcp:34.5.0.0/16",
            ],
        );
        let rules = |e: &Egress| -> Vec<String> {
            allow_matches(&p, e).into_iter().map(|(m, _)| m).collect()
        };
        let private = PRIVATE_NETS.join(", ");
        // The agent allows nothing private: only the public parts.
        assert_eq!(
            rules(&egress(&[])),
            [
                format!("ip daddr 100.0.0.0/8 tcp dport 22 ip daddr != {{ {private} }}"),
                "ip daddr 34.5.0.0/16 meta l4proto tcp".to_owned(),
            ]
        );
        // The agent allows some: what both allow.
        let agent = egress(&[
            "any:10.1.0.0/16:400-500",
            "udp:192.168.2.7",
            "tcp:100.64.0.0/10",
        ]);
        assert_eq!(
            rules(&agent),
            [
                "ip daddr 10.1.0.0/16 tcp dport 443".to_owned(),
                "ip daddr 192.168.2.7/32 meta l4proto udp".to_owned(),
                format!("ip daddr 100.0.0.0/8 tcp dport 22 ip daddr != {{ {private} }}"),
                "ip daddr 100.64.0.0/10 tcp dport 22".to_owned(),
                "ip daddr 34.5.0.0/16 meta l4proto tcp".to_owned(),
            ]
        );
        // Intersections.
        let r = |s: &str| s.parse::<EgressRule>().unwrap();
        let i = |a: &str, b: &str| intersect(&r(a), &r(b)).map(|x| x.to_string());
        assert_eq!(
            i("tcp:10.0.0.0/8:443", "any:10.1.2.0/24").as_deref(),
            Some("tcp:10.1.2.0/24:443")
        );
        assert_eq!(
            i("tcp:10.0.0.0/8:400-500", "tcp:10.0.0.0/8:450-600").as_deref(),
            Some("tcp:10.0.0.0/8:450-500")
        );
        assert_eq!(i("tcp:10.0.0.0/8", "udp:10.0.0.0/8"), None);
        assert_eq!(i("tcp:10.0.0.0/8:1-10", "tcp:10.0.0.0/8:20-30"), None);
        assert_eq!(i("any:10.1.0.0/16", "any:10.2.0.0/16"), None);
    }

    /// A restricted recipe records the restriction in a form recipes of agents from
    /// before it cannot read (the network backend as it was then), so such an agent never
    /// starts the orb unrestricted, and its garbage collection, which reads every recipe,
    /// deletes nothing.
    #[test]
    fn restricted_recipes_are_unreadable_to_older_agents() {
        /// `NetBackend` and `NetAttachment` as agents up to 0.2.8 have them.
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "snake_case", tag = "kind")]
        #[allow(dead_code)]
        enum OldBackend {
            User,
            Tap { netns: String, index: u32 },
        }
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct OldAttachment {
            backend: OldBackend,
            mac: String,
            ipv4_cidr: String,
            ipv4_gateway: String,
            mtu: u32,
        }
        const GOLDEN: &str = r#"{"backend":{"kind":"restricted_tap","netns":"orbd-01a20372-cc74-710a-b470-6bac3eba2690","index":7},"mac":"52:54:00:aa:bb:cc","ipv4_cidr":"10.0.2.15/24","ipv4_gateway":"10.0.2.2","mtu":1500}"#;
        let att = NetAttachment {
            backend: NetBackend::RestrictedTap {
                netns: "orbd-01a20372-cc74-710a-b470-6bac3eba2690".into(),
                index: 7,
            },
            mac: "52:54:00:aa:bb:cc".into(),
            ipv4_cidr: "10.0.2.15/24".into(),
            ipv4_gateway: "10.0.2.2".into(),
            mtu: 1500,
        };
        assert_eq!(serde_json::to_string(&att).unwrap(), GOLDEN);
        assert_eq!(serde_json::from_str::<NetAttachment>(GOLDEN).unwrap(), att);
        assert!(att.is_tap() && att.is_restricted());
        assert_eq!(att.index(), Some(7));
        let e = serde_json::from_str::<OldAttachment>(GOLDEN).unwrap_err();
        assert!(
            e.to_string().contains("unknown variant `restricted_tap`"),
            "{e}"
        );
        // An unrestricted one is as before.
        let plain = GOLDEN.replace("restricted_tap", "tap");
        assert!(serde_json::from_str::<OldAttachment>(&plain).is_ok());
        assert!(
            !serde_json::from_str::<NetAttachment>(&plain)
                .unwrap()
                .is_restricted()
        );
    }

    /// A flow conntrack still holds from the index's earlier orb (here an unrestricted
    /// one), or from this orb under a wider policy, is not established for a restricted
    /// orb's launch: its packets are decided again and dropped. The orb's own flows go
    /// on across a rebuild of the table with its mark (an agent restart). Real namespaces, veths, NAT and conntrack, in a throwaway user, network
    /// and mount namespace (this test runs itself again inside `unshare -rnm`). Skipped
    /// where that or nft is unavailable, unless `ORBD_TEST_NFT=1` requires it.
    #[cfg(target_os = "linux")]
    #[test]
    fn established_flows_count_only_with_the_launch_mark() {
        const INNER: &str = "ORBD_TEST_CT_INNER";
        if std::env::var_os(INNER).is_none() {
            let probe = Command::new("unshare")
                .args([
                    "-rnm",
                    "sh",
                    "-c",
                    "mount -t tmpfs none /run && nft list ruleset",
                ])
                .output();
            if !probe.is_ok_and(|o| o.status.success()) {
                assert!(
                    std::env::var("ORBD_TEST_NFT").is_err(),
                    "ORBD_TEST_NFT is set but `unshare -rnm` with nft does not work"
                );
                eprintln!("skipped: no unprivileged namespaces with nft");
                return;
            }
            let out = Command::new("unshare")
                .arg("-rnm")
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::vm::net::tests::established_flows_count_only_with_the_launch_mark",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(INNER, "1")
                .output()
                .unwrap();
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                out.status.success() && text.contains("1 passed"),
                "inner test failed:\n{text}"
            );
            return;
        }
        let sh = |script: &str| {
            let o = Command::new("sh").args(["-ec", script]).output().unwrap();
            assert!(
                o.status.success(),
                "{script}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        };
        sh(
            "mount -t tmpfs none /run && mkdir -p /run/netns && ip link set lo up \
            && echo 1 > /proc/sys/net/ipv4/ip_forward \
            && ip netns add inet && ip link add wan0 type veth peer name eth0 netns inet \
            && ip addr add 8.8.8.1/24 dev wan0 && ip link set wan0 up \
            && ip -n inet addr add 8.8.8.8/24 dev eth0 && ip -n inet link set eth0 up \
            && ip -n inet link set lo up",
        );
        // Index 5: 169.254.0.21 (agent side) and .22 (the orb's).
        let make_orb = || {
            sh(
                "ip netns add orb && ip link add orbd5 type veth peer name eth0 netns orb \
                && ip addr add 169.254.0.21/30 dev orbd5 && ip link set orbd5 up \
                && ip -n orb addr add 169.254.0.22/30 dev eth0 && ip -n orb link set eth0 up \
                && ip -n orb link set lo up && ip -n orb route add default via 169.254.0.21",
            )
        };
        nft(&host_table(&Egress::default(), &[], &[])).unwrap();
        let receiver = in_netns("inet", || {
            let s = std::net::UdpSocket::bind("8.8.8.8:9999").map_err(|e| e.to_string())?;
            // How long a dropped datagram is waited for; delivery takes well under 1 ms.
            s.set_read_timeout(Some(std::time::Duration::from_millis(300)))
                .map_err(|e| e.to_string())?;
            Ok(s)
        })
        .unwrap();
        let received = |what: &str| {
            let mut buf = [0u8; 100];
            while let Ok((n, from)) = receiver.recv_from(&mut buf) {
                if &buf[..n] == what.as_bytes() {
                    let _ = receiver.send_to(b"ack", from);
                    return true;
                }
            }
            false
        };
        let send = |port: u16, what: &str| {
            in_netns("orb", || {
                let s =
                    std::net::UdpSocket::bind(("169.254.0.22", port)).map_err(|e| e.to_string())?;
                s.send_to(what.as_bytes(), "8.8.8.8:9999")
                    .map_err(|e| e.to_string())?;
                Ok(())
            })
            .unwrap()
        };
        let agent = Egress::default();
        let nothing = policy(&[], &[], &[]);
        let open = policy(&[], &[], &["udp:8.8.8.0/24"]);
        let restrict = |p: &EgressPolicy, mark: u32| {
            let r = Restricted {
                index: 5,
                policy: p,
                mark,
                opened: &[],
            };
            nft(&restrict_script(&r, &agent, false)).unwrap();
        };

        // An unrestricted orb's flow; its orb is deleted, a restricted one gets the index.
        make_orb();
        send(40000, "unrestricted");
        assert!(received("unrestricted"));
        sh("ip netns del orb");
        // The namespace, and its veth's peer, go away in the background.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while Command::new("ip")
            .args(["link", "show", "orbd5"])
            .output()
            .is_ok_and(|o| o.status.success())
        {
            assert!(std::time::Instant::now() < deadline, "orbd5 stays");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        make_orb();
        restrict(&nothing, 1);
        send(40000, "same tuple");
        assert!(
            !received("same tuple"),
            "a leftover flow passed the restricted chain"
        );
        send(40001, "new tuple");
        assert!(!received("new tuple"));

        // The same orb, first allowed, then narrowed at its next launch.
        restrict(&open, 2);
        send(40002, "allowed");
        assert!(received("allowed"));
        send(40002, "still allowed");
        assert!(received("still allowed"), "its own established flow");
        restrict(&nothing, 3);
        send(40002, "after narrowing");
        assert!(
            !received("after narrowing"),
            "a flow of the wider policy passed"
        );

        // An agent restart: the table is rebuilt from the recorded policy and mark,
        // here without the addresses its set held. The orb's established flow goes on
        // (the same mark); a new one to that address does not (the set is empty); under
        // another mark the old flow is decided again, and dropped.
        let names = policy(&["x.example"], &["udp:9999"], &[]);
        restrict(&names, 4);
        nft(&open_script(5, &[(Ipv4Addr::new(8, 8, 8, 8), 600)])).unwrap();
        send(40003, "resolved");
        assert!(received("resolved"));
        let rebuild = |mark: u32| {
            let r = [Restricted {
                index: 5,
                policy: &names,
                mark,
                opened: &[],
            }];
            nft(&host_table(&agent, &[], &r)).unwrap();
        };
        rebuild(4);
        send(40003, "after the rebuild");
        assert!(
            received("after the rebuild"),
            "a restart cut an established flow"
        );
        send(40004, "new after the rebuild");
        assert!(!received("new after the rebuild"), "the set was emptied");
        rebuild(9);
        send(40003, "under another mark");
        assert!(!received("under another mark"));
    }

    #[test]
    fn rebinding_targets_are_never_opened() {
        for no in [
            "10.0.0.1",
            "172.17.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "100.100.100.100",
            "127.0.0.1",
            "169.254.169.254",
            "169.254.0.1",
            "168.63.129.16",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
        ] {
            assert!(!openable(no.parse().unwrap()), "{no}");
        }
        for yes in [
            "1.1.1.1",
            "34.36.1.1",
            "140.82.112.3",
            "168.63.129.17",
            "100.128.0.1",
        ] {
            assert!(openable(yes.parse().unwrap()), "{yes}");
        }
    }

    /// With the flow log, new orb flows pass a chain that mirrors the decision rules one
    /// for one and only logs; the decision rules are unchanged, and without the flow log
    /// nothing logs.
    #[test]
    fn flow_log_mirrors_the_egress_decision() {
        let dns = ["1.1.1.1".to_string()];
        let mut e = egress(&["udp:192.168.2.201:41641", "tcp:10.0.0.0/8:8000-8100"]);
        let plain = host_table(&e, &dns, &[]);
        assert!(
            !plain.contains("log") && !plain.contains("flowlog"),
            "{plain}"
        );
        e.flow_log = true;
        let t = host_table(&e, &dns, &[]);
        assert_eq!(forward(&t), {
            let mut want = forward(&plain);
            want.splice(5..5, ["ct state new jump flowlog_gate".into()]);
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
        let decisions: Vec<String> = forward(&plain)[5..].to_vec();
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
        // Orb to agent: logged as dropped, through the same gate (as restricted for a
        // restricted orb).
        let input = t.split("chain input {").nth(1).unwrap();
        assert!(
            input.contains(
                "iifname \"orbd*\" ip saddr != @egress_orbs ct state new jump flowlog_input"
            ),
            "{input}"
        );
        assert!(
            input.contains(
                "iifname \"orbd*\" ip saddr @egress_orbs ct state new jump flowlog_restricted_drop"
            ),
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
            let t = host_table(&e, &["1.1.1.1".into()], &[]);
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
        let ns = ns_table("10.0.2.0/24", None);
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
        assert!(!ns.contains("dnat"));
        // A restricted orb's guest asks its gateway; the namespace sends that to the
        // proxy, and nothing else.
        let ns = ns_table("10.0.2.0/24", Some("10.0.2.2"));
        assert!(ns.contains(
            r#"iifname "tap0" ip daddr 10.0.2.2 meta l4proto { tcp, udp } th dport 53 dnat to 169.254.0.1"#
        ));
        assert_eq!(ns.matches("dnat").count(), 1);
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
