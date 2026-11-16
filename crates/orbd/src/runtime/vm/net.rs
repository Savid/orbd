//! Agent-local network attachment for one VM, chosen when the orb's disk is created and
//! persisted in its recipe; a sleeping VM is always restored with the attachment (and
//! MAC) it was saved with. Guests see the agent's guest network as it was when the orb
//! was created (default `10.0.2.15/24` via `10.0.2.2`), applied by the guest helper from
//! `Wake.network`.
//!
//! * `User`: QEMU's built-in slirp. No host privileges, guest-initiated traffic only.
//! * `Tap`: a per-orb network namespace `orbd-<orb>` holding the VM's `tap0`
//!   (the guest's gateway, e.g. `10.0.2.2/24`) and one end of a veth pair; the other
//!   end, `orbd<i>`, sits in the agent's namespace with a `/30` from `169.254.0.0/16`
//!   (`i` is a durable per-host index). The namespace masquerades the guest behind its
//!   veth address and the agent's namespace masquerades that onwards, so guests share
//!   addresses and only leave through NAT. nftables table `inet orbd` drops orb → agent
//!   traffic (except replies), orb ↔ orb forwarding, IPv6, packets conntrack cannot
//!   track or that did not come through an orb's namespace (they would leave un-NATed,
//!   e.g. with a spoofed source), cloud metadata, and orb → private destinations (the
//!   LAN, a tailnet, ...) that the agent's [`Egress`] does not allow. The VMM runs inside
//!   the namespace and sees nothing but its TAP.
//!
//! `Tap` is built with `ip` and `nft` run with fixed arguments; every step is
//! idempotent, so `adopt` repairs what is missing (after a host reboot) without touching
//! what a running VMM uses.

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
    /// retry after a crash finds it again) and builds the orb's namespace. Undone by
    /// [`release`].
    pub fn tap(orb: OrbId, state_dir: &Path, network: GuestNetwork) -> Result<Self, String> {
        let index = allocate(&state_dir.join("net"), orb)?;
        let att = Self::with_backend(
            orb,
            network,
            NetBackend::Tap {
                netns: format!("orbd-{orb}"),
                index,
            },
        );
        att.adopt()?;
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
    /// missing.
    pub fn adopt(&self) -> Result<(), String> {
        match &self.backend {
            NetBackend::User => Ok(()),
            NetBackend::Tap { netns, index } => {
                let (_, prefix) = self.subnet()?;
                build_namespace(netns, *index, &format!("{}/{prefix}", self.ipv4_gateway))
            }
        }
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

/// Enables forwarding in the agent's namespace and installs orbd's nftables table
/// (replaced atomically; nothing else is touched). Run once before any `Tap` VM starts.
pub fn prepare_host(egress: &Egress, dns_servers: &[String]) -> Result<(), String> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| format!("enabling IPv4 forwarding: {e}"))?;
    nft(&host_table(egress, dns_servers))?;
    if egress.allow_private {
        tracing::warn!(
            "Firecracker orbs may reach every private destination, the host's LAN included \
             (ORBD_ALLOW_PRIVATE_EGRESS)"
        );
    } else {
        let allowed: Vec<String> = egress.allow.iter().map(|r| r.to_string()).collect();
        tracing::info!(
            allowed = %allowed.join(","),
            dns = %dns_servers.join(","),
            "Firecracker orbs reach the internet, their DNS servers and only these private \
             destinations (more with ORBD_EGRESS_ALLOW)"
        );
    }
    Ok(())
}

/// orbd's nftables table for `egress`: see the module docs.
fn host_table(egress: &Egress, dns_servers: &[String]) -> String {
    let mut rules = String::new();
    let mut rule = |r: String| {
        rules.push_str("        iifname \"orbd*\" ");
        rules.push_str(&r);
        rules.push('\n');
    };
    // Orbs resolve through the agent's DNS servers, wherever those are (a link-local
    // resolver too, so before ALWAYS_BLOCKED).
    for d in dns_servers
        .iter()
        .filter_map(|d| d.parse::<std::net::Ipv4Addr>().ok())
    {
        rule(format!(
            "ip daddr {d} meta l4proto {{ tcp, udp }} th dport 53 accept comment \"dns\""
        ));
    }
    rule(format!("ip daddr {{ {} }} drop", ALWAYS_BLOCKED.join(", ")));
    if !egress.allow_private {
        for r in &egress.allow {
            let net = format!("{}/{}", r.net, r.prefix);
            let ports = r.ports.map(|(a, b)| match a == b {
                true => a.to_string(),
                false => format!("{a}-{b}"),
            });
            let what = match (r.proto, ports) {
                (EgressProto::Tcp, Some(p)) => format!("tcp dport {p} "),
                (EgressProto::Udp, Some(p)) => format!("udp dport {p} "),
                (EgressProto::Any, Some(p)) => format!("meta l4proto {{ tcp, udp }} th dport {p} "),
                (EgressProto::Tcp, None) => "meta l4proto tcp ".into(),
                (EgressProto::Udp, None) => "meta l4proto udp ".into(),
                (EgressProto::Any, None) => String::new(),
            };
            rule(format!("ip daddr {net} {what}accept comment \"{r}\""));
        }
        rule(format!("ip daddr {{ {} }} drop", PRIVATE_NETS.join(", ")));
    }
    format!(
        r#"table inet orbd
delete table inet orbd
table inet orbd {{
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "orbd*" ct state established,related accept
        iifname "orbd*" drop
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname "orbd*" meta nfproto ipv6 drop
        iifname "orbd*" ct state invalid,untracked drop
        iifname "orbd*" ip saddr != 169.254.0.0/16 drop
        iifname "orbd*" oifname "orbd*" drop
{rules}    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        iifname "orbd*" oifname != "orbd*" masquerade
    }}
}}
"#
    )
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

/// `gateway` is the TAP's address, e.g. `10.0.2.2/24`.
fn build_namespace(netns: &str, index: u32, gateway: &str) -> Result<(), String> {
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
    if !exists(&["-n", netns, "link", "show", TAP]) {
        ip(&["-n", netns, "tuntap", "add", "dev", TAP, "mode", "tap"])?;
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
        nft(r#"table ip orbd
delete table ip orbd
table ip orbd {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" masquerade
    }
}
"#)
    })
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
        for e in [
            egress(&[]),
            egress(&[
                "udp:192.168.2.201:41641",
                "any:10.1.0.0/16:80-90",
                "tcp:172.16.0.0/12",
                "udp:10.0.0.0/8",
            ]),
            Egress::new(true, &[]).unwrap(),
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
        }
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
