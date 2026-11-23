//! Egress rules: the private destinations an agent lets every VM orb reach
//! ([`EgressRule`], `ORBD_EGRESS_ALLOW`), and an orb type's restricted egress policy
//! ([`EgressPolicy`], `egress:` in `orb_types`).
//!
//! An orb whose type has a policy reaches nothing but what the policy lists: names that
//! match its `domains` (as the agent's DNS proxy resolved them, on its `ports`), the
//! addresses its `allow` rules name, and the proxy itself. The policy is part of the
//! orb's spec, so it travels from the coordinator to the agent with every command; see
//! `runtime::vm::egress` for how agents enforce it.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Most `domains` one policy may list.
pub const MAX_DOMAINS: usize = 256;
/// Most `allow` rules one policy may list.
pub const MAX_ALLOW: usize = 64;
/// Most `ports` entries one policy may list.
pub const MAX_PORTS: usize = 16;
/// The ports allowlisted domains are reached on when a policy names none.
pub const DEFAULT_PORTS: [&str; 1] = ["tcp:443"];

fn mask(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EgressProto {
    Tcp,
    Udp,
    /// Every protocol; with ports, TCP or UDP to them.
    Any,
}

/// One allowed destination: `<proto>:<address or CIDR>[:<ports>]`, e.g.
/// `udp:192.168.2.201:41641` (Tailscale to a LAN host), `tcp:10.0.0.0/8:8000-8100`,
/// `any:192.168.2.0/24` (every protocol and port). `proto` is tcp, udp or any; ports are
/// one port or a range, every port without them. Prefixes shorter than /8 (and `*`) are
/// refused, as is link-local (cloud metadata).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

/// `<port>` or `<low>-<high>`, 1-65535.
fn port_range(p: &str) -> Option<(u16, u16)> {
    let (a, b) = p.split_once('-').unwrap_or((p, p));
    let (a, b): (u16, u16) = (a.parse().ok()?, b.parse().ok()?);
    (a != 0 && a <= b).then_some((a, b))
}

impl std::str::FromStr for EgressRule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = |why: &str| {
            format!(
                "{s:?}: {why} (expected <tcp|udp|any>:<address or CIDR>[:<port or range>], \
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
            "any" => EgressProto::Any,
            _ => return Err(bad("protocol must be tcp, udp or any")),
        };
        if addr == "*" {
            return Err(bad(
                "`*` would allow every private destination: list the ones orbs need",
            ));
        }
        let (ip, prefix) = match addr.split_once('/') {
            Some((ip, p)) => (ip, p.parse::<u8>().map_err(|_| bad("bad prefix"))?),
            None => (addr, 32),
        };
        let net: Ipv4Addr = ip.parse().map_err(|_| bad("bad IPv4 address"))?;
        if prefix > 32 {
            return Err(bad("prefix above /32"));
        }
        if prefix < 8 {
            return Err(bad(
                "prefixes shorter than /8 are refused: list the private ranges orbs need",
            ));
        }
        if u32::from(net) & !mask(prefix) != 0 {
            return Err(bad("host bits are set"));
        }
        let link_local = Ipv4Addr::new(169, 254, 0, 0);
        let m = mask(prefix.min(16));
        if u32::from(net) & m == u32::from(link_local) & m {
            return Err(bad("link-local (cloud metadata) is never allowed"));
        }
        let ports = match ports {
            None | Some("") | Some("*") => None,
            Some(p) => {
                Some(port_range(p).ok_or_else(|| bad("ports must be 1-65535, low to high"))?)
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

/// Domains below which anyone can have names that the Public Suffix List does not name as
/// such (it lists other levels of them, or nothing): shared hosting and storage of large
/// providers. A wildcard right over one is refused, like one over a public suffix.
pub const SHARED_NOT_IN_PSL: &[&str] = &[
    "amazonaws.com",
    "on.aws",
    "core.windows.net",
    "storage.googleapis.com",
    "googleusercontent.com",
    "fastly.net",
    "b-cdn.net",
    "r2.cloudflarestorage.com",
    "cloudflarestorage.com",
    "github.dev",
    "app.github.dev",
    "netlify.com",
    "herokudns.com",
    "glitch.me",
    "wordpress.com",
    "squarespace.com",
];

/// Whether `name` is a public suffix of the Public Suffix List (its private section
/// included), as compiled into this build.
fn public_suffix(name: &str) -> bool {
    psl::suffix(name.as_bytes()).is_some_and(|s| s.as_bytes() == name.as_bytes())
}

/// An allowlisted name: `example.com` (that name only) or `*.example.com` (every name
/// below it, not `example.com` itself). Lowercase, without the trailing dot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DomainPattern {
    name: String,
    wildcard: bool,
}

impl DomainPattern {
    /// Refuses a wildcard over a suffix under which anyone can have names: a public
    /// suffix of the Public Suffix List (private section included, e.g. `co.uk`,
    /// `github.io`, `s3.us-east-1.amazonaws.com`), a name with public suffixes right
    /// below it (a `*.` rule of the list, e.g. `compute.amazonaws.com`), or one of
    /// [`SHARED_NOT_IN_PSL`]. Checked when orbd.yaml is loaded, never when a recorded or
    /// sent policy is read, so a list update never makes those unreadable.
    pub fn check_shared(&self) -> Result<(), String> {
        let base = &self.name;
        let shared = self.wildcard
            && (public_suffix(base)
                || public_suffix(&format!("orbd-probe.{base}"))
                || SHARED_NOT_IN_PSL.contains(&base.as_str()));
        match shared {
            false => Ok(()),
            true => Err(format!(
                "{self}: a wildcard over a suffix anyone can have names under (a public \
                 suffix or shared hosting) would allow every site there; list the names"
            )),
        }
    }

    /// Whether `name` (lowercase, no trailing dot, as [`normalize_name`] gives it)
    /// matches.
    pub fn matches(&self, name: &str) -> bool {
        if !self.wildcard {
            return name == self.name;
        }
        name.len() > self.name.len() + 1
            && name.ends_with(&self.name)
            && name.as_bytes()[name.len() - self.name.len() - 1] == b'.'
    }
}

impl std::fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.wildcard {
            f.write_str("*.")?;
        }
        f.write_str(&self.name)
    }
}

/// `name` in lowercase without one trailing dot, if it is a hostname: labels of 1-63
/// letters, digits, `-` (not first or last) and `_`, at most 253 characters.
pub fn normalize_name(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    for label in name.split('.') {
        let b = label.as_bytes();
        if b.is_empty()
            || b.len() > 63
            || b[0] == b'-'
            || b[b.len() - 1] == b'-'
            || !b
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        {
            return None;
        }
    }
    Some(name.to_ascii_lowercase())
}

impl std::str::FromStr for DomainPattern {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = |why: &str| {
            format!(
                "{s:?}: {why} (expected a name such as example.com, or *.example.com for every \
                 name below it)"
            )
        };
        let s = s.trim();
        let (wildcard, rest) = match s.strip_prefix("*.") {
            Some(r) => (true, r),
            None => (false, s),
        };
        if rest.contains('*') {
            return Err(bad("`*` may only be the whole first label"));
        }
        let name = normalize_name(rest).ok_or_else(|| {
            bad("not a hostname (letters, digits, - and _; internationalized names in punycode)")
        })?;
        let labels = name.split('.').count();
        if labels < 2 {
            return Err(bad(if wildcard {
                "a wildcard needs a name of at least two labels below it, not a top-level domain"
            } else {
                "a fully qualified name with at least two labels"
            }));
        }
        if name.parse::<Ipv4Addr>().is_ok() || name.split('.').all(|l| l.parse::<u32>().is_ok()) {
            return Err(bad("an address, not a name: list addresses in `allow`"));
        }
        Ok(Self { name, wildcard })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PortProto {
    Tcp,
    Udp,
}

impl PortProto {
    pub fn as_str(self) -> &'static str {
        match self {
            PortProto::Tcp => "tcp",
            PortProto::Udp => "udp",
        }
    }
}

/// Where allowlisted domains are reached: `tcp:443`, `udp:443`, `tcp:8000-8100`
/// (`tcp:1-65535` for every TCP port).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortRule {
    pub proto: PortProto,
    /// Inclusive.
    pub ports: (u16, u16),
}

impl std::fmt::Display for PortRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (a, b) = self.ports;
        match a == b {
            true => write!(f, "{}:{a}", self.proto.as_str()),
            false => write!(f, "{}:{a}-{b}", self.proto.as_str()),
        }
    }
}

impl std::str::FromStr for PortRule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad =
            |why: &str| format!("{s:?}: {why} (expected <tcp|udp>:<port or range>, e.g. tcp:443)");
        let (proto, ports) = s.trim().split_once(':').ok_or_else(|| bad("no port"))?;
        let proto = match proto.to_ascii_lowercase().as_str() {
            "tcp" => PortProto::Tcp,
            "udp" => PortProto::Udp,
            _ => return Err(bad("protocol must be tcp or udp")),
        };
        let ports = port_range(ports).ok_or_else(|| bad("ports must be 1-65535, low to high"))?;
        Ok(Self { proto, ports })
    }
}

/// An orb type's restricted egress (see the module docs). Validated when it is built,
/// whether from `orbd.yaml`, a recorded spec or the wire; serialized as the strings it
/// was written as, `ports` always explicit.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawEgressPolicy", into = "RawEgressPolicy")]
pub struct EgressPolicy {
    pub domains: Vec<DomainPattern>,
    pub ports: Vec<PortRule>,
    pub allow: Vec<EgressRule>,
}

/// `egress:` as written: `domains`, `ports` (default `[tcp:443]`) and `allow`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEgressPolicy {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ports: Option<Vec<String>>,
    #[serde(default)]
    pub allow: Vec<String>,
}

impl TryFrom<RawEgressPolicy> for EgressPolicy {
    type Error = String;

    fn try_from(r: RawEgressPolicy) -> Result<Self, String> {
        let ports = r
            .ports
            .unwrap_or_else(|| DEFAULT_PORTS.map(String::from).to_vec());
        Self::from_parts(&r.domains, &ports, &r.allow)
    }
}

impl From<EgressPolicy> for RawEgressPolicy {
    fn from(p: EgressPolicy) -> Self {
        let (domains, ports, allow) = p.parts();
        Self {
            domains,
            ports: Some(ports),
            allow,
        }
    }
}

impl EgressPolicy {
    /// From its three lists (ports explicit), validated: well-formed entries, none
    /// twice, within [`MAX_DOMAINS`], [`MAX_PORTS`] and [`MAX_ALLOW`].
    pub fn from_parts(
        domains: &[String],
        ports: &[String],
        allow: &[String],
    ) -> Result<Self, String> {
        if domains.len() > MAX_DOMAINS {
            return Err(format!("egress.domains: more than {MAX_DOMAINS}"));
        }
        if ports.len() > MAX_PORTS {
            return Err(format!("egress.ports: more than {MAX_PORTS}"));
        }
        if allow.len() > MAX_ALLOW {
            return Err(format!("egress.allow: more than {MAX_ALLOW}"));
        }
        fn parse<T: std::str::FromStr<Err = String> + PartialEq + std::fmt::Display>(
            what: &str,
            items: &[String],
        ) -> Result<Vec<T>, String> {
            let mut out: Vec<T> = Vec::with_capacity(items.len());
            for i in items {
                let v: T = i.parse().map_err(|e| format!("egress.{what}: {e}"))?;
                if out.contains(&v) {
                    return Err(format!("egress.{what}: {v} is listed twice"));
                }
                out.push(v);
            }
            Ok(out)
        }
        let policy = Self {
            domains: parse("domains", domains)?,
            ports: parse("ports", ports)?,
            allow: parse("allow", allow)?,
        };
        if !policy.domains.is_empty() && policy.ports.is_empty() {
            return Err("egress.ports is empty: allowlisted domains would be unreachable".into());
        }
        Ok(policy)
    }

    /// What only orbd.yaml is held to (see [`DomainPattern::check_shared`]).
    pub fn check_config(&self) -> Result<(), String> {
        for d in &self.domains {
            d.check_shared()
                .map_err(|e| format!("egress.domains: {e}"))?;
        }
        Ok(())
    }

    /// The three lists as strings: what [`Self::from_parts`] takes.
    pub fn parts(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        (
            self.domains.iter().map(|d| d.to_string()).collect(),
            self.ports.iter().map(|p| p.to_string()).collect(),
            self.allow.iter().map(|r| r.to_string()).collect(),
        )
    }

    /// Whether `name` (normalized, see [`normalize_name`]) is allowlisted.
    pub fn allows_name(&self, name: &str) -> bool {
        self.domains.iter().any(|d| d.matches(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(
        domains: &[&str],
        ports: Option<&[&str]>,
        allow: &[&str],
    ) -> Result<EgressPolicy, String> {
        let s = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        EgressPolicy::try_from(RawEgressPolicy {
            domains: s(domains),
            ports: ports.map(s),
            allow: s(allow),
        })
    }

    #[test]
    fn domains_match_exactly_or_below_a_wildcard() {
        let p = policy(&["ampcode.com", "*.ampcode.com", "GitHub.com."], None, &[]).unwrap();
        for yes in [
            "ampcode.com",
            "static.ampcode.com",
            "a.b.ampcode.com",
            "github.com",
        ] {
            assert!(p.allows_name(yes), "{yes}");
        }
        for no in [
            "evilampcode.com",
            "ampcode.com.evil",
            "xampcode.com",
            "api.github.com",
            "com",
            "",
            ".ampcode.com",
        ] {
            assert!(!p.allows_name(no), "{no}");
        }
        assert_eq!(p.domains[2].to_string(), "github.com", "normalized");
        assert_eq!(p.ports, vec!["tcp:443".parse().unwrap()], "default ports");
        assert_eq!(
            normalize_name("Static.AmpCode.com."),
            Some("static.ampcode.com".into())
        );
        assert_eq!(normalize_name("a..b"), None);
        assert_eq!(normalize_name("a b.com"), None);
        assert_eq!(normalize_name(&format!("{}.com", "a".repeat(64))), None);
    }

    #[test]
    fn policies_are_validated() {
        for bad in [
            "*",
            "*.com",
            "com",
            "foo.*.com",
            "*foo.com",
            "**.foo.com",
            "1.2.3.4",
            "10.0.0.1",
            "-a.com",
            "a-.com",
            "a_b.c\u{e9}.com",
            "exa mple.com",
            "",
        ] {
            assert!(policy(&[bad], None, &[]).is_err(), "{bad:?}");
        }
        assert!(
            policy(&["a.com", "A.com."], None, &[])
                .unwrap_err()
                .contains("twice")
        );
        for bad in [
            "tcp",
            "tcp:0",
            "tcp:2-1",
            "icmp:1",
            "any:443",
            "tcp:70000",
            "tcp:*",
        ] {
            assert!(policy(&["a.com"], Some(&[bad]), &[]).is_err(), "{bad:?}");
        }
        assert!(
            policy(&["a.com"], Some(&[]), &[])
                .unwrap_err()
                .contains("ports is empty")
        );
        // Without domains, no ports are needed: an address-only (or empty) policy.
        assert!(policy(&[], Some(&[]), &["tcp:203.0.113.0/24:443"]).is_ok());
        assert!(policy(&[], None, &[]).is_ok());
        for bad in [
            "tcp:0.0.0.0/0",
            "any:169.254.169.254",
            "tcp:10.0.0.1/8",
            "x:1.2.3.4",
        ] {
            assert!(policy(&[], None, &[bad]).is_err(), "{bad:?}");
        }
        let many: Vec<String> = (0..=MAX_DOMAINS)
            .map(|i| format!("h{i}.example.com"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(policy(&many, None, &[]).unwrap_err().contains("more than"));
        let ok = &many[..MAX_DOMAINS];
        assert_eq!(policy(ok, None, &[]).unwrap().domains.len(), MAX_DOMAINS);
    }

    #[test]
    fn serializes_as_written_with_explicit_ports() {
        let p = policy(
            &["ampcode.com", "*.ampcode.com"],
            None,
            &["tcp:203.0.113.0/24:443", "udp:192.0.2.1"],
        )
        .unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(
            json,
            r#"{"domains":["ampcode.com","*.ampcode.com"],"ports":["tcp:443"],"allow":["tcp:203.0.113.0/24:443","udp:192.0.2.1"]}"#
        );
        assert_eq!(serde_json::from_str::<EgressPolicy>(&json).unwrap(), p);
        // Recorded specs are checked again when read.
        assert!(serde_json::from_str::<EgressPolicy>(r#"{"domains":["*"]}"#).is_err());
        assert!(serde_json::from_str::<EgressPolicy>(r#"{"domain":[]}"#).is_err());
    }

    /// Wildcards over public suffixes (the Public Suffix List's, private section
    /// included) and well-known shared hosting are refused for orbd.yaml, never when a
    /// recorded or sent policy is read.
    #[test]
    fn wildcards_over_shared_suffixes_are_refused_in_config_only() {
        for shared in [
            "*.co.uk",
            "*.workers.dev",
            "*.GitHub.io",
            "*.s3.us-east-1.amazonaws.com",
            "*.ts.net",
            "*.us.com",
            "*.compute.amazonaws.com",
            "*.foo.ck",
            "*.app.github.dev",
            "*.r2.cloudflarestorage.com",
            "*.amazonaws.com",
            "*.storage.googleapis.com",
            "*.googleapis.com",
            "*.xn--4it168d.jp",
        ] {
            // Read as a recorded or sent policy: fine.
            let p = policy(&[shared], None, &[]).unwrap();
            let e = p.check_config().unwrap_err();
            assert!(e.contains("anyone can have names"), "{shared}: {e}");
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(serde_json::from_str::<EgressPolicy>(&json).unwrap(), p);
        }
        for fine in [
            "*.example.co.uk",
            "my.workers.dev",
            "*.ampcode.com",
            "*.cdn.orbd.test",
            "*.mybucket.s3.amazonaws.com",
            "co.uk.example.com",
        ] {
            let p = policy(&[fine], None, &[]).unwrap();
            assert_eq!(p.check_config(), Ok(()), "{fine}");
        }
        for s in SHARED_NOT_IN_PSL {
            assert_eq!(normalize_name(s).as_deref(), Some(*s), "{s}");
            assert!(s.contains('.'), "{s}");
        }
    }
}
