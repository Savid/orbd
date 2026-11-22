//! DNS messages (RFC 1035) as far as the egress proxy ([`super::egress`]) needs them:
//! queries from orbs, A queries to the agent's upstream servers and their answers, and
//! the answers it builds for orbs. Everything read is untrusted: lengths, counts and
//! compression pointers are bounds-checked, pointers must go strictly backwards (so
//! they cannot loop), names are at most 255 bytes, and a malformed message is an error,
//! never a panic. Answers to orbs are built afresh from what was checked, never relayed.

use std::net::Ipv4Addr;

pub const HEADER: usize = 12;
pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_OPT: u16 = 41;
pub const CLASS_IN: u16 = 1;

pub const NOERROR: u8 = 0;
pub const FORMERR: u8 = 1;
pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;
pub const NOTIMP: u8 = 4;
pub const REFUSED: u8 = 5;

const QR: u16 = 0x8000;
const TC: u16 = 0x0200;
const RD: u16 = 0x0100;
const RA: u16 = 0x0080;

/// Longest name on the wire.
const MAX_NAME: usize = 255;
/// Most compression pointers followed in one name.
const MAX_POINTERS: usize = 32;
/// Most answer records read from one response.
pub const MAX_ANSWERS: usize = 256;
/// Most CNAMEs followed from the queried name.
pub const MAX_CHAIN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn parse(msg: &[u8]) -> Option<Self> {
        let w = |i: usize| Some(u16::from_be_bytes(msg.get(i..i + 2)?.try_into().ok()?));
        Some(Self {
            id: w(0)?,
            flags: w(2)?,
            qdcount: w(4)?,
            ancount: w(6)?,
            nscount: w(8)?,
            arcount: w(10)?,
        })
    }

    pub fn response(&self) -> bool {
        self.flags & QR != 0
    }

    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xf) as u8
    }

    pub fn truncated(&self) -> bool {
        self.flags & TC != 0
    }

    pub fn rcode(&self) -> u8 {
        (self.flags & 0xf) as u8
    }

    fn write(&self, out: &mut Vec<u8>) {
        for w in [
            self.id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        ] {
            out.extend_from_slice(&w.to_be_bytes());
        }
    }
}

/// A name as received: its labels, case kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    /// Lowercase and dotted, without the trailing dot, if every label is a hostname
    /// label (letters, digits, `-`, `_`): the only names the proxy acts on.
    pub fn text(&self) -> Option<String> {
        if self.labels.is_empty() {
            return None;
        }
        let mut out = String::new();
        for (i, l) in self.labels.iter().enumerate() {
            if !l
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
            {
                return None;
            }
            if i > 0 {
                out.push('.');
            }
            out.push_str(&String::from_utf8_lossy(l).to_ascii_lowercase());
        }
        crate::model::egress::normalize_name(&out)
    }

    fn write(&self, out: &mut Vec<u8>) {
        for l in &self.labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l);
        }
        out.push(0);
    }
}

/// Reads the name at `start`: the name and where what follows it begins.
pub fn read_name(msg: &[u8], start: usize) -> Result<(Name, usize), &'static str> {
    let mut labels = Vec::new();
    let mut pos = start;
    // Where the name continues after its first pointer; pointers must point before the
    // previous one (and before the name), so they cannot loop.
    let mut after: Option<usize> = None;
    let mut limit = start;
    let mut wire = 1;
    let mut pointers = 0;
    loop {
        let len = *msg.get(pos).ok_or("truncated name")? as usize;
        match len & 0xc0 {
            0x00 if len == 0 => {
                pos += 1;
                break;
            }
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + len).ok_or("truncated label")?;
                wire += 1 + len;
                if wire > MAX_NAME {
                    return Err("name longer than 255 bytes");
                }
                labels.push(label.to_vec());
                pos += 1 + len;
            }
            0xc0 => {
                let low = *msg.get(pos + 1).ok_or("truncated pointer")? as usize;
                let target = ((len & 0x3f) << 8) | low;
                if after.is_none() {
                    after = Some(pos + 2);
                }
                pointers += 1;
                if target < HEADER || target >= limit.min(pos) || pointers > MAX_POINTERS {
                    return Err("bad compression pointer");
                }
                limit = target;
                pos = target;
            }
            _ => return Err("unsupported label type"),
        }
    }
    Ok((Name { labels }, after.unwrap_or(pos)))
}

fn u16_at(msg: &[u8], i: usize) -> Result<u16, &'static str> {
    msg.get(i..i + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or("truncated")
}

fn u32_at(msg: &[u8], i: usize) -> Result<u32, &'static str> {
    msg.get(i..i + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or("truncated")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    pub qclass: u16,
}

fn read_question(msg: &[u8], pos: usize) -> Result<(Question, usize), &'static str> {
    let (name, pos) = read_name(msg, pos)?;
    let q = Question {
        name,
        qtype: u16_at(msg, pos)?,
        qclass: u16_at(msg, pos + 2)?,
    };
    Ok((q, pos + 4))
}

/// A query from an orb.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub header: Header,
    pub question: Question,
    /// The UDP payload size the client advertised with EDNS (version 0), if it did.
    pub edns: Option<u16>,
}

/// Largest UDP answer to an EDNS client (DNS Flag Day 2020); without EDNS, 512 bytes.
pub const MAX_EDNS: u16 = 1232;

impl Query {
    /// How large a UDP answer to this query may be.
    pub fn udp_limit(&self) -> usize {
        usize::from(self.edns.map_or(512, |s| s.clamp(512, MAX_EDNS)))
    }
}

/// The UDP size of an EDNS (version 0) OPT record in the records after a query's
/// question at `pos`, if there is one; anything malformed there is ignored (no EDNS).
fn read_edns(msg: &[u8], mut pos: usize, h: &Header) -> Option<u16> {
    let skip = usize::from(h.ancount) + usize::from(h.nscount);
    let total = skip + usize::from(h.arcount);
    if total > 8 {
        return None;
    }
    for i in 0..total {
        let (name, at) = read_name(msg, pos).ok()?;
        let rtype = u16_at(msg, at).ok()?;
        let class = u16_at(msg, at + 2).ok()?;
        let ttl = u32_at(msg, at + 4).ok()?;
        let len = usize::from(u16_at(msg, at + 8).ok()?);
        let end = at + 10 + len;
        if end > msg.len() {
            return None;
        }
        if i >= skip && rtype == TYPE_OPT && name.labels.is_empty() {
            // Extended rcode, version, flags: only version 0 is understood.
            return (ttl >> 16 & 0xff == 0).then_some(class);
        }
        pos = end;
    }
    None
}

/// Why a message from an orb gets no normal answer.
#[derive(Debug, PartialEq, Eq)]
pub enum QueryError {
    /// Not a query (or too short to answer): no reply at all.
    Ignore,
    /// A malformed query: FORMERR to this header.
    Malformed(Header),
}

/// Reads a query: one question; whatever follows it (e.g. EDNS) is ignored.
pub fn parse_query(msg: &[u8]) -> Result<Query, QueryError> {
    let header = Header::parse(msg).ok_or(QueryError::Ignore)?;
    if header.response() {
        return Err(QueryError::Ignore);
    }
    if header.qdcount != 1 {
        return Err(QueryError::Malformed(header));
    }
    let (question, end) = read_question(msg, HEADER).map_err(|_| QueryError::Malformed(header))?;
    let edns = read_edns(msg, end, &header);
    Ok(Query {
        header,
        question,
        edns,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Cname(Name),
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: u16,
    pub class: u16,
    /// Seconds; a TTL with the top bit set counts as 0 (RFC 2181).
    pub ttl: u32,
    pub data: RData,
}

fn read_record(msg: &[u8], pos: usize) -> Result<(Record, usize), &'static str> {
    let (name, pos) = read_name(msg, pos)?;
    let rtype = u16_at(msg, pos)?;
    let class = u16_at(msg, pos + 2)?;
    let ttl = u32_at(msg, pos + 4)?;
    let ttl = if ttl & 0x8000_0000 != 0 { 0 } else { ttl };
    let len = u16_at(msg, pos + 8)? as usize;
    let start = pos + 10;
    let end = start + len;
    let rdata = msg.get(start..end).ok_or("truncated record data")?;
    let data = match (rtype, class) {
        (TYPE_A, CLASS_IN) => {
            let b: [u8; 4] = rdata.try_into().map_err(|_| "A record of the wrong size")?;
            RData::A(Ipv4Addr::from(b))
        }
        (TYPE_CNAME, CLASS_IN) => {
            // The name may point back into the message, but its own bytes are the data.
            let (target, after) = read_name(&msg[..end], start)?;
            if after != end {
                return Err("CNAME data longer than its name");
            }
            RData::Cname(target)
        }
        _ => RData::Other,
    };
    Ok((
        Record {
            name,
            rtype,
            class,
            ttl,
            data,
        },
        end,
    ))
}

/// A response from an upstream server: its question and answer records (authority and
/// additional records are not read).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub header: Header,
    pub question: Question,
    pub answers: Vec<Record>,
}

pub fn parse_response(msg: &[u8]) -> Result<Response, &'static str> {
    let header = Header::parse(msg).ok_or("shorter than a header")?;
    if !header.response() {
        return Err("not a response");
    }
    if header.qdcount != 1 {
        return Err("not one question");
    }
    if usize::from(header.ancount) > MAX_ANSWERS {
        return Err("too many answers");
    }
    let (question, mut pos) = read_question(msg, HEADER)?;
    let mut answers = Vec::with_capacity(header.ancount.into());
    for _ in 0..header.ancount {
        let (r, next) = read_record(msg, pos)?;
        answers.push(r);
        pos = next;
    }
    Ok(Response {
        header,
        question,
        answers,
    })
}

impl Response {
    /// Whether this answers `id`'s query for `name` (normalized) of `qtype`.
    pub fn answers_query(&self, id: u16, name: &str, qtype: u16) -> bool {
        self.header.id == id
            && self.header.opcode() == 0
            && self.question.qtype == qtype
            && self.question.qclass == CLASS_IN
            && self.question.name.text().as_deref() == Some(name)
    }
}

/// Appends `name` (normalized text) in wire form.
fn write_text_name(out: &mut Vec<u8>, name: &str) {
    for l in name.split('.').filter(|l| !l.is_empty()) {
        let l = &l.as_bytes()[..l.len().min(63)];
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    out.push(0);
}

/// A recursive query for `name` (normalized) of `qtype`, with an EDNS OPT record
/// advertising `edns_size` bytes over UDP if given.
pub fn build_query(id: u16, name: &str, qtype: u16, edns_size: Option<u16>) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    Header {
        id,
        flags: RD,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: u16::from(edns_size.is_some()),
    }
    .write(&mut out);
    write_text_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    if let Some(size) = edns_size {
        out.push(0); // root
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // extended rcode, flags, no data
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnswerData {
    A(Ipv4Addr),
    Cname(String),
}

/// One record of an answer to an orb; names normalized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub name: String,
    pub ttl: u32,
    pub data: AnswerData,
}

/// Writes names with compression: suffixes already written (lowercase) and where.
struct Names {
    at: Vec<(String, u16)>,
}

impl Names {
    fn write(&mut self, out: &mut Vec<u8>, name: &str) {
        let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".");
            if let Some((_, off)) = self.at.iter().find(|(s, _)| *s == suffix) {
                out.extend_from_slice(&(0xc000 | off).to_be_bytes());
                return;
            }
            if out.len() < 0x3fff {
                self.at.push((suffix, out.len() as u16));
            }
            let l = &labels[i].as_bytes()[..labels[i].len().min(63)];
            out.push(l.len() as u8);
            out.extend_from_slice(l);
        }
        out.push(0);
    }
}

/// The answer to `query` with `rcode` and `answers` (in order), at most `limit` bytes:
/// as many records as fit, with TC set if any did not, so the orb can ask again over
/// TCP. An EDNS query gets an OPT record back (advertising [`MAX_EDNS`]).
pub fn build_response(query: &Query, rcode: u8, answers: &[Answer], limit: usize) -> Vec<u8> {
    let mut flags = QR | (query.header.flags & RD) | RA | u16::from(rcode & 0xf);
    let opt = query.edns.is_some();
    // Room kept for the OPT record: root name, type, class, TTL, length.
    let reserve = if opt { 11 } else { 0 };
    let mut out = Vec::with_capacity(512);
    out.resize(HEADER, 0);
    query.question.name.write(&mut out);
    out.extend_from_slice(&query.question.qtype.to_be_bytes());
    out.extend_from_slice(&query.question.qclass.to_be_bytes());
    let mut names = Names { at: Vec::new() };
    if let Some(q) = query.question.name.text() {
        names.at.push((q, HEADER as u16));
    }
    let mut count: u16 = 0;
    for a in answers {
        let before = out.len();
        names.write(&mut out, &a.name);
        let rtype = match &a.data {
            AnswerData::A(_) => TYPE_A,
            AnswerData::Cname(_) => TYPE_CNAME,
        };
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&a.ttl.min(0x7fff_ffff).to_be_bytes());
        let len_at = out.len();
        out.extend_from_slice(&[0, 0]);
        match &a.data {
            AnswerData::A(ip) => out.extend_from_slice(&ip.octets()),
            AnswerData::Cname(target) => names.write(&mut out, target),
        }
        let len = (out.len() - len_at - 2) as u16;
        out[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
        if out.len() + reserve > limit || count == u16::MAX {
            // Names this record added to the table point past the end: none are used
            // again.
            out.truncate(before);
            flags |= TC;
            break;
        }
        count += 1;
    }
    if opt {
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&MAX_EDNS.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    let mut h = Vec::with_capacity(HEADER);
    Header {
        id: query.header.id,
        flags,
        qdcount: 1,
        ancount: count,
        nscount: 0,
        arcount: u16::from(opt),
    }
    .write(&mut h);
    out[..HEADER].copy_from_slice(&h);
    out
}

/// An error answer to a query that could not be read: its header only, with `rcode`.
pub fn build_error(header: &Header, rcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER);
    Header {
        id: header.id,
        flags: QR | (header.flags & (RD | 0x7800)) | RA | u16::from(rcode & 0xf),
        qdcount: 0,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    }
    .write(&mut out);
    out
}

/// What an upstream answer to an A query for `qname` (normalized) says about it: the
/// CNAME chain from `qname` (at most [`MAX_CHAIN`] links, no loops) and the addresses
/// of the name it ends at, each with the lowest TTL along the way. Records about any
/// other name, as an upstream may add, are left out.
pub fn answer_chain(qname: &str, answers: &[Record]) -> (Vec<Answer>, Vec<(Ipv4Addr, u32)>) {
    let mut chain = Vec::new();
    let mut current = qname.to_owned();
    let mut ttl = u32::MAX;
    let owned_by =
        |r: &Record, name: &str| r.class == CLASS_IN && r.name.text().as_deref() == Some(name);
    for _ in 0..MAX_CHAIN {
        let Some((target, t)) = answers.iter().find_map(|r| match &r.data {
            RData::Cname(n) if owned_by(r, &current) => Some((n.text(), r.ttl)),
            _ => None,
        }) else {
            break;
        };
        let Some(target) = target else { break };
        if target == qname || chain.iter().any(|a: &Answer| a.name == target) {
            break;
        }
        ttl = ttl.min(t);
        chain.push(Answer {
            name: current.clone(),
            ttl: t,
            data: AnswerData::Cname(target.clone()),
        });
        current = target;
    }
    let mut addrs: Vec<(Ipv4Addr, u32)> = Vec::new();
    for r in answers {
        if let RData::A(ip) = r.data
            && owned_by(r, &current)
            && !addrs.iter().any(|(a, _)| *a == ip)
        {
            addrs.push((ip, r.ttl.min(ttl)));
        }
    }
    (chain, addrs)
}

/// The name records of `answer` are owned by, for [`answer_chain`]'s A records: the
/// name the chain ends at.
pub fn chain_end<'a>(qname: &'a str, chain: &'a [Answer]) -> &'a str {
    match chain.last().map(|a| &a.data) {
        Some(AnswerData::Cname(t)) => t,
        _ => qname,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(out: &mut Vec<u8>, name: &[u8], rtype: u16, ttl: u32, data: &[u8]) {
        out.extend_from_slice(name);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    fn wire(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        write_text_name(&mut v, name);
        v
    }

    /// A response to `build_query(7, "www.example.com", A)`: www CNAME edge.cdn.net
    /// (pointer into the question), edge.cdn.net A 192.0.2.1 and A 198.51.100.7, and an
    /// unrelated record an upstream should not have sent.
    fn cdn_response() -> Vec<u8> {
        let q = build_query(7, "www.example.com", TYPE_A, None);
        let mut m = q.clone();
        m[2] |= 0x80; // QR
        m[7] = 4; // ancount
        let cname_at = m.len() + 12; // after the owner pointer and fixed fields
        record(&mut m, &[0xc0, 12], TYPE_CNAME, 300, &wire("edge.cdn.net"));
        let edge = [0xc0, cname_at as u8];
        record(&mut m, &edge, TYPE_A, 60, &[192, 0, 2, 1]);
        record(&mut m, &edge, TYPE_A, 30, &[198, 51, 100, 7]);
        record(
            &mut m,
            &wire("evil.example.org"),
            TYPE_A,
            9999,
            &[203, 0, 113, 9],
        );
        m
    }

    #[test]
    fn queries_round_trip() {
        let q = build_query(0xbeef, "Static.AmpCode.com", TYPE_A, Some(1232));
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.header.id, 0xbeef);
        assert_eq!(parsed.question.qtype, TYPE_A);
        assert_eq!(parsed.question.qclass, CLASS_IN);
        assert_eq!(
            parsed.question.name.text().as_deref(),
            Some("static.ampcode.com")
        );
        assert_eq!(parsed.header.arcount, 1, "EDNS");
        assert_eq!(parsed.edns, Some(1232));
        // EDNS of another version, or a malformed OPT record: none, the query stands.
        let mut v1 = q.clone();
        let n = v1.len();
        v1[n - 5] = 1; // version
        assert_eq!(parse_query(&v1).unwrap().edns, None);
        assert_eq!(parse_query(&q[..q.len() - 3]).unwrap().edns, None);
        // Responses and runts get no answer; other malformed queries a FORMERR.
        let mut r = q.clone();
        r[2] |= 0x80;
        assert_eq!(parse_query(&r), Err(QueryError::Ignore));
        assert_eq!(parse_query(&q[..11]), Err(QueryError::Ignore));
        assert!(matches!(
            parse_query(&q[..20]),
            Err(QueryError::Malformed(_))
        ));
        let mut two = q.clone();
        two[5] = 2;
        assert!(matches!(parse_query(&two), Err(QueryError::Malformed(_))));
        let e = build_error(&parsed.header, FORMERR);
        let h = Header::parse(&e).unwrap();
        assert_eq!(
            (h.id, h.response(), h.rcode(), h.qdcount),
            (0xbeef, true, FORMERR, 0)
        );
    }

    #[test]
    fn follows_cname_chains_only_from_the_queried_name() {
        let m = cdn_response();
        let r = parse_response(&m).unwrap();
        assert!(r.answers_query(7, "www.example.com", TYPE_A));
        assert!(!r.answers_query(8, "www.example.com", TYPE_A));
        assert!(!r.answers_query(7, "example.com", TYPE_A));
        let (chain, addrs) = answer_chain("www.example.com", &r.answers);
        assert_eq!(
            chain,
            vec![Answer {
                name: "www.example.com".into(),
                ttl: 300,
                data: AnswerData::Cname("edge.cdn.net".into())
            }]
        );
        assert_eq!(chain_end("www.example.com", &chain), "edge.cdn.net");
        // The lower TTL along the chain; the stray record is not taken.
        assert_eq!(
            addrs,
            vec![
                (Ipv4Addr::new(192, 0, 2, 1), 60),
                (Ipv4Addr::new(198, 51, 100, 7), 30)
            ]
        );
        // A name with no chain: only its own records.
        let (chain, addrs) = answer_chain("evil.example.org", &r.answers);
        assert!(chain.is_empty());
        assert_eq!(addrs, vec![(Ipv4Addr::new(203, 0, 113, 9), 9999)]);
        // A CNAME loop ends the chain without addresses.
        let cname = |from: &str, to: &str| Record {
            name: Name {
                labels: from.split('.').map(|l| l.as_bytes().to_vec()).collect(),
            },
            rtype: TYPE_CNAME,
            class: CLASS_IN,
            ttl: 5,
            data: RData::Cname(Name {
                labels: to.split('.').map(|l| l.as_bytes().to_vec()).collect(),
            }),
        };
        let looped = [cname("a.x.com", "b.x.com"), cname("b.x.com", "a.x.com")];
        let (chain, addrs) = answer_chain("a.x.com", &looped);
        assert_eq!(chain.len(), 1);
        assert!(addrs.is_empty());
        let long: Vec<Record> = (0..20)
            .map(|i| cname(&format!("h{i}.x.com"), &format!("h{}.x.com", i + 1)))
            .collect();
        assert_eq!(answer_chain("h0.x.com", &long).0.len(), MAX_CHAIN);
    }

    #[test]
    fn hostile_messages_are_errors() {
        let good = cdn_response();
        // Every truncation of a valid response fails cleanly (or parses less).
        for n in 0..good.len() {
            let _ = parse_response(&good[..n]);
            let _ = parse_query(&good[..n]);
            assert!(parse_response(&good[..n]).is_err(), "cut at {n}");
        }
        // Compression loops: a pointer to itself, forward, and two pointing at each other.
        let mut m = build_query(1, "a.com", TYPE_A, None);
        m[2] |= 0x80;
        let at = m.len();
        m.extend_from_slice(&[0xc0, at as u8]); // to itself
        assert_eq!(read_name(&m, at).unwrap_err(), "bad compression pointer");
        let mut f = m.clone();
        f[at + 1] = (at + 2) as u8; // forward
        f.extend_from_slice(&[0]);
        assert!(read_name(&f, at).is_err());
        let mut pair = m[..at].to_vec();
        pair.extend_from_slice(&[1, b'x', 0xc0, (at + 2) as u8]);
        pair.extend_from_slice(&[1, b'y', 0xc0, at as u8]);
        assert!(read_name(&pair, at + 4).is_err());
        assert!(read_name(&pair, at).is_err());
        // Pointer into the header, reserved label types, too-long names.
        assert!(
            read_name(
                &[0; 12].iter().copied().chain([0xc0, 2]).collect::<Vec<_>>(),
                12
            )
            .is_err()
        );
        assert!(
            read_name(
                &[0; 12].iter().copied().chain([0x40, 0]).collect::<Vec<_>>(),
                12
            )
            .is_err()
        );
        let mut long = vec![0u8; 12];
        for _ in 0..5 {
            long.push(63);
            long.extend_from_slice(&[b'a'; 63]);
        }
        long.push(0);
        assert_eq!(
            read_name(&long, 12).unwrap_err(),
            "name longer than 255 bytes"
        );
        // A pointer chain within bounds but over the pointer limit.
        let mut chain = vec![0u8; 12];
        chain.extend_from_slice(&[1, b'a', 0]);
        for i in 0..40u16 {
            let prev = if i == 0 { 12 } else { 15 + 2 * (i - 1) };
            chain.extend_from_slice(&(0xc000 | prev).to_be_bytes());
        }
        assert!(read_name(&chain, chain.len() - 2).is_err());
        // Record data running past the message, a 5-byte A record, a CNAME whose name
        // runs past its data.
        let base = {
            let mut m = build_query(2, "a.com", TYPE_A, None);
            m[2] |= 0x80;
            m[7] = 1;
            m
        };
        let mut over = base.clone();
        record(&mut over, &[0xc0, 12], TYPE_A, 1, &[1, 2, 3, 4]);
        let n = over.len();
        over[n - 6] = 0xff; // rdlength
        assert!(parse_response(&over).is_err());
        let mut five = base.clone();
        record(&mut five, &[0xc0, 12], TYPE_A, 1, &[1, 2, 3, 4, 5]);
        assert!(parse_response(&five).is_err());
        let mut cn = base.clone();
        let mut data = wire("b.com");
        data.pop(); // its root label is outside rdlength
        record(&mut cn, &[0xc0, 12], TYPE_CNAME, 1, &data);
        cn.push(0);
        assert!(parse_response(&cn).is_err());
        // Counts that promise more than there is.
        let mut many = base.clone();
        many[6] = 0x01; // ancount 257
        many[7] = 0x01;
        assert_eq!(parse_response(&many).unwrap_err(), "too many answers");
        let mut missing = base.clone();
        missing[7] = 3;
        record(&mut missing, &[0xc0, 12], TYPE_A, 1, &[1, 2, 3, 4]);
        assert!(parse_response(&missing).is_err());
        // Top-bit TTLs are zero; names with odd bytes are not hostnames.
        let mut neg = base.clone();
        record(&mut neg, &[0xc0, 12], TYPE_A, 0x8000_0001, &[1, 2, 3, 4]);
        assert_eq!(parse_response(&neg).unwrap().answers[0].ttl, 0);
        let odd = Name {
            labels: vec![b"a.b".to_vec(), b"com".to_vec()],
        };
        assert_eq!(odd.text(), None);
        let nul = Name {
            labels: vec![b"a\0".to_vec(), b"com".to_vec()],
        };
        assert_eq!(nul.text(), None);
        assert_eq!(Name::default().text(), None);
    }

    #[test]
    fn hostile_messages_never_panic() {
        // Deterministic pseudo-random garbage and mutations of a valid response.
        let good = cdn_response();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let mut m = good.clone();
            for _ in 0..(next() % 6 + 1) {
                let i = (next() as usize) % m.len();
                m[i] = next() as u8;
            }
            if let Ok(r) = parse_response(&m) {
                let _ = answer_chain("www.example.com", &r.answers);
            }
            let _ = parse_query(&m);
            let len = (next() % 64) as usize;
            let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse_response(&junk);
            let _ = parse_query(&junk);
        }
    }

    #[test]
    fn answers_are_compressed_and_truncated_to_fit() {
        let q = parse_query(&build_query(9, "WWW.Example.com", TYPE_A, None)).unwrap();
        let answers = vec![
            Answer {
                name: "www.example.com".into(),
                ttl: 300,
                data: AnswerData::Cname("edge.cdn.net".into()),
            },
            Answer {
                name: "edge.cdn.net".into(),
                ttl: 60,
                data: AnswerData::A(Ipv4Addr::new(192, 0, 2, 1)),
            },
            Answer {
                name: "edge.cdn.net".into(),
                ttl: 60,
                data: AnswerData::A(Ipv4Addr::new(192, 0, 2, 2)),
            },
        ];
        let m = build_response(&q, NOERROR, &answers, 512);
        let r = parse_response(&m).unwrap();
        assert!(r.answers_query(9, "www.example.com", TYPE_A));
        assert_eq!(r.header.rcode(), NOERROR);
        assert!(!r.header.truncated());
        assert_eq!(r.header.flags & RD, RD, "RD copied");
        assert_eq!(r.question.name, q.question.name, "the question as asked");
        let (chain, addrs) = answer_chain("www.example.com", &r.answers);
        assert_eq!(chain, answers[..1]);
        assert_eq!(addrs.len(), 2);
        // Compressed: each owner is a pointer.
        assert!(m.len() < 100, "{}", m.len());
        // Too big for UDP: as many whole records as fit, and TC.
        let many: Vec<Answer> = (0..60)
            .map(|i| Answer {
                name: "www.example.com".into(),
                ttl: 1,
                data: AnswerData::A(Ipv4Addr::new(192, 0, 2, i)),
            })
            .collect();
        let m = build_response(&q, NOERROR, &many, 512);
        assert!(m.len() <= 512);
        let r = parse_response(&m).unwrap();
        assert!(r.header.truncated());
        assert_eq!(r.answers.len(), (512 - 12 - 21) / 16, "{}", m.len());
        assert_eq!(
            r.answers[..],
            parse_response(&build_response(&q, NOERROR, &many, 65535))
                .unwrap()
                .answers[..r.answers.len()]
        );
        let m = build_response(&q, NOERROR, &many, 65535);
        assert_eq!(parse_response(&m).unwrap().answers.len(), 60);
        // An EDNS client gets up to its size (at most 1232) and an OPT record back.
        let e = parse_query(&build_query(10, "www.example.com", TYPE_A, Some(4096))).unwrap();
        assert_eq!((e.edns, e.udp_limit()), (Some(4096), 1232));
        let m = build_response(&e, NOERROR, &many, e.udp_limit());
        let h = Header::parse(&m).unwrap();
        assert!(!h.truncated() && h.ancount == 60 && h.arcount == 1, "{h:?}");
        assert_eq!(&m[m.len() - 11..m.len() - 6], &[0, 0, 41, 0x04, 0xd0]);
        let small = parse_query(&build_query(11, "www.example.com", TYPE_A, Some(100))).unwrap();
        assert_eq!(small.udp_limit(), 512);
        let m = build_response(&small, NOERROR, &many, small.udp_limit());
        let h = Header::parse(&m).unwrap();
        assert!(m.len() <= 512 && h.truncated() && h.arcount == 1);
        assert_eq!(q.edns, None);
        assert_eq!(q.udp_limit(), 512);
        let nx = parse_response(&build_response(&q, NXDOMAIN, &[], 512)).unwrap();
        assert_eq!(nx.header.rcode(), NXDOMAIN);
    }
}
