//! Operator CLI on the coordinator's admin socket: `orbd status`, `orbd orb ...` and
//! `orbd agent list`. Written for people and for agents (scripts, coding agents):
//!
//! * `--json` prints one JSON object on stdout. Fields are only ever added; times are
//!   `*_unix_ms`, sizes `*_bytes`.
//! * Errors go to stderr (a JSON object with `--json`), with a hint where there is a
//!   next step, and the exit code says what kind of error it was ([`Exit`]).

pub mod orbs;
pub mod status;

use orbd_proto::control::v1 as pb;
use serde::Serialize;
use std::path::Path;
use tonic::transport::Channel;

/// Exit codes. Stable: scripts and agents branch on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exit {
    /// 1: anything else, including a pause or delete that ran and failed, or whose
    /// outcome is not known (`orbd orb show` says what happened).
    Failed = 1,
    /// 2: bad arguments, e.g. an orb prefix matching several orbs.
    Usage = 2,
    /// 3: no such orb or agent.
    NotFound = 3,
    /// 4: refused, nothing done: e.g. deleting an orb that runs or woke lately.
    Refused = 4,
    /// 5: the coordinator, or the orb's host, cannot be reached; retrying may help.
    Unavailable = 5,
    /// 6: `orbd status --check` found problems of severity `error`.
    Unhealthy = 6,
}

pub const EXIT_CODES_HELP: &str = "\
Exit codes: 0 ok; 1 failed (a pause or delete that ran and failed, or whose outcome is
unknown: `orbd orb show` says what happened); 2 bad arguments (e.g. an ambiguous orb
prefix); 3 no such orb or agent; 4 refused, nothing done (e.g. deleting an orb in use);
5 the coordinator or the orb's host is unreachable, retry later; 6 `status --check`
found errors. With --json, errors are one JSON object on stderr:
{\"error\": {\"exit_code\", \"kind\", \"message\", \"hint\", \"retryable\"}}.";

/// An error with its exit code and, where there is one, what to do next.
#[derive(Debug)]
pub struct CliError {
    pub exit: Exit,
    pub message: String,
    pub hint: Option<String>,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl CliError {
    pub fn new(exit: Exit, message: impl Into<String>) -> Self {
        Self {
            exit,
            message: message.into(),
            hint: None,
        }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// From a failed admin call; `what` prefixes the message (e.g. "amp-1 not deleted").
    pub fn from_status(s: &tonic::Status, what: Option<&str>) -> Self {
        use tonic::Code;
        let exit = match s.code() {
            Code::NotFound => Exit::NotFound,
            Code::InvalidArgument => Exit::Usage,
            // Refused before anything was done.
            Code::FailedPrecondition | Code::AlreadyExists => Exit::Refused,
            Code::Unavailable | Code::DeadlineExceeded => Exit::Unavailable,
            // Aborted: it ran and failed. Unknown: it may have happened.
            _ => Exit::Failed,
        };
        let message = match what {
            Some(w) => format!("{w}: {}", s.message()),
            None => s.message().to_owned(),
        };
        let hint = match exit {
            Exit::NotFound => Some("`orbd orb list` lists the orbs that exist".to_owned()),
            _ => None,
        };
        Self {
            exit,
            message,
            hint,
        }
    }

    /// Prints the error to stderr: `error: ...` and `hint: ...` lines, or with `json` a
    /// single object `{"error": {"exit_code", "kind", "message", "hint"}}`.
    pub fn print(&self, json: bool) {
        if json {
            let v = serde_json::json!({ "error": {
                "exit_code": self.exit as i32,
                "kind": self.exit,
                "message": self.message,
                "hint": self.hint,
                // Trying again later may succeed (the coordinator or a host was away).
                "retryable": self.exit == Exit::Unavailable,
            }});
            eprintln!("{v}");
        } else {
            eprintln!("error: {}", self.message);
            if let Some(h) = &self.hint {
                eprintln!("hint: {h}");
            }
        }
    }
}

async fn channel(socket: &Path) -> Result<Channel, CliError> {
    crate::amp::dispatch::connect(socket).await.map_err(|e| {
        CliError::new(
            Exit::Unavailable,
            format!("cannot reach the coordinator at {}: {e:#}", socket.display()),
        )
        .hint("run this on the coordinator's host (in its container), as the user that owns the socket; is the coordinator running?")
    })
}

pub async fn orbs_client(socket: &Path) -> Result<pb::orbs_client::OrbsClient<Channel>, CliError> {
    Ok(pb::orbs_client::OrbsClient::new(channel(socket).await?))
}

pub async fn admin_client(
    socket: &Path,
) -> Result<pb::admin_client::AdminClient<Channel>, CliError> {
    Ok(pb::admin_client::AdminClient::new(channel(socket).await?))
}

pub fn to_json<T: Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).expect("serializable") + "\n"
}

// --- formatting ----------------------------------------------------------------------

pub const GIB: u64 = crate::model::GIB;

pub fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB as f64)
}

/// `54.6G`, for tables.
pub fn gib_short(bytes: u64) -> String {
    format!("{:.1}G", bytes as f64 / GIB as f64)
}

/// Short size for tables: `12G`, `0.4G`, `-` for unknown.
pub fn size(bytes: Option<u64>) -> String {
    match bytes {
        None => "-".into(),
        Some(b) if b >= 10 * GIB => format!("{}G", b / GIB),
        Some(b) => format!("{:.1}G", b as f64 / GIB as f64),
    }
}

/// `45s`, `12m`, `5h`, `3d`.
pub fn age(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86_400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// `2026-11-16 03:46:07Z`.
pub fn utc(unix_ms: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp((unix_ms / 1000) as i64) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
            t.year(),
            t.month() as u8,
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        ),
        Err(_) => "?".into(),
    }
}

/// Left-aligned columns, two spaces apart; the last column is not padded.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let n = header.len();
    let mut width: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate().take(n) {
            width[i] = width[i].max(c.chars().count());
        }
    }
    let mut out = String::new();
    let mut line = |cells: Vec<&str>| {
        let mut l = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                l.push_str(c);
            } else {
                l.push_str(&format!("{c:<w$}  ", w = width[i]));
            }
        }
        out.push_str(l.trim_end());
        out.push('\n');
    };
    line(header.to_vec());
    for r in rows {
        line(r.iter().map(String::as_str).collect());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(age(59_000), "59s");
        assert_eq!(age(3_600_000), "1h");
        assert_eq!(age(4 * 86_400_000), "4d");
        assert_eq!(size(Some(33 * GIB)), "33G");
        assert_eq!(size(Some(GIB / 2)), "0.5G");
        assert_eq!(size(None), "-");
        assert_eq!(utc(1_794_804_367_000), "2026-11-16 04:46:07Z");
        assert_eq!(
            table(&["A", "BB"], &[vec!["xxx".into(), "y".into()]]),
            "A    BB\nxxx  y\n"
        );
    }

    #[test]
    fn status_codes_map_to_exit_codes() {
        let e = CliError::from_status(&tonic::Status::not_found("no orb"), None);
        assert_eq!(e.exit, Exit::NotFound);
        let e = CliError::from_status(&tonic::Status::failed_precondition("in use"), Some("x"));
        assert_eq!((e.exit, e.message.as_str()), (Exit::Refused, "x: in use"));
        // A command that ran and failed, or may have happened, did not "do nothing".
        for s in [
            tonic::Status::aborted("failed"),
            tonic::Status::unknown("?"),
        ] {
            assert_eq!(CliError::from_status(&s, None).exit, Exit::Failed);
        }
        let e = CliError::from_status(&tonic::Status::unavailable("down"), None);
        assert_eq!(e.exit, Exit::Unavailable);
    }
}
