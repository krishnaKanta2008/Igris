//! Append-only audit logging.
//!
//! Every request handled by `igrisd` produces exactly one audit record: the
//! timestamp, request id, operation, permission decision, and the result. The
//! log is opened in append mode and each record is one JSON object on its own
//! line (JSON Lines), which keeps it append-only and easy to consume.
//!
//! Records intentionally exclude secrets and bulky payloads. The `result`
//! field records only a coarse outcome (`success`, `denied`, `error`), never
//! response contents.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Coarse outcome of handling a request, as recorded in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult {
    /// The operation succeeded.
    Success,
    /// The operation was denied by policy.
    Denied,
    /// The operation was not attempted or failed (e.g. protocol error).
    Error,
}

/// A single append-only audit record.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// RFC 3339 UTC timestamp derived from the system clock.
    pub timestamp: String,
    /// Request correlation id, when the request had a usable one.
    pub request_id: Option<String>,
    /// Operation name, when known.
    pub operation: Option<String>,
    /// Permission decision: `"allow"` or `"deny"`.
    pub decision: String,
    /// Coarse result: `"success"`, `"denied"`, or `"error"`.
    pub result: AuditResult,
    /// Peer identifier (the local side of the Unix socket).
    pub peer: Option<String>,
}

/// Append-only audit log writer.
pub struct AuditLog {
    file: File,
}

impl AuditLog {
    /// Open (creating if needed) the append-only audit log at `path`.
    pub fn open(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file })
    }

    /// Append one record as a JSON line and flush it to disk.
    pub fn record(&mut self, record: &AuditRecord) -> io::Result<()> {
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.flush()
    }
}

/// Format the current system time as an RFC 3339 UTC timestamp (second
/// precision). Implemented without external dependencies.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_rfc3339(secs)
}

/// Format a Unix timestamp (seconds) as RFC 3339 UTC.
pub fn format_rfc3339(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let secs_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert days since the Unix epoch to a (year, month, day) civil date.
/// Algorithm from Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn formats_known_timestamp() {
        // 2021-01-01T00:00:00Z == 1609459200
        assert_eq!(format_rfc3339(1_609_459_200), "2021-01-01T00:00:00Z");
    }

    #[test]
    fn handles_leap_day() {
        // 2020-02-29T12:34:56Z == 1582979696
        assert_eq!(format_rfc3339(1_582_979_696), "2020-02-29T12:34:56Z");
    }

    #[test]
    fn writes_and_appends_json_lines() {
        let dir = std::env::temp_dir().join(format!("igris-audit-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("audit.log");

        let mut log = AuditLog::open(&path).expect("open audit log");
        for id in ["a", "b"] {
            log.record(&AuditRecord {
                timestamp: format_rfc3339(0),
                request_id: Some(id.to_string()),
                operation: Some("system.info".to_string()),
                decision: "allow".to_string(),
                result: AuditResult::Success,
                peer: None,
            })
            .expect("record");
        }

        let contents = fs::read_to_string(&path).expect("read audit log");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "append-only: one line per record");
        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("valid json line");
        assert_eq!(first["result"], "success");
        assert_eq!(first["decision"], "allow");

        let _ = fs::remove_dir_all(&dir);
    }
}
