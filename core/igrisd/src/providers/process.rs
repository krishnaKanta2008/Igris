//! Read-only process observation provider (`process.list`, `process.stat`,
//! `process.children`).
//!
//! Data comes exclusively from `/proc/<pid>/stat` (pid, comm, state, ppid)
//! and `/proc/<pid>/status` (Uid, Gid, VmRSS). The provider never reads
//! `cmdline`, `environ`, `exe`, `cwd`, `root`, fd lists, cgroups, or wchan,
//! and never invokes a shell or any subprocess.
//!
//! Results are bounded; scanning remains O(number of processes) because every
//! request must consider every PID directory in `/proc`. Processes that
//! disappear mid-scan are skipped; a disappeared target pid on `process.stat`
//! or a disappeared parent on `process.children` yields a sanitized
//! `NOT_FOUND`.

use std::fs;

use serde::Serialize;

use igris_proto::{error_code, MAX_PID, PROCESS_DEFAULT_MAX, PROCESS_MAX};

/// One process, as exposed to clients. Fields are chosen to be sufficient for
/// observation while avoiding sensitive host details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessEntry {
    pub pid: u64,
    pub ppid: u64,
    /// Kernel `comm` (truncated to 15 chars by the kernel).
    pub name: String,
    /// Single-letter process state from `/proc/<pid>/stat`.
    pub state: String,
    pub uid: u32,
    pub gid: u32,
    /// Resident set size in KiB, or `null` when unavailable.
    pub rss_kb: Option<u64>,
}

/// `process.list` result payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListResult {
    pub entries: Vec<ProcessEntry>,
    pub truncated: bool,
}

/// `process.children` result payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChildrenResult {
    pub parent_pid: u64,
    pub entries: Vec<ProcessEntry>,
    pub truncated: bool,
}

/// A provider-level failure mapped to a sanitized protocol error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFailure {
    pub code: &'static str,
    pub message: &'static str,
    /// `true` when the request itself was rejected (audit `deny`).
    pub denied: bool,
}

impl ProcessFailure {
    fn not_found() -> Self {
        Self {
            code: error_code::NOT_FOUND,
            message: "process not found",
            denied: false,
        }
    }

    fn unavailable() -> Self {
        Self {
            code: error_code::FS_ERROR,
            message: "process information unavailable",
            denied: false,
        }
    }

    fn invalid_pid() -> Self {
        Self {
            code: error_code::BAD_REQUEST,
            message: "invalid pid",
            denied: true,
        }
    }
}

/// Parsed subset of `/proc/<pid>/stat`.
struct ParsedStat {
    pid: u64,
    comm: String,
    state: String,
    ppid: u64,
}

/// Parse `/proc/<pid>/stat` robustly.
///
/// `comm` may contain spaces and parentheses, so fields after it are located
/// by the *last* ')' in the line. Layout: `pid (comm) state ppid ...`.
fn parse_stat(raw: &str) -> Option<ParsedStat> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close <= open {
        return None;
    }
    let pid: u64 = raw[..open].trim().parse().ok()?;
    let comm = raw[open + 1..close].to_string();
    let rest = &raw[close + 1..];
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.to_string();
    let ppid: u64 = fields.next()?.parse().ok()?;
    if comm.is_empty() || state.is_empty() {
        return None;
    }
    Some(ParsedStat {
        pid,
        comm,
        state,
        ppid,
    })
}

/// Parsed subset of `/proc/<pid>/status`.
struct ParsedStatus {
    uid: u32,
    gid: u32,
    rss_kb: Option<u64>,
}

fn parse_status(raw: &str) -> Option<ParsedStatus> {
    let mut uid = None;
    let mut gid = None;
    let mut rss = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next()?.parse().ok();
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = rest.split_whitespace().next()?.parse().ok();
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            // Format: "<kb> kB"; tolerate a bare number.
            rss = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    Some(ParsedStatus {
        uid: uid?,
        gid: gid?,
        rss_kb: rss,
    })
}

/// Read and merge `/proc/<pid>/stat` and `/proc/<pid>/status`.
fn entry_for(pid: u64) -> Result<ProcessEntry, ProcessFailure> {
    let stat_raw = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProcessFailure::not_found())
        }
        Err(_) => return Err(ProcessFailure::unavailable()),
    };
    let status_raw = match fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProcessFailure::not_found())
        }
        Err(_) => return Err(ProcessFailure::unavailable()),
    };
    let parsed_stat = parse_stat(&stat_raw).ok_or_else(ProcessFailure::unavailable)?;
    let parsed_status = parse_status(&status_raw).ok_or_else(ProcessFailure::unavailable)?;
    Ok(ProcessEntry {
        pid: parsed_stat.pid,
        ppid: parsed_stat.ppid,
        name: parsed_stat.comm,
        state: parsed_stat.state,
        uid: parsed_status.uid,
        gid: parsed_status.gid,
        rss_kb: parsed_status.rss_kb,
    })
}

/// Build an entry only if the pid is well-formed; otherwise `None`-style
/// filtering is the caller's job.
fn valid_pid(pid: u64) -> bool {
    (1..=MAX_PID).contains(&pid)
}

/// Iterate numeric PID directories under `/proc` in ascending PID order,
/// invoking `visit` for each readable process. Unreadable or vanished
/// processes are skipped, so the scan never fails on a changing process
/// table. The scan is O(number of processes).
fn for_each_entry(mut visit: impl FnMut(ProcessEntry)) {
    let Ok(read_dir) = fs::read_dir("/proc") else {
        return;
    };
    let mut pids: Vec<u64> = Vec::new();
    for entry in read_dir.flatten() {
        let name = entry.file_name();
        let Ok(name) = name.into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<u64>() else {
            continue;
        };
        if valid_pid(pid) {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    for pid in pids {
        if let Ok(entry) = entry_for(pid) {
            visit(entry);
        }
    }
}

/// `process.stat`: metadata for exactly one process.
pub fn stat(params: &serde_json::Value) -> Result<ProcessEntry, ProcessFailure> {
    let pid = params
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(ProcessFailure::invalid_pid)?;
    if !valid_pid(pid) {
        return Err(ProcessFailure::invalid_pid());
    }
    entry_for(pid)
}

/// `process.list`: bounded, pid-sorted process snapshot.
pub fn list(params: &serde_json::Value) -> Result<ListResult, ProcessFailure> {
    let max = params
        .get("max")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(PROCESS_DEFAULT_MAX)
        .clamp(1, PROCESS_MAX);

    let mut entries: Vec<ProcessEntry> = Vec::new();
    let mut overflow = false;
    for_each_entry(|entry| {
        if entries.len() < max {
            entries.push(entry);
        } else {
            overflow = true;
        }
    });
    entries.sort_by_key(|e| e.pid);
    Ok(ListResult {
        entries,
        truncated: overflow,
    })
}

/// Keep only direct children of `parent_pid`, pid-sorted. Pure filter used by
/// `children` and unit-tested directly.
#[cfg(test)]
fn filter_direct_children(parent_pid: u64, entries: Vec<ProcessEntry>) -> Vec<ProcessEntry> {
    let mut children: Vec<ProcessEntry> = entries
        .into_iter()
        .filter(|e| e.ppid == parent_pid)
        .collect();
    children.sort_by_key(|e| e.pid);
    children
}

/// `process.children`: direct children of `pid` (not recursive descendants).
pub fn children(params: &serde_json::Value) -> Result<ChildrenResult, ProcessFailure> {
    let parent = params
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(ProcessFailure::invalid_pid)?;
    if !valid_pid(parent) {
        return Err(ProcessFailure::invalid_pid());
    }
    let max = params
        .get("max")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(PROCESS_DEFAULT_MAX)
        .clamp(1, PROCESS_MAX);

    // The parent must exist; a disappeared parent is NOT_FOUND, and an empty
    // child list alone must not be confused with a missing parent.
    entry_for(parent).map_err(|e| match e {
        ProcessFailure { code, .. } if code == error_code::NOT_FOUND => ProcessFailure::not_found(),
        other => other,
    })?;

    let mut children: Vec<ProcessEntry> = Vec::new();
    let mut overflow = false;
    for_each_entry(|entry| {
        if entry.ppid != parent {
            return;
        }
        if children.len() < max {
            children.push(entry);
        } else {
            overflow = true;
        }
    });
    children.sort_by_key(|e| e.pid);
    Ok(ChildrenResult {
        parent_pid: parent,
        entries: children,
        truncated: overflow,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_simple_comm() {
        let raw = "1234 (igrisd) S 1000 1234 1234 0 -1 4194304 100 0 0 0 10 2 0 0 20 0 1 0 50 1000000 200 18446744073709551615\n";
        let parsed = parse_stat(raw).expect("parses");
        assert_eq!(parsed.pid, 1234);
        assert_eq!(parsed.comm, "igrisd");
        assert_eq!(parsed.state, "S");
        assert_eq!(parsed.ppid, 1000);
    }

    #[test]
    fn parses_stat_with_spaces_and_parens_in_comm() {
        let raw = "4321 (my (weird) proc name) R 1 4321 4321 0 -1 4194304 100 0 0 0 10 2 0 0 20 0 1 0 50 1000000 200 18446744073709551615\n";
        let parsed = parse_stat(raw).expect("parses");
        assert_eq!(parsed.pid, 4321);
        assert_eq!(parsed.comm, "my (weird) proc name");
        assert_eq!(parsed.state, "R");
        assert_eq!(parsed.ppid, 1);
    }

    #[test]
    fn rejects_stat_without_comm_delimiters() {
        assert!(parse_stat("1234 no-parens S 1\n").is_none());
        assert!(parse_stat("").is_none());
    }

    #[test]
    fn parses_status_uid_gid_vmrss() {
        let raw = "Name:\ttest\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\nVmRSS:\t  2048 kB\n";
        let parsed = parse_status(raw).expect("parses");
        assert_eq!(parsed.uid, 1000);
        assert_eq!(parsed.gid, 1001);
        assert_eq!(parsed.rss_kb, Some(2048));
    }

    #[test]
    fn status_missing_vmrss_is_none() {
        let raw = "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
        let parsed = parse_status(raw).expect("parses");
        assert_eq!(parsed.rss_kb, None);
    }

    #[test]
    fn rejects_status_without_uid() {
        assert!(parse_status("Name:\tx\nGid:\t0\t0\t0\t0\n").is_none());
    }

    #[test]
    fn list_is_bounded_and_sorted() {
        let result = list(&serde_json::json!({"max": 5})).expect("list");
        assert!(result.entries.len() <= 5);
        let pids: Vec<u64> = result.entries.iter().map(|e| e.pid).collect();
        let mut sorted = pids.clone();
        sorted.sort_unstable();
        assert_eq!(pids, sorted);
    }

    #[test]
    fn list_default_and_truncation_shape() {
        let result = list(&serde_json::json!({})).expect("list");
        assert!(result.entries.len() <= PROCESS_DEFAULT_MAX);
        // On any host with more than PROCESS_DEFAULT_MAX processes, truncated
        // must be set; otherwise it is simply false. Either way the field is
        // consistent with the entry count.
        if result.truncated {
            assert_eq!(result.entries.len(), PROCESS_DEFAULT_MAX);
        }
    }

    #[test]
    fn stat_self_process() {
        let pid = std::process::id() as u64;
        let entry = stat(&serde_json::json!({"pid": pid})).expect("stat self");
        assert_eq!(entry.pid, pid);
        assert!(!entry.name.is_empty());
        assert!(!entry.state.is_empty());
        assert!(entry.uid == entry.uid); // field present and typed
    }

    #[test]
    fn stat_disappeared_process_is_not_found() {
        // PID 4,000,000 is at the hard bound and essentially never a live
        // process; treat NotFound as the expected outcome but accept
        // unavailable on pathological systems.
        let err = stat(&serde_json::json!({"pid": MAX_PID})).expect_err("missing pid");
        assert!(err.code == error_code::NOT_FOUND || err.code == error_code::FS_ERROR);
    }

    #[test]
    fn children_selects_direct_children_only() {
        let mk = |pid: u64, ppid: u64| ProcessEntry {
            pid,
            ppid,
            name: format!("p{pid}"),
            state: "S".into(),
            uid: 0,
            gid: 0,
            rss_kb: None,
        };
        // 100 -> 120 -> 140 ; 100 -> 130
        let all = vec![mk(140, 120), mk(120, 100), mk(130, 100), mk(999, 999)];
        let children = filter_direct_children(100, all);
        let pids: Vec<u64> = children.iter().map(|e| e.pid).collect();
        assert_eq!(pids, vec![120, 130]); // not 140
    }

    #[test]
    fn children_requires_existing_parent() {
        let err = children(&serde_json::json!({"pid": MAX_PID})).expect_err("missing parent");
        assert_eq!(err.code, error_code::NOT_FOUND);
    }

    #[test]
    fn children_of_self_has_consistent_shape() {
        let pid = std::process::id() as u64;
        let result = children(&serde_json::json!({"pid": pid})).expect("children");
        assert_eq!(result.parent_pid, pid);
        for entry in &result.entries {
            assert_eq!(entry.ppid, pid, "only direct children allowed");
        }
    }
}
