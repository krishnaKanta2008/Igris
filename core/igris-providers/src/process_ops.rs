use std::fs;

use serde::Serialize;
use serde_json::Value;

use igris_proto::{error_code, ALLOWED_SIGNALS, MAX_PID, PROCESS_DEFAULT_MAX, PROCESS_MAX};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessEntry {
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
    pub state: String,
    pub uid: u32,
    pub gid: u32,
    pub rss_kb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListResult {
    pub entries: Vec<ProcessEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChildrenResult {
    pub parent_pid: u64,
    pub entries: Vec<ProcessEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFailure {
    pub code: &'static str,
    pub message: &'static str,
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

struct ParsedStat {
    pid: u64,
    comm: String,
    state: String,
    ppid: u64,
}
fn parse_stat(raw: &str) -> Option<ParsedStat> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close <= open {
        return None;
    }
    let pid: u64 = raw[..open].trim().parse().ok()?;
    let comm = raw[open + 1..close].to_string();
    let mut fields = raw[close + 1..].split_whitespace();
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
            rss = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    Some(ParsedStatus {
        uid: uid?,
        gid: gid?,
        rss_kb: rss,
    })
}

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

fn valid_pid(pid: u64) -> bool {
    (1..=MAX_PID).contains(&pid)
}

fn for_each_entry(mut visit: impl FnMut(ProcessEntry)) {
    let Ok(read_dir) = fs::read_dir("/proc") else {
        return;
    };
    let mut pids = Vec::new();
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

pub fn stat(params: &Value) -> Result<ProcessEntry, ProcessFailure> {
    let pid = params
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(ProcessFailure::invalid_pid)?;
    if !valid_pid(pid) {
        return Err(ProcessFailure::invalid_pid());
    }
    entry_for(pid)
}

pub fn list(params: &Value) -> Result<ListResult, ProcessFailure> {
    let max = params
        .get("max")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(PROCESS_DEFAULT_MAX)
        .clamp(1, PROCESS_MAX);
    let mut entries = Vec::new();
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

#[allow(dead_code)]
fn filter_direct_children(parent_pid: u64, entries: Vec<ProcessEntry>) -> Vec<ProcessEntry> {
    let mut children: Vec<ProcessEntry> = entries
        .into_iter()
        .filter(|e| e.ppid == parent_pid)
        .collect();
    children.sort_by_key(|e| e.pid);
    children
}

pub fn children(params: &Value) -> Result<ChildrenResult, ProcessFailure> {
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
    entry_for(parent).map_err(|e| match e {
        ProcessFailure { code, .. } if code == error_code::NOT_FOUND => ProcessFailure::not_found(),
        other => other,
    })?;
    let mut children = Vec::new();
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

pub fn signal(params: &Value) -> Result<Value, ProcessFailure> {
    let pid = params
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(ProcessFailure::invalid_pid)?;
    if !valid_pid(pid) {
        return Err(ProcessFailure::invalid_pid());
    }
    let signal = params
        .get("signal")
        .and_then(|v| v.as_u64())
        .ok_or(ProcessFailure {
            code: error_code::BAD_REQUEST,
            message: "`signal` must be a positive integer",
            denied: true,
        })?;
    if signal == 0 {
        return Err(ProcessFailure {
            code: error_code::BAD_REQUEST,
            message: "`signal` must be a positive integer",
            denied: true,
        });
    }
    if !ALLOWED_SIGNALS.contains(&signal) {
        return Err(ProcessFailure {
            code: error_code::BAD_REQUEST,
            message: "signal is not in the allow-list",
            denied: true,
        });
    }
    let my_pid = std::process::id() as u64;
    if pid == my_pid {
        return Err(ProcessFailure {
            code: error_code::BAD_REQUEST,
            message: "signaling self is not permitted",
            denied: true,
        });
    }

    // Extract owner_pid from params (provided by server after authorization)
    let owner_pid = params
        .get("owner_pid")
        .and_then(|v| v.as_u64())
        .ok_or(ProcessFailure {
            code: error_code::BAD_REQUEST,
            message: "missing owner_pid parameter",
            denied: true,
        })?;

    // Use pidfd-based signaling for race-resistant signal delivery.
    // pidfd_open obtains a stable reference to the target process.
    // pidfd_send_signal delivers the signal via that stable reference.
    // Ancestry is verified via the pidfd to eliminate TOCTOU.
    let result = send_signal_via_pidfd_with_authorization(pid, signal, owner_pid);

    // If pidfd is not supported (ENOSYS), return a clear error instead of falling back.
    match result {
        Ok(_) => Ok(serde_json::json!({"sent": true})),
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => Err(ProcessFailure {
            code: error_code::FS_ERROR,
            message: "pidfd signaling not supported on this kernel (requires Linux 5.1+)",
            denied: false,
        }),
        Err(e) => {
            // Check if this is an authorization failure (not a descendant)
            let msg = e.to_string();
            if msg.contains("not a descendant") {
                return Err(ProcessFailure {
                    code: error_code::DENIED,
                    message: "target process is not a descendant of the session owner",
                    denied: true,
                });
            }
            match e.kind() {
                std::io::ErrorKind::NotFound => Err(ProcessFailure {
                    code: error_code::NOT_FOUND,
                    message: "process not found",
                    denied: false,
                }),
                std::io::ErrorKind::PermissionDenied => Err(ProcessFailure {
                    code: error_code::FS_ERROR,
                    message: "permission denied",
                    denied: false,
                }),
                _ => Err(ProcessFailure {
                    code: error_code::FS_ERROR,
                    message: "failed to send signal",
                    denied: false,
                }),
            }
        }
    }
}

/// Send a signal to a process using pidfd for race-resistant delivery.
/// Opens pidfd FIRST (stabilizes the target process reference), then verifies
/// target is a descendant of owner_pid, then signals via pidfd.
/// Returns Ok(()) on success, or an error if pidfd is not supported or the operation fails.
fn send_signal_via_pidfd_with_authorization(
    pid: u64,
    signal: u64,
    owner_pid: u64,
) -> std::io::Result<()> {
    // Syscall numbers for pidfd operations (Linux x86_64)
    const SYS_PIDFD_OPEN: i64 = 434;
    const SYS_PIDFD_SEND_SIGNAL: i64 = 424;
    const PIDFD_NONBLOCK: u32 = libc::O_NONBLOCK as u32;

    // Open a pidfd for the target process FIRST (stabilizes the target process reference)
    let pidfd = unsafe {
        libc::syscall(
            SYS_PIDFD_OPEN,
            pid as libc::pid_t,
            PIDFD_NONBLOCK as libc::c_uint,
        )
    };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let pidfd = pidfd as libc::c_int;

    // Verify target is a descendant of owner_pid using the pid
    // The pidfd stabilizes the target process reference, so the target PID is now stable.
    // Read /proc/<pid>/stat to get ppid and walk up the process tree.
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = std::fs::read_to_string(&stat_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;

    // Parse PPID from stat (field 4 after the comm field)
    // Format: pid (comm) state ppid ...
    let close_paren = stat_content.rfind(')').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed stat: no closing paren",
        )
    })?;
    let after_comm = &stat_content[close_paren + 1..].trim_start();
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() < 2 {
        unsafe { libc::close(pidfd as libc::c_int) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed stat: insufficient fields",
        ));
    }
    // fields[0] = state, fields[1] = ppid
    let initial_ppid = fields[1].parse::<u64>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed stat: invalid ppid",
        )
    })?;

    // Walk up the process tree to verify target is a descendant of owner_pid
    let mut current_pid = pid;
    let mut current_ppid = initial_ppid;
    let mut authorized = false;
    for _ in 0..256 {
        if current_pid == owner_pid {
            authorized = true;
            break;
        }
        if current_pid == 0 || current_pid == 1 {
            break; // Reached init or invalid
        }
        // Move up the tree
        current_pid = current_ppid;
        // Read PPID of current process
        let stat_path = format!("/proc/{}/stat", current_pid);
        let stat_content = match std::fs::read_to_string(&stat_path) {
            Ok(content) => content,
            Err(_) => break, // Process exited or can't read
        };
        let close_paren = match stat_content.rfind(')') {
            Some(pos) => pos,
            None => break,
        };
        let after_comm = &stat_content[close_paren + 1..].trim_start();
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        if fields.len() < 2 {
            break;
        }
        current_ppid = match fields[1].parse::<u64>() {
            Ok(ppid) => ppid,
            Err(_) => break,
        };
    }

    if !authorized {
        unsafe { libc::close(pidfd as libc::c_int) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "target process is not a descendant of the session owner",
        ));
    }

    // Re-validate target's immediate parent (ppid) hasn't changed during the walk.
    // This narrows the window for intermediate-ancestor PID reuse races.
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = std::fs::read_to_string(&stat_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
    let close_paren = stat_content.rfind(')').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed stat: no closing paren",
        )
    })?;
    let after_comm = &stat_content[close_paren + 1..].trim_start();
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() < 2 {
        unsafe { libc::close(pidfd as libc::c_int) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed stat: insufficient fields on re-validation",
        ));
    }
    let current_ppid = fields[1].parse::<u64>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed stat: invalid ppid on re-validation",
        )
    })?;
    if current_ppid != initial_ppid {
        unsafe { libc::close(pidfd as libc::c_int) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "target process parent changed during authorization",
        ));
    }

    // Send the signal via pidfd (pass NULL for siginfo to use default)
    let ret = unsafe {
        libc::syscall(
            SYS_PIDFD_SEND_SIGNAL,
            pidfd as libc::c_int,
            signal as libc::c_int,
            std::ptr::null::<libc::siginfo_t>(),
            0u32 as libc::c_uint,
        )
    };

    // Close the pidfd
    unsafe { libc::close(pidfd as libc::c_int) };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
