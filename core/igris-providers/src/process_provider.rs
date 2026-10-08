//! Process provider binary.
//!
//! Handles process.list, process.stat, process.children, proc.signal operations
//! within a sandboxed environment.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use igris_proto::{
    error_code, read_frame, validate_request, write_response, ReadFrame, Request, Response,
    MAX_REQUEST_SIZE, MAX_RESPONSE_SIZE,
};

use igris_sandbox::init_provider_sandbox;

fn run_provider_server<F>(
    socket_path: &Path,
    fs_root: &Path,
    writable_paths: &[PathBuf],
    handler: F,
) -> std::io::Result<()>
where
    F: Fn(&Request) -> Result<serde_json::Value, (String, String)> + Send + Sync + 'static,
{
    // Apply sandboxing
    init_provider_sandbox(fs_root, writable_paths, true, None)
        .map_err(|e| std::io::Error::other(format!("sandbox init failed: {}", e)))?;

    // Bind socket
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    let handler = Arc::new(handler);

    // Handle connections
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let handler = Arc::clone(&handler);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(&mut stream, &handler) {
                        eprintln!("provider connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("provider accept error: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_connection<F>(
    stream: &mut std::os::unix::net::UnixStream,
    handler: &Arc<F>,
) -> std::io::Result<()>
where
    F: Fn(&Request) -> Result<serde_json::Value, (String, String)> + Send + Sync,
{
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    loop {
        let frame = match read_frame(stream, MAX_REQUEST_SIZE) {
            Ok(frame) => frame,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        match frame {
            ReadFrame::Closed => return Ok(()),
            ReadFrame::TooLarge { declared } => {
                let response = Response::error(
                    None,
                    igris_proto::error_code::TOO_LARGE,
                    format!(
                        "request declared {} bytes, exceeding the {}-byte maximum",
                        declared, MAX_REQUEST_SIZE
                    ),
                );
                let _ = write_response(stream, &response, MAX_RESPONSE_SIZE);
                return Ok(());
            }
            ReadFrame::Received(bytes) => {
                let request: Request = match serde_json::from_slice(&bytes) {
                    Ok(req) => req,
                    Err(e) => {
                        let response = Response::error(
                            None,
                            igris_proto::error_code::BAD_REQUEST,
                            format!("malformed request: {}", e),
                        );
                        let _ = write_response(stream, &response, MAX_RESPONSE_SIZE);
                        continue;
                    }
                };

                let id_for_error = if request.id.is_empty() {
                    None
                } else {
                    Some(request.id.clone())
                };

                if let Err(e) = validate_request(&request) {
                    let response = Response::error(id_for_error, e.code, e.message);
                    let _ = write_response(stream, &response, MAX_RESPONSE_SIZE);
                    continue;
                }

                let response = match handler(&request) {
                    Ok(result) => Response::success(request.id, result),
                    Err((code, message)) => Response::error(Some(request.id), &code, message),
                };

                if write_response(stream, &response, MAX_RESPONSE_SIZE).is_err() {
                    return Ok(());
                }
            }
        }
    }
}

mod process_ops {
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
            ProcessFailure { code, .. } if code == error_code::NOT_FOUND => {
                ProcessFailure::not_found()
            }
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
        let ret = unsafe { ::libc::kill(pid as ::libc::pid_t, signal as ::libc::c_int) };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            match err.kind() {
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
        } else {
            Ok(serde_json::json!({"sent": true}))
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: igris-process-provider <socket_path> [fs_root] [writable_paths...]");
        std::process::exit(1);
    }
    let socket_path = PathBuf::from(&args[1]);
    let fs_root = PathBuf::from("/"); // Process provider doesn't need fs_root
    let writable_paths: Vec<PathBuf> = vec![];

    run_provider_server(
        &socket_path,
        &fs_root,
        &writable_paths,
        move |req| match req.op.as_str() {
            igris_proto::OP_PROCESS_LIST => {
                let result = process_ops::list(&req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_PROCESS_STAT => {
                let result = process_ops::stat(&req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_PROCESS_CHILDREN => {
                let result = process_ops::children(&req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_PROC_SIGNAL => {
                let result = process_ops::signal(&req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            _ => Err((
                error_code::UNKNOWN_OPERATION.to_string(),
                "unsupported operation".to_string(),
            )),
        },
    )
    .expect("provider server failed");
}
