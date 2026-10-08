//! System provider binary.
//!
//! Handles system.info operation within a sandboxed environment.

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

mod system_ops {
    use std::fs;
    use std::io;
    use std::path::Path;

    use serde::Serialize;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct CpuInfo {
        pub model: Option<String>,
        pub logical_cores: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    pub struct MemoryInfo {
        pub total_kb: u64,
        pub free_kb: u64,
        pub available_kb: u64,
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct SystemInfo {
        pub hostname: String,
        pub kernel_release: String,
        pub kernel_version: String,
        pub architecture: String,
        pub cpu: CpuInfo,
        pub memory: MemoryInfo,
        pub uptime_seconds: f64,
    }

    pub fn collect() -> io::Result<SystemInfo> {
        fn read_trimmed(path: &Path) -> io::Result<String> {
            Ok(fs::read_to_string(path)?.trim().to_string())
        }
        fn read_to_string(path: &Path) -> io::Result<String> {
            fs::read_to_string(path).map_err(|e| {
                io::Error::new(e.kind(), format!("failed to read {}: {e}", path.display()))
            })
        }
        fn parse_uptime(raw: &str) -> Option<f64> {
            raw.split_whitespace().next()?.parse::<f64>().ok()
        }
        fn parse_meminfo(raw: &str) -> Option<MemoryInfo> {
            let mut total = None;
            let mut free = None;
            let mut available = None;
            for line in raw.lines() {
                let mut parts = line.split_whitespace();
                let Some(key) = parts.next() else {
                    continue;
                };
                match key {
                    "MemTotal:" => total = parse_meminfo_value(parts.next()),
                    "MemFree:" => free = parse_meminfo_value(parts.next()),
                    "MemAvailable:" => available = parse_meminfo_value(parts.next()),
                    _ => {}
                }
            }
            match (total, free, available) {
                (Some(t), Some(f), Some(a)) => Some(MemoryInfo {
                    total_kb: t,
                    free_kb: f,
                    available_kb: a,
                }),
                _ => None,
            }
        }
        fn parse_meminfo_value(value: Option<&str>) -> Option<u64> {
            value.and_then(|v| v.parse::<u64>().ok())
        }
        fn parse_cpuinfo_model(raw: &str) -> Option<String> {
            for line in raw.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim() == "model name" {
                        let v = v.trim();
                        if !v.is_empty() {
                            return Some(v.to_string());
                        }
                    }
                }
            }
            None
        }
        fn count_cpuinfo_processors(raw: &str) -> Option<usize> {
            let count = raw
                .lines()
                .filter_map(|l| l.split_once(':'))
                .filter(|(k, _)| k.trim() == "processor")
                .count();
            if count == 0 {
                None
            } else {
                Some(count)
            }
        }
        fn parse_cpu_count(list: &str) -> Option<usize> {
            let mut count = 0;
            for part in list.trim().split(',') {
                let part = part.trim();
                if part.is_empty() {
                    return None;
                }
                match part.split_once('-') {
                    Some((s, e)) => {
                        let s: usize = s.parse().ok()?;
                        let e: usize = e.parse().ok()?;
                        if e < s {
                            return None;
                        }
                        count += e - s + 1;
                    }
                    None => {
                        part.parse::<usize>().ok()?;
                        count += 1;
                    }
                }
            }
            if count == 0 {
                None
            } else {
                Some(count)
            }
        }

        let hostname = read_trimmed(Path::new("/proc/sys/kernel/hostname"))?;
        let kernel_release = read_trimmed(Path::new("/proc/sys/kernel/osrelease"))?;
        let kernel_version = read_trimmed(Path::new("/proc/sys/kernel/version"))?;
        let architecture = read_trimmed(Path::new("/proc/sys/kernel/arch"))?;
        let uptime_raw = read_trimmed(Path::new("/proc/uptime"))?;
        let uptime_seconds = parse_uptime(&uptime_raw)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc/uptime"))?;
        let meminfo = read_to_string(Path::new("/proc/meminfo"))?;
        let memory = parse_meminfo(&meminfo)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc/meminfo"))?;
        let cpuinfo = read_to_string(Path::new("/proc/cpuinfo")).unwrap_or_default();
        let online = read_trimmed(Path::new("/sys/devices/system/cpu/online")).unwrap_or_default();
        let logical_cores = parse_cpu_count(&online)
            .or_else(|| count_cpuinfo_processors(&cpuinfo))
            .unwrap_or(1);

        Ok(SystemInfo {
            hostname,
            kernel_release,
            kernel_version,
            architecture,
            cpu: CpuInfo {
                model: parse_cpuinfo_model(&cpuinfo),
                logical_cores,
            },
            memory,
            uptime_seconds,
        })
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: igris-system-provider <socket_path> [fs_root] [writable_paths...]");
        std::process::exit(1);
    }
    let socket_path = PathBuf::from(&args[1]);
    let fs_root = PathBuf::from("/");
    let writable_paths: Vec<PathBuf> = vec![];

    run_provider_server(
        &socket_path,
        &fs_root,
        &writable_paths,
        move |req| match req.op.as_str() {
            igris_proto::OP_SYSTEM_INFO => {
                let info = system_ops::collect()
                    .map_err(|e| (error_code::INTERNAL.to_string(), e.to_string()))?;
                serde_json::to_value(info).map_err(|_| {
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
