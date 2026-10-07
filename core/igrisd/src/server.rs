//! Unix domain socket server and request dispatch.
//!
//! The server accepts framed JSON requests, treats every byte from the client
//! as untrusted, and applies this pipeline in order:
//!
//! 1. frame and size check (oversized requests are rejected before the body is read),
//! 2. JSON parse,
//! 3. protocol validation (version, id, params, supported operation),
//! 4. permission decision (default deny),
//! 5. dispatch to the provider,
//! 6. one audit record per request.
//!
//! Connections are handled on their own thread; the audit log is shared behind
//! a mutex. The socket is created with `0600` permissions so only the owning
//! user can connect.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use igris_permd::{Decision, Policy};
use igris_proto::{
    error_code, read_frame, validate_request, write_response, ReadFrame, Request, Response,
    MAX_REQUEST_SIZE, MAX_RESPONSE_SIZE,
};

use crate::audit::{now_rfc3339, AuditLog, AuditRecord, AuditResult};
use crate::config::Config;
use crate::providers::fs;
use crate::providers::process;
use crate::providers::system_info;

/// Idle timeout for a single connection.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
/// Accept-loop poll interval while the listener is non-blocking.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// State shared with connection-handling threads.
#[derive(Clone)]
struct Shared {
    policy: Arc<Policy>,
    audit: Arc<Mutex<AuditLog>>,
    /// Canonical filesystem root for filesystem tools.
    fs_root: PathBuf,
    /// Canonical paths explicitly permitted for filesystem writes/deletes.
    writable_paths: Vec<PathBuf>,
}

/// The daemon listener and its shared state.
pub struct Server {
    listener: UnixListener,
    socket_path: PathBuf,
    shared: Shared,
    running: Arc<AtomicBool>,
}

impl Server {
    /// Bind the Unix socket and open the audit log.
    ///
    /// Creates parent directories with `0700` permissions, removes a stale
    /// socket file, and sets the socket to `0600`.
    pub fn bind(config: &Config, policy: Policy) -> io::Result<Self> {
        let audit = AuditLog::open(&config.audit_log_path)?;

        if let Some(parent) = config.socket_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        remove_stale_socket(&config.socket_path)?;
        let listener = UnixListener::bind(&config.socket_path)?;
        std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;

        // Ensure the filesystem root exists and is stored in canonical form
        // so containment checks cannot be confused by symlinks or `..`.
        std::fs::create_dir_all(&config.fs_root)?;
        let fs_root = config.fs_root.canonicalize()?;

        let mut writable_paths = Vec::with_capacity(config.writable_paths.len());

        for path in &config.writable_paths {
            let canonical = path.canonicalize()?;

            if !canonical.starts_with(&fs_root) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "configured writable path escapes filesystem root",
                ));
            }

            writable_paths.push(canonical);
        }

        // Writable paths must be existing directories; otherwise they cannot
        // serve as a writable subtree root.
        for canonical in &writable_paths {
            if !canonical.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "configured writable path is not a directory",
                ));
            }
        }

        Ok(Self {
            listener,
            socket_path: config.socket_path.clone(),
            shared: Shared {
                policy: Arc::new(policy),
                audit: Arc::new(Mutex::new(audit)),
                fs_root,
                writable_paths,
            },
            running: Arc::new(AtomicBool::new(true)),
        })
    }

    /// The bound socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Request the accept loop to stop after the current poll iteration.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Run the blocking accept loop until [`Server::shutdown`] is called.
    pub fn run(&self) -> io::Result<()> {
        while self.running.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let shared = self.shared.clone();
                    thread::spawn(move || {
                        if let Err(e) = serve_stream(stream, &shared) {
                            eprintln!("igrisd: connection error: {e}");
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL_INTERVAL);
                }
                Err(e) => {
                    eprintln!("igrisd: accept error: {e}");
                    thread::sleep(POLL_INTERVAL);
                }
            }
        }
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Serve one client connection until it disconnects or a fatal error occurs.
fn serve_stream(mut stream: UnixStream, shared: &Shared) -> io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    let peer = stream.peer_addr().ok().map(|a| format!("{a:?}"));

    loop {
        let frame = match read_frame(&mut stream, MAX_REQUEST_SIZE) {
            Ok(frame) => frame,
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::ConnectionReset =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        match frame {
            ReadFrame::Closed => return Ok(()),
            ReadFrame::TooLarge { declared } => {
                record(
                    shared,
                    &peer,
                    None,
                    None,
                    Decision::Deny,
                    AuditResult::Error,
                );
                let response = Response::error(
                    None,
                    error_code::TOO_LARGE,
                    format!(
                        "request declared {declared} bytes, exceeding the {MAX_REQUEST_SIZE}-byte maximum"
                    ),
                );
                // The stream cannot be resynchronised after skipping a body.
                let _ = write_response(&mut stream, &response, MAX_RESPONSE_SIZE);
                return Ok(());
            }
            ReadFrame::Received(bytes) => {
                let response = handle_payload(&bytes, shared, &peer);
                if write_response(&mut stream, &response, MAX_RESPONSE_SIZE).is_err() {
                    // Client disconnected before reading the response.
                    return Ok(());
                }
            }
        }
    }
}

/// Parse, validate, authorize, and execute one request payload.
fn handle_payload(bytes: &[u8], shared: &Shared, peer: &Option<String>) -> Response {
    let request: Request = match serde_json::from_slice(bytes) {
        Ok(request) => request,
        Err(e) => {
            record(shared, peer, None, None, Decision::Deny, AuditResult::Error);
            return Response::error(
                None,
                error_code::BAD_REQUEST,
                format!("malformed request: {e}"),
            );
        }
    };

    let id_for_error = if request.id.is_empty() {
        None
    } else {
        Some(request.id.clone())
    };

    if let Err(e) = validate_request(&request) {
        record(
            shared,
            peer,
            id_for_error.clone(),
            Some(request.op.clone()),
            Decision::Deny,
            AuditResult::Error,
        );
        return Response::error(id_for_error, e.code, e.message);
    }

    if let Err(e) = igris_proto::validate_operation_params(&request.op, &request.params) {
        record(
            shared,
            peer,
            id_for_error.clone(),
            Some(request.op.clone()),
            Decision::Deny,
            AuditResult::Error,
        );
        return Response::error(id_for_error, e.code, e.message);
    }

    let decision = shared.policy.evaluate(&request.op);
    if decision == Decision::Deny {
        record(
            shared,
            peer,
            Some(request.id.clone()),
            Some(request.op.clone()),
            Decision::Deny,
            AuditResult::Denied,
        );
        return Response::error(
            Some(request.id.clone()),
            error_code::DENIED,
            format!("operation {:?} denied by policy", request.op),
        );
    }

    match dispatch(
        &request.op,
        &request.params,
        &shared.fs_root,
        &shared.writable_paths,
    ) {
        Ok(result) => {
            record(
                shared,
                peer,
                Some(request.id.clone()),
                Some(request.op.clone()),
                Decision::Allow,
                AuditResult::Success,
            );
            Response::success(request.id.clone(), result)
        }
        Err(failure) => {
            record(
                shared,
                peer,
                Some(request.id.clone()),
                Some(request.op.clone()),
                if failure.denied {
                    Decision::Deny
                } else {
                    Decision::Allow
                },
                AuditResult::Error,
            );
            Response::error(Some(request.id.clone()), failure.code, failure.message)
        }
    }
}

/// Route an allowed operation to its provider.
fn dispatch(
    op: &str,
    params: &serde_json::Value,
    fs_root: &Path,
    writable_paths: &[PathBuf],
) -> Result<serde_json::Value, DispatchFailure> {
    match op {
        igris_proto::OP_SYSTEM_INFO => {
            let info = system_info::collect().map_err(|e| DispatchFailure {
                code: error_code::INTERNAL,
                message: sanitize_internal(&e.to_string()),
                denied: false,
            })?;
            serde_json::to_value(info).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode system information",
                denied: false,
            })
        }
        igris_proto::OP_FS_LIST => {
            let result = fs::list(fs_root, params).map_err(DispatchFailure::from)?;
            serde_json::to_value(result).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode fs.list result",
                denied: false,
            })
        }
        igris_proto::OP_FS_STAT => {
            let result = fs::stat(fs_root, params).map_err(DispatchFailure::from)?;
            serde_json::to_value(result).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode fs.stat result",
                denied: false,
            })
        }
        igris_proto::OP_FS_READ => {
            let result = fs::read(fs_root, params).map_err(DispatchFailure::from)?;
            serde_json::to_value(result).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode fs.read result",
                denied: false,
            })
        }
        igris_proto::OP_FS_WRITE => {
            let result =
                fs::write(fs_root, writable_paths, params).map_err(DispatchFailure::from)?;
            serde_json::to_value(result).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode fs.write result",
                denied: false,
            })
        }
        igris_proto::OP_FS_DELETE => {
            let result =
                fs::delete(fs_root, writable_paths, params).map_err(DispatchFailure::from)?;
            serde_json::to_value(result).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode fs.delete result",
                denied: false,
            })
        }
        igris_proto::OP_PROCESS_LIST => {
            let result = process::list(params).map_err(DispatchFailure::from)?;
            serde_json::to_value(result).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode process.list result",
                denied: false,
            })
        }
        igris_proto::OP_PROCESS_STAT => {
            let result = process::stat(params).map_err(DispatchFailure::from)?;
            serde_json::to_value(result).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode process.stat result",
                denied: false,
            })
        }
        igris_proto::OP_PROCESS_CHILDREN => {
            let result = process::children(params).map_err(DispatchFailure::from)?;
            serde_json::to_value(result).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode process.children result",
                denied: false,
            })
        }
        igris_proto::OP_PROC_SIGNAL => {
            let result = process::signal(params).map_err(DispatchFailure::from)?;
            serde_json::to_value(result).map_err(|_| DispatchFailure {
                code: error_code::INTERNAL,
                message: "failed to encode process.signal result",
                denied: false,
            })
        }
        _other => Err(DispatchFailure {
            code: error_code::UNKNOWN_OPERATION,
            message: "unsupported operation",
            denied: true,
        }),
    }
}

/// Provider/dispatch error mapped to a protocol error body and audit decision.
#[derive(Debug)]
struct DispatchFailure {
    code: &'static str,
    message: &'static str,
    /// `true` when the request itself was rejected (audit `deny`).
    denied: bool,
}

impl From<fs::FsFailure> for DispatchFailure {
    fn from(f: fs::FsFailure) -> Self {
        Self {
            code: f.code,
            message: f.message,
            denied: f.denied,
        }
    }
}

impl From<process::ProcessFailure> for DispatchFailure {
    fn from(f: process::ProcessFailure) -> Self {
        Self {
            code: f.code,
            message: f.message,
            denied: f.denied,
        }
    }
}

/// Provider errors from `system.info` carry OS text; keep it, it is about the
/// local machine the user already owns, but never include raw paths for fs.
fn sanitize_internal(message: &str) -> &'static str {
    let _ = message;
    "system information unavailable"
}

/// Append one audit record, ignoring a poisoned lock (logging must not abort).
fn record(
    shared: &Shared,
    peer: &Option<String>,
    request_id: Option<String>,
    operation: Option<String>,
    decision: Decision,
    result: AuditResult,
) {
    let entry = AuditRecord {
        timestamp: now_rfc3339(),
        request_id,
        operation,
        decision: decision.as_str().to_string(),
        result,
        peer: peer.clone(),
    };
    if let Ok(mut log) = shared.audit.lock() {
        let _ = log.record(&entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_paths_must_remain_inside_fs_root() {
        let root = std::env::temp_dir().join(format!("igris-server-test-{}", std::process::id()));

        let writable = root.join("writable");
        std::fs::create_dir_all(&writable).expect("create test directories");

        let config = Config::with_writable_paths(
            root.join("igrisd.sock"),
            root.join("audit.log"),
            &root,
            [&writable],
        );

        let server = Server::bind(&config, Policy::milestone_three())
            .expect("valid writable path should be accepted");

        assert_eq!(server.shared.writable_paths.len(), 1);
        assert_eq!(
            server.shared.writable_paths[0],
            writable.canonicalize().unwrap()
        );

        drop(server);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn writable_path_outside_fs_root_is_rejected() {
        let root =
            std::env::temp_dir().join(format!("igris-server-test-outside-{}", std::process::id()));

        let fs_root = root.join("root");
        let outside = root.join("outside");

        std::fs::create_dir_all(&fs_root).expect("create fs root");
        std::fs::create_dir_all(&outside).expect("create outside directory");

        let config = Config::with_writable_paths(
            root.join("igrisd.sock"),
            root.join("audit.log"),
            &fs_root,
            [&outside],
        );

        let result = Server::bind(&config, Policy::milestone_three());

        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dispatch_returns_system_info() {
        let value = dispatch(
            igris_proto::OP_SYSTEM_INFO,
            &serde_json::json!({}),
            Path::new("/"),
            &[],
        )
        .expect("system.info dispatches");
        assert!(value.get("hostname").is_some());
        assert!(value.get("memory").is_some());
    }

    #[test]
    fn dispatch_rejects_unknown_operation() {
        assert!(dispatch("fs.write", &serde_json::json!({}), Path::new("/"), &[],).is_err());
    }
}
