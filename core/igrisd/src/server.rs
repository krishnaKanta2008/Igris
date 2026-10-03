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

        Ok(Self {
            listener,
            socket_path: config.socket_path.clone(),
            shared: Shared {
                policy: Arc::new(policy),
                audit: Arc::new(Mutex::new(audit)),
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

    match dispatch(&request.op, &request.params) {
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
        Err(message) => {
            record(
                shared,
                peer,
                Some(request.id.clone()),
                Some(request.op.clone()),
                Decision::Allow,
                AuditResult::Error,
            );
            Response::error(Some(request.id.clone()), error_code::INTERNAL, message)
        }
    }
}

/// Route an allowed operation to its provider.
fn dispatch(op: &str, _params: &serde_json::Value) -> Result<serde_json::Value, String> {
    match op {
        igris_proto::OP_SYSTEM_INFO => {
            let info = system_info::collect().map_err(|e| e.to_string())?;
            serde_json::to_value(info).map_err(|e| e.to_string())
        }
        other => Err(format!("unsupported operation {other:?}")),
    }
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
    fn dispatch_returns_system_info() {
        let value = dispatch(igris_proto::OP_SYSTEM_INFO, &serde_json::json!({}))
            .expect("system.info dispatches");
        assert!(value.get("hostname").is_some());
        assert!(value.get("memory").is_some());
    }

    #[test]
    fn dispatch_rejects_unknown_operation() {
        assert!(dispatch("fs.read", &serde_json::json!({})).is_err());
    }
}
