//! Unix domain socket server and request dispatch.
//!
//! The server accepts framed JSON requests, treats every byte from the client
//! as untrusted, and applies this pipeline in order:
//!
//! 1. frame and size check (oversized requests are rejected before the body is read),
//! 2. JSON parse,
//! 3. protocol validation (version, id, params, supported operation),
//! 4. tool registry validation (tool exists, schema validation),
//! 5. session capability authorization (if session_id provided),
//! 6. confirmation gate (if confirmation required),
//! 7. permission decision (default deny),
//! 8. dispatch to the sandboxed provider,
//! 9. one audit record per request with correlation ID.
//!
//! Connections are handled on their own thread; the audit log is shared behind
//! a mutex. The socket is created with `0600` permissions so only the owning
//! user can connect.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use igris_confirmation::{ConfirmationGate, ConfirmationToken};
use igris_permd::{Decision, Policy};
use igris_proto::{
    error_code, read_frame, validate_operation_params, validate_request, write_response, ReadFrame,
    Request, Response, MAX_REQUEST_SIZE, MAX_RESPONSE_SIZE,
};
use igris_session::{SessionId, SessionManager};
use igris_tool_registry::{ToolId, ToolRegistry};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::str::FromStr;

use crate::audit::{now_rfc3339, AuditLog, AuditRecord, AuditResult};
use crate::config::Config;
use crate::sandboxed_providers::ProviderManager;

/// Peer credentials obtained from SO_PEERCRED.
#[derive(Debug, Clone, Copy)]
#[expect(dead_code)]
struct PeerCred {
    pid: u64,
    uid: u64,
    gid: u64,
}

/// Check if target_pid is a descendant of ancestor_pid by walking the process tree.
/// Returns true if target_pid is a descendant (child, grandchild, etc.) of ancestor_pid.
/// Returns false if target_pid equals ancestor_pid (self), if process not found, or if not a descendant.
pub(crate) fn is_descendant_of(target_pid: u64, ancestor_pid: u64) -> bool {
    if target_pid == ancestor_pid {
        return false; // Self-signaling is not allowed
    }
    let mut current = target_pid;
    // Walk up the process tree, max 256 steps to avoid infinite loops
    for _ in 0..256 {
        if current == 0 || current == 1 {
            // Reached init process (PID 1) or invalid PID
            return false;
        }
        if current == ancestor_pid {
            return true; // Found ancestor in the chain
        }
        // Read PPID from /proc/<current>/stat
        let stat_path = format!("/proc/{}/stat", current);
        let stat_content = match std::fs::read_to_string(&stat_path) {
            Ok(content) => content,
            Err(_) => return false, // Process not found or cannot read
        };
        // Parse PPID from stat correctly, handling process names with spaces/parentheses.
        // Format: pid (comm) state ppid ...
        // The comm field is enclosed in parentheses and may contain spaces.
        // Find the closing ')' of the comm field.
        let close_paren = match stat_content.rfind(')') {
            Some(pos) => pos,
            None => return false, // Malformed stat line
        };
        // Fields after comm: state ppid ...
        let after_comm = &stat_content[close_paren + 1..].trim_start();
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // fields[0] = state, fields[1] = ppid
        if fields.len() < 2 {
            return false;
        }
        current = match fields[1].parse::<u64>() {
            Ok(ppid) => ppid,
            Err(_) => return false,
        };
    }
    false // Max depth exceeded
}

/// Idle timeout for a single connection.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
/// Accept-loop poll interval while the listener is non-blocking.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// State shared with connection-handling threads.
#[derive(Clone)]
#[expect(dead_code)]
struct Shared {
    policy: Arc<Policy>,
    audit: Arc<Mutex<AuditLog>>,
    /// Canonical filesystem root for filesystem tools.
    fs_root: PathBuf,
    /// Canonical paths explicitly permitted for filesystem writes/deletes.
    writable_paths: Vec<PathBuf>,
    /// Sandboxed provider manager.
    providers: Arc<Mutex<ProviderManager>>,
    /// Tool registry for schema validation.
    tool_registry: Arc<ToolRegistry>,
    /// Session manager for agent capability authorization.
    session_manager: Arc<SessionManager>,
    /// Confirmation gate for sensitive operations.
    confirmation_gate: Arc<ConfirmationGate>,
    /// Correlation ID counter for audit trail.
    correlation_id: Arc<AtomicU64>,
    /// If true, enable test mode (auto-approve confirmations, etc.).
    test_mode: bool,
    /// Daemon configuration (for capability grants, etc.).
    config: Arc<Config>,
}

/// The daemon listener and its shared state.
pub struct Server {
    listener: UnixListener,
    socket_path: PathBuf,
    shared: Shared,
    running: Arc<AtomicBool>,
    next_connection_id: AtomicU64,
}

impl Server {
    /// Access the session manager for test purposes.
    pub fn session_manager(&self) -> Arc<SessionManager> {
        self.shared.session_manager.clone()
    }

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

        // Create provider directory under the fs_root for sockets
        let provider_dir = fs_root.join(".igris-providers");
        let providers = Arc::new(Mutex::new(ProviderManager::spawn_all(
            &fs_root,
            &writable_paths,
            &provider_dir,
            false, // production mode
        )?));

        // Initialize M8 components
        let tool_registry = Arc::new(igris_tool_registry::default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(
            ConfirmationGate::new(session_manager.clone(), tool_registry.clone())
                .with_test_mode(false),
        );
        let config_arc = Arc::new(config.clone());

        Ok(Self {
            listener,
            socket_path: config.socket_path.clone(),
            shared: Shared {
                policy: Arc::new(policy),
                audit: Arc::new(Mutex::new(audit)),
                fs_root,
                writable_paths,
                providers,
                tool_registry,
                session_manager,
                confirmation_gate,
                correlation_id: Arc::new(AtomicU64::new(1)),
                test_mode: false,
                config: config_arc,
            },
            running: Arc::new(AtomicBool::new(true)),
            next_connection_id: AtomicU64::new(1),
        })
    }

    /// Test-only bind that skips sandboxed provider spawning.
    ///
    /// This is for tests that only need to verify config validation without
    /// requiring sandbox permissions.
    pub fn bind_test(config: &Config, policy: Policy) -> io::Result<Self> {
        // Create audit log parent directory first
        if let Some(parent) = config.audit_log_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

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

        for canonical in &writable_paths {
            if !canonical.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "configured writable path is not a directory",
                ));
            }
        }

        // Create provider directory and spawn providers in test mode
        let provider_dir = fs_root.join(".igris-providers");
        std::fs::create_dir_all(&provider_dir)?;
        let providers = Arc::new(Mutex::new(ProviderManager::spawn_all(
            &fs_root,
            &writable_paths,
            &provider_dir,
            true, // test mode
        )?));

        // Initialize M8 components
        let tool_registry = Arc::new(igris_tool_registry::default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(
            ConfirmationGate::new(session_manager.clone(), tool_registry.clone())
                .with_test_mode(true),
        );
        let config_arc = Arc::new(config.clone());

        Ok(Self {
            listener,
            socket_path: config.socket_path.clone(),
            shared: Shared {
                policy: Arc::new(policy),
                audit: Arc::new(Mutex::new(audit)),
                fs_root,
                writable_paths,
                providers,
                tool_registry,
                session_manager,
                confirmation_gate,
                correlation_id: Arc::new(AtomicU64::new(1)),
                test_mode: true,
                config: config_arc,
            },
            running: Arc::new(AtomicBool::new(true)),
            next_connection_id: AtomicU64::new(1),
        })
    }

    /// Test-only bind that creates a server with production confirmation settings
    /// but skips provider spawning.
    ///
    /// This is for tests that need production confirmation behavior without
    /// requiring sandbox permissions or provider spawning.
    pub fn bind_prod_test(config: &Config, policy: Policy) -> io::Result<Self> {
        // Create audit log parent directory first
        if let Some(parent) = config.audit_log_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

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

        for canonical in &writable_paths {
            if !canonical.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "configured writable path is not a directory",
                ));
            }
        }

        // Create empty provider manager (no providers spawned)
        let provider_dir = fs_root.join(".igris-providers");
        std::fs::create_dir_all(&provider_dir)?;
        let providers = Arc::new(Mutex::new(ProviderManager {
            providers: Vec::new(),
            provider_dir,
        }));

        // Initialize M8 components with production confirmation settings (test_mode = false)
        let tool_registry = Arc::new(igris_tool_registry::default_registry());
        let session_manager = Arc::new(SessionManager::new(tool_registry.clone()));
        let confirmation_gate = Arc::new(
            ConfirmationGate::new(session_manager.clone(), tool_registry.clone())
                .with_test_mode(false),
        );

        Ok(Self {
            listener,
            socket_path: config.socket_path.clone(),
            shared: Shared {
                policy: Arc::new(policy),
                audit: Arc::new(Mutex::new(AuditLog::open(&config.audit_log_path)?)),
                fs_root,
                writable_paths,
                providers,
                tool_registry: Arc::new(igris_tool_registry::default_registry()),
                session_manager: Arc::new(SessionManager::new(Arc::new(
                    igris_tool_registry::default_registry(),
                ))),
                confirmation_gate,
                correlation_id: Arc::new(AtomicU64::new(1)),
                test_mode: false,
                config: Arc::new(config.clone()),
            },
            running: Arc::new(AtomicBool::new(true)),
            next_connection_id: AtomicU64::new(1),
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
                    let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
                    thread::spawn(move || {
                        if let Err(e) = serve_stream(stream, &shared, connection_id) {
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
fn serve_stream(mut stream: UnixStream, shared: &Shared, connection_id: u64) -> io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    let peer = stream.peer_addr().ok().map(|a| format!("{a:?}"));

    // Get peer credentials (PID, UID, GID) from the kernel via SO_PEERCRED.
    // This is the only trustworthy way to identify the connecting process.
    let peer_cred = getsockopt(&stream, PeerCredentials)
        .map(|c| PeerCred {
            pid: c.pid() as u64,
            uid: c.uid() as u64,
            gid: c.gid() as u64,
        })
        .ok();

    let result = (|| {
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
                    record_audit(
                        shared,
                        &peer,
                        None,
                        None,
                        None,
                        Decision::Deny,
                        AuditResult::Error,
                        "oversized_request",
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
                    let response = handle_payload(&bytes, shared, &peer, &peer_cred, connection_id);
                    if write_response(&mut stream, &response, MAX_RESPONSE_SIZE).is_err() {
                        // Client disconnected before reading the response.
                        return Ok(());
                    }
                }
            }
        }
    })();

    // Clean up provider resources owned by this connection on disconnect.
    if let Ok(providers) = shared.providers.lock() {
        for provider in &providers.providers {
            if provider.is_alive() {
                // Note: The provider handles its own connection cleanup internally
                // when the client disconnects from the provider socket.
            }
        }
    }

    result
}

/// Generate a correlation ID for audit trail.
fn next_correlation_id(shared: &Shared) -> String {
    let id = shared.correlation_id.fetch_add(1, Ordering::Relaxed);
    format!("cid-{:016x}", id)
}

/// Parse, validate, authorize, and execute one request payload.
fn handle_payload(
    bytes: &[u8],
    shared: &Shared,
    peer: &Option<String>,
    peer_cred: &Option<PeerCred>,
    _connection_id: u64,
) -> Response {
    let correlation_id = next_correlation_id(shared);

    let request: Request = match serde_json::from_slice(bytes) {
        Ok(request) => request,
        Err(e) => {
            record_audit(
                shared,
                peer,
                None,
                None,
                Some(correlation_id.clone()),
                Decision::Deny,
                AuditResult::Error,
                "malformed_request",
            );
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

    // Step 1: Protocol validation (version, id, params, supported operation)
    if let Err(e) = validate_request(&request) {
        record_audit(
            shared,
            peer,
            id_for_error.clone(),
            Some(request.op.clone()),
            Some(correlation_id.clone()),
            Decision::Deny,
            AuditResult::Error,
            "protocol_validation_failed",
        );
        return Response::error(id_for_error, e.code, e.message);
    }

    // Step 2: Tool registry validation
    let tool_id = ToolId::new(&request.op);
    let tool = match shared.tool_registry.get(&tool_id) {
        Some(t) => t,
        None => {
            record_audit(
                shared,
                peer,
                id_for_error.clone(),
                Some(request.op.clone()),
                Some(correlation_id.clone()),
                Decision::Deny,
                AuditResult::Error,
                "unknown_tool",
            );
            return Response::error(
                id_for_error,
                error_code::TOOL_NOT_FOUND,
                format!("unknown tool: {}", request.op),
            );
        }
    };

    // Step 3: Validate operation parameters against tool schema
    if let Err(e) = validate_operation_params(&request.op, &request.params) {
        record_audit(
            shared,
            peer,
            id_for_error.clone(),
            Some(request.op.clone()),
            Some(correlation_id.clone()),
            Decision::Deny,
            AuditResult::Error,
            "schema_validation_failed",
        );
        return Response::error(id_for_error, e.code, e.message);
    }

    // Step 4: Session capability authorization (if session_id provided)
    let session_id = request
        .session_id
        .as_ref()
        .and_then(|s| SessionId::from_str(s).ok());
    if let Some(ref sid) = session_id {
        if let Err(e) = shared.session_manager.validate_capability(sid, &tool_id) {
            let error_code = match e {
                igris_session::SessionError::SessionNotFound(_) => error_code::SESSION_NOT_FOUND,
                igris_session::SessionError::SessionExpired => error_code::SESSION_EXPIRED,
                igris_session::SessionError::SessionRevoked => error_code::SESSION_REVOKED,
                igris_session::SessionError::MissingCapability(_) => error_code::MISSING_CAPABILITY,
                _ => error_code::SESSION_NOT_FOUND,
            };
            record_audit(
                shared,
                peer,
                Some(request.id.clone()),
                Some(request.op.clone()),
                Some(correlation_id.clone()),
                Decision::Deny,
                AuditResult::Denied,
                "capability_check_failed",
            );
            return Response::error(
                Some(request.id.clone()),
                error_code,
                format!("session capability check failed: {}", e),
            );
        }
    }

    // Step 5: Confirmation gate (if tool requires confirmation)
    // In test mode, skip confirmation for all tools (auto-approve for testing)
    let skip_confirmation = shared.test_mode;

    // Only apply confirmation logic for tools that require it
    if tool.requires_confirmation() && !skip_confirmation {
        let confirmation_token = match request.confirmation_token.as_ref() {
            Some(token_str) => match token_str.parse::<ConfirmationToken>() {
                Ok(token) => Some(Ok(token)),
                Err(_) => Some(Err(error_code::CONFIRMATION_INVALID)),
            },
            None => None,
        };

        match confirmation_token {
            Some(Ok(token)) => {
                // Token provided - validate and consume
                if let Some(ref sid) = session_id {
                    if let Err(e) = shared.confirmation_gate.validate_and_consume(
                        sid,
                        &tool_id,
                        &request.params,
                        &token,
                    ) {
                        let error_code = match e {
                            igris_confirmation::ConfirmationError::ConfirmationNotFound(_) => {
                                error_code::CONFIRMATION_INVALID
                            }
                            igris_confirmation::ConfirmationError::ConfirmationAlreadyUsed => {
                                error_code::CONFIRMATION_INVALID
                            }
                            igris_confirmation::ConfirmationError::ConfirmationExpired => {
                                error_code::CONFIRMATION_INVALID
                            }
                            igris_confirmation::ConfirmationError::ConfirmationMismatch => {
                                error_code::CONFIRMATION_INVALID
                            }
                            _ => error_code::CONFIRMATION_INVALID,
                        };
                        record_audit(
                            shared,
                            peer,
                            Some(request.id.clone()),
                            Some(request.op.clone()),
                            Some(correlation_id.clone()),
                            Decision::Deny,
                            AuditResult::Denied,
                            "confirmation_validation_failed",
                        );
                        return Response::error(
                            Some(request.id.clone()),
                            error_code,
                            format!("confirmation validation failed: {}", e),
                        );
                    }
                } else {
                    record_audit(
                        shared,
                        peer,
                        Some(request.id.clone()),
                        Some(request.op.clone()),
                        Some(correlation_id.clone()),
                        Decision::Deny,
                        AuditResult::Denied,
                        "confirmation_no_session",
                    );
                    return Response::error(
                        Some(request.id.clone()),
                        error_code::CONFIRMATION_REQUIRED,
                        "confirmation token provided but no session_id".to_string(),
                    );
                }
            }
            Some(Err(_)) => {
                // Invalid token format
                record_audit(
                    shared,
                    peer,
                    Some(request.id.clone()),
                    Some(request.op.clone()),
                    Some(correlation_id.clone()),
                    Decision::Deny,
                    AuditResult::Denied,
                    "confirmation_required",
                );
                return Response::error(
                    Some(request.id.clone()),
                    error_code::CONFIRMATION_INVALID,
                    "invalid confirmation token format".to_string(),
                );
            }
            None => {
                // No token provided - require confirmation
                record_audit(
                    shared,
                    peer,
                    Some(request.id.clone()),
                    Some(request.op.clone()),
                    Some(correlation_id.clone()),
                    Decision::Deny,
                    AuditResult::Denied,
                    "confirmation_required",
                );
                return Response::error(
                Some(request.id.clone()),
                error_code::CONFIRMATION_REQUIRED,
                format!(
                    "confirmation required for operation {}: use confirmation_id from prior request",
                    request.op
                ),
            );
            }
        }
    }

    // Step 6: Permission decision (default deny)
    let decision = shared.policy.evaluate(&request.op);
    if decision == Decision::Deny {
        record_audit(
            shared,
            peer,
            Some(request.id.clone()),
            Some(request.op.clone()),
            Some(correlation_id.clone()),
            Decision::Deny,
            AuditResult::Denied,
            "policy_denied",
        );
        return Response::error(
            Some(request.id.clone()),
            error_code::DENIED,
            format!("operation {:?} denied by policy", request.op),
        );
    }

    // Step 6b: Process-signal authorization (if proc.signal operation)
    if request.op == "proc.signal" {
        if let Some(ref sid) = session_id {
            // Verify session ownership first
            let peer_cred = match peer_cred.as_ref() {
                Some(c) => c,
                None => {
                    record_audit(
                        shared,
                        peer,
                        Some(request.id.clone()),
                        Some(request.op.clone()),
                        Some(correlation_id.clone()),
                        Decision::Deny,
                        AuditResult::Error,
                        "peer_credentials_unavailable",
                    );
                    return Response::error(
                        Some(request.id.clone()),
                        error_code::INTERNAL,
                        "cannot verify session ownership without peer credentials".to_string(),
                    );
                }
            };
            if let Err(e) = shared
                .session_manager
                .verify_session_owner(sid, peer_cred.pid)
            {
                record_audit(
                    shared,
                    peer,
                    Some(request.id.clone()),
                    Some(request.op.clone()),
                    Some(correlation_id.clone()),
                    Decision::Deny,
                    AuditResult::Denied,
                    "session_ownership_verification_failed",
                );
                return Response::error(
                    Some(request.id.clone()),
                    error_code::SESSION_NOT_FOUND,
                    format!("session ownership verification failed: {}", e),
                );
            }
            // Get session to access owner_pid
            if let Some(session) = shared.session_manager.get_session(sid) {
                let owner_pid = session.owner_pid;
                // Extract target PID from request params
                if let Some(target_pid) = request.params.get("pid").and_then(|v| v.as_u64()) {
                    // Validate target PID against session owner PID
                    if target_pid == owner_pid {
                        record_audit(
                            shared,
                            peer,
                            Some(request.id.clone()),
                            Some(request.op.clone()),
                            Some(correlation_id.clone()),
                            Decision::Deny,
                            AuditResult::Error,
                            "self_signaling_rejected",
                        );
                        return Response::error(
                            Some(request.id.clone()),
                            error_code::BAD_REQUEST,
                            "signaling self is not permitted".to_string(),
                        );
                    }
                    // Ancestry check: verify target is a descendant of session owner
                    // First check if the target process exists; if not, skip ancestry check
                    // and let the provider return NOT_FOUND.
                    let stat_path = format!("/proc/{}/stat", target_pid);
                    if std::fs::read_to_string(&stat_path).is_ok() {
                        // Process exists; verify it's a descendant
                        if !is_descendant_of(target_pid, owner_pid) {
                            record_audit(
                                shared,
                                peer,
                                Some(request.id.clone()),
                                Some(request.op.clone()),
                                Some(correlation_id.clone()),
                                Decision::Deny,
                                AuditResult::Denied,
                                "target_outside_process_boundary",
                            );
                            return Response::error(
                                Some(request.id.clone()),
                                error_code::DENIED,
                                "target process is not a descendant of the session owner"
                                    .to_string(),
                            );
                        }
                    }
                    // Note: The provider also performs ancestry check via pidfd to eliminate
                    // TOCTOU between authorization and signal delivery.
                }
            } else {
                record_audit(
                    shared,
                    peer,
                    Some(request.id.clone()),
                    Some(request.op.clone()),
                    Some(correlation_id.clone()),
                    Decision::Deny,
                    AuditResult::Error,
                    "session_not_found_for_signal",
                );
                return Response::error(
                    Some(request.id.clone()),
                    error_code::SESSION_NOT_FOUND,
                    "session not found for signal authorization".to_string(),
                );
            }
        } else {
            // No session provided - deny proc.signal without session
            record_audit(
                shared,
                peer,
                Some(request.id.clone()),
                Some(request.op.clone()),
                Some(correlation_id.clone()),
                Decision::Deny,
                AuditResult::Error,
                "signal_requires_session",
            );
            return Response::error(
                Some(request.id.clone()),
                error_code::SESSION_NOT_FOUND,
                "proc.signal requires a valid session".to_string(),
            );
        }
    }

    // Step 7: Forward request to sandboxed provider
    let providers = match shared.providers.lock() {
        Ok(p) => p,
        Err(_) => {
            record_audit(
                shared,
                peer,
                Some(request.id.clone()),
                Some(request.op.clone()),
                Some(correlation_id.clone()),
                Decision::Allow,
                AuditResult::Error,
                "provider_lock_poisoned",
            );
            return Response::error(
                Some(request.id.clone()),
                error_code::INTERNAL,
                "provider manager lock poisoned",
            );
        }
    };

    // For proc.signal, add owner_pid to request params so provider can do ancestry check via pidfd
    let mut request_to_forward = request.clone();
    if request.op == "proc.signal" {
        if let Some(ref sid) = session_id {
            if let Some(session) = shared.session_manager.get_session(sid) {
                if let Some(params) = request_to_forward.params.as_object_mut() {
                    params.insert(
                        "owner_pid".to_string(),
                        serde_json::json!(session.owner_pid),
                    );
                }
            }
        }
    }

    match providers.forward_request(&request_to_forward) {
        Ok(response) => {
            let audit_result = if response.ok {
                AuditResult::Success
            } else {
                AuditResult::Error
            };
            record_audit(
                shared,
                peer,
                Some(request.id.clone()),
                Some(request.op.clone()),
                Some(correlation_id.clone()),
                Decision::Allow,
                audit_result,
                "success",
            );
            response
        }
        Err(e) => {
            record_audit(
                shared,
                peer,
                Some(request.id.clone()),
                Some(request.op.clone()),
                Some(correlation_id.clone()),
                Decision::Allow,
                AuditResult::Error,
                "provider_error",
            );
            Response::error(
                Some(request.id.clone()),
                error_code::INTERNAL,
                format!("provider error: {}", e),
            )
        }
    }
}

/// Append one audit record with correlation ID, ignoring a poisoned lock (logging must not abort).
#[allow(clippy::too_many_arguments)]
fn record_audit(
    shared: &Shared,
    peer: &Option<String>,
    request_id: Option<String>,
    operation: Option<String>,
    correlation_id: Option<String>,
    decision: Decision,
    result: AuditResult,
    stage: &str,
) {
    let entry = AuditRecord {
        timestamp: now_rfc3339(),
        request_id,
        operation,
        decision: decision.as_str().to_string(),
        result,
        peer: peer.clone(),
        correlation_id,
        stage: Some(stage.to_string()),
    };
    if let Ok(mut log) = shared.audit.lock() {
        let _ = log.record(&entry);
    }
}

#[cfg(test)]
/// Production confirmation gate tests using Server::bind() (not bind_test).
/// These tests verify the production confirmation gate behavior without test-mode auto-approval.
mod production_confirmation_tests {
    use super::*;
    use igris_permd::Policy;
    use igris_proto::{error_code, Request, Response};
    use igris_session::CapabilitySet;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    /// Helper to create a production-mode server for testing.
    /// Uses bind_prod_test() to get production confirmation behavior without spawning providers.
    fn create_prod_server() -> (
        Arc<Server>,
        PathBuf,
        PathBuf,
        PathBuf,
        thread::JoinHandle<()>,
    ) {
        let root = std::env::temp_dir().join(format!("igris-prod-test-{}", std::process::id()));
        let socket_path = root.join("igrisd.sock");
        let audit_path = root.join("audit.log");
        let fs_root = root.join("root");
        let writable = fs_root.join("writable");

        std::fs::create_dir_all(&fs_root).expect("create fs root");
        std::fs::create_dir_all(&writable).expect("create writable");

        let config = Config::with_writable_paths(
            socket_path.clone(),
            audit_path.clone(),
            &fs_root,
            [&writable],
        );

        // Use production bind with test helper - production confirmation settings, no providers
        let server = Arc::new(
            Server::bind_prod_test(&config, Policy::milestone_five(true, true))
                .expect("bind production test server"),
        );

        // Run server in background thread
        let runner = server.clone();
        let handle = thread::spawn(move || {
            let _ = runner.run();
        });

        // Wait for the socket to accept a connection.
        for _ in 0..200 {
            if UnixStream::connect(&socket_path).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }

        (server, socket_path, audit_path, root, handle)
    }

    /// Send a raw request and get response.
    fn send_request(socket_path: &Path, request: Request) -> Response {
        let mut stream = UnixStream::connect(socket_path).expect("connect");
        let payload = serde_json::to_vec(&request).expect("encode request");
        let len = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len).expect("write len");
        stream.write_all(&payload).expect("write payload");

        // Read response frame
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).expect("read len");
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).expect("read body");
        serde_json::from_slice(&buf).expect("parse response")
    }

    /// Create a confirmation-required request (proc.signal) without token.
    fn make_signal_request(session_id: &str, target_pid: u64, token: Option<String>) -> Request {
        let params = serde_json::json!({
            "pid": target_pid,
            "signal": 15,
            "confirm": true
        });

        Request {
            version: 1,
            id: "test-req".to_string(),
            op: "proc.signal".to_string(),
            params,
            session_id: Some(session_id.to_string()),
            confirmation_token: token,
        }
    }

    #[test]
    fn prod_confirmation_missing_token_returns_required() {
        let (server, _socket_path, _audit_path, _root, _handle) = create_prod_server();
        // Use the actual process ID as the session owner to match SO_PEERCRED
        let owner_pid = std::process::id() as u64;
        let session_id = server
            .session_manager()
            .create_session(
                CapabilitySet::from_iter(vec!["process_control".to_string()]),
                owner_pid,
            )
            .unwrap()
            .id
            .to_string();

        // No confirmation_token provided - use a PID that doesn't exist to bypass ancestry check
        let request = make_signal_request(&session_id, 3_999_999, None);
        let response = send_request(server.socket_path(), request);

        eprintln!("DEBUG: response = {:?}", response);
        eprintln!("DEBUG: tool.requires_confirmation() = true"); // proc.signal requires confirmation
        eprintln!("DEBUG: skip_confirmation = false"); // production mode
        assert!(!response.ok, "expected rejection");
        assert_eq!(
            response.error.as_ref().unwrap().code,
            error_code::CONFIRMATION_REQUIRED
        );
        assert!(response
            .error
            .as_ref()
            .unwrap()
            .message
            .contains("confirmation required"));
    }

    #[test]
    fn prod_confirmation_request_not_dispatched_to_provider() {
        let (server, _socket_path, _audit_path, _root, _handle) = create_prod_server();
        let session_id = server
            .session_manager()
            .create_session(
                CapabilitySet::from_iter(vec!["process_control".to_string()]),
                std::process::id() as u64,
            )
            .unwrap()
            .id
            .to_string();

        // Request without token should be rejected at confirmation gate
        let request = make_signal_request(&session_id, std::process::id() as u64, None);
        let response = send_request(server.socket_path(), request);

        // Should be rejected before provider dispatch
        assert!(!response.ok);
        assert_eq!(
            response.error.as_ref().unwrap().code,
            error_code::CONFIRMATION_REQUIRED
        );
        // Provider should never have been called - no "sent" field in response
        assert!(response.result.is_none() || response.result.unwrap().get("sent").is_none());
    }

    #[test]
    fn prod_confirmation_invalid_token_rejected() {
        let (server, _socket_path, _audit_path, _root, _handle) = create_prod_server();
        let session_id = server
            .session_manager()
            .create_session(
                CapabilitySet::from_iter(vec!["process_control".to_string()]),
                std::process::id() as u64,
            )
            .unwrap()
            .id
            .to_string();

        // Invalid token format
        let request = make_signal_request(
            &session_id,
            std::process::id() as u64,
            Some("not-a-valid-uuid".to_string()),
        );
        let response = send_request(server.socket_path(), request);

        assert!(!response.ok);
        assert_eq!(
            response.error.as_ref().unwrap().code,
            error_code::CONFIRMATION_INVALID
        );
    }

    #[test]
    fn prod_confirmation_replayed_token_rejected() {
        use igris_confirmation::ConfirmationGate;
        use igris_session::SessionManager;
        use std::sync::Arc;

        let registry = Arc::new(igris_tool_registry::default_registry());
        let session_mgr = Arc::new(SessionManager::new(registry.clone()));
        let gate = ConfirmationGate::new(session_mgr.clone(), registry.clone());

        let caps = CapabilitySet::from_iter(vec!["process_control".to_string()]);
        let session = session_mgr
            .create_session(caps, std::process::id() as u64)
            .unwrap();

        let tool_id = igris_tool_registry::ToolId::new("proc.signal");
        let args =
            serde_json::json!({"pid": std::process::id() as u64, "signal": 15, "confirm": true});

        let request = gate
            .request_confirmation(&session.id, &tool_id, args.clone())
            .unwrap();
        let decision = gate.approve(&request.id).unwrap();
        let token = decision.token.unwrap();

        // First consumption should succeed
        gate.validate_and_consume(&session.id, &tool_id, &args, &token)
            .unwrap();

        // Second consumption should fail with AlreadyUsed
        let result = gate.validate_and_consume(&session.id, &tool_id, &args, &token);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            igris_confirmation::ConfirmationError::ConfirmationAlreadyUsed
        ));
    }

    #[test]
    #[ignore = "requires provider binaries in PATH (bind_test spawns providers)"]
    fn prod_confirmation_non_confirmation_tools_bypass() {
        // Use bind_test() to get a server with spawned providers.
        // The confirmation gate behavior for non-confirmation tools is identical
        // in test_mode=true and test_mode=false (both skip confirmation for tools
        // that don't require it), so this validates the bypass logic.
        let root = std::env::temp_dir().join(format!("igris-test-bypass-{}", std::process::id()));
        let socket_path = root.join("igrisd.sock");
        let audit_path = root.join("audit.log");
        let fs_root = root.join("root");
        let writable = fs_root.join("writable");

        std::fs::create_dir_all(&fs_root).expect("create fs root");
        std::fs::create_dir_all(&writable).expect("create writable");

        let config = Config::with_writable_paths(
            socket_path.clone(),
            audit_path.clone(),
            &fs_root,
            [&writable],
        );

        let server = Arc::new(
            Server::bind_test(&config, Policy::milestone_five(true, true))
                .expect("bind test server"),
        );

        // Run server in background thread
        let runner = server.clone();
        let _handle = thread::spawn(move || {
            let _ = runner.run();
        });

        // Wait for the socket to accept a connection.
        for _ in 0..200 {
            if UnixStream::connect(&socket_path).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }

        let session_id = server
            .session_manager()
            .create_session(
                CapabilitySet::from_iter(vec!["system_info".to_string()]),
                std::process::id() as u64,
            )
            .unwrap()
            .id
            .to_string();

        // system.info does not require confirmation
        let request = Request {
            version: 1,
            id: "test-req".to_string(),
            op: "system.info".to_string(),
            params: serde_json::json!({}),
            session_id: Some(session_id),
            confirmation_token: None,
        };

        let response = send_request(server.socket_path(), request);
        assert!(
            response.ok,
            "system.info should succeed without confirmation"
        );
        assert!(response.result.is_some());
        assert!(response.result.unwrap().get("hostname").is_some());

        drop(server);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    #[ignore = "requires root privileges for sandbox setup (namespaces, cgroups, seccomp)"]
    fn prod_bind_configures_confirmation_gate_test_mode_false() {
        let root = std::env::temp_dir().join(format!("igris-prod-test-{}", std::process::id()));
        let socket_path = root.join("igrisd.sock");
        let audit_path = root.join("audit.log");
        let fs_root = root.join("root");
        let writable = fs_root.join("writable");

        std::fs::create_dir_all(&fs_root).expect("create fs root");
        std::fs::create_dir_all(&writable).expect("create writable");

        let config = Config::with_writable_paths(
            socket_path.clone(),
            audit_path.clone(),
            &fs_root,
            [&writable],
        );

        // Production bind() should create gate with test_mode = false
        let server = Server::bind(&config, Policy::milestone_five(true, true))
            .expect("bind production server");

        // The confirmation gate should have test_mode = false
        // We verify this by checking that confirmation is required for sensitive ops
        let session_id = server
            .session_manager()
            .create_session(
                CapabilitySet::from_iter(vec!["process_control".to_string()]),
                std::process::id() as u64,
            )
            .unwrap()
            .id
            .to_string();

        let request = Request {
            version: 1,
            id: "test-req".to_string(),
            op: "proc.signal".to_string(),
            params: serde_json::json!({"pid": std::process::id() as u64, "signal": 15, "confirm": true}),
            session_id: Some(session_id),
            confirmation_token: None,
        };

        let response = send_request(server.socket_path(), request);
        assert!(!response.ok);
        assert_eq!(
            response.error.as_ref().unwrap().code,
            error_code::CONFIRMATION_REQUIRED
        );

        drop(server);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    #[ignore = "requires provider binaries in PATH (bind_test spawns providers)"]
    fn prod_bind_test_configures_confirmation_gate_test_mode_true() {
        let root = std::env::temp_dir().join(format!("igris-test-test-{}", std::process::id()));
        let socket_path = root.join("igrisd.sock");
        let audit_path = root.join("audit.log");
        let fs_root = root.join("root");
        let writable = fs_root.join("writable");

        std::fs::create_dir_all(&fs_root).expect("create fs root");
        std::fs::create_dir_all(&writable).expect("create writable");

        let config = Config::with_writable_paths(
            socket_path.clone(),
            audit_path.clone(),
            &fs_root,
            [&writable],
        );

        // Test bind_test() should create gate with test_mode = true
        let server = Server::bind_test(&config, Policy::milestone_five(true, true))
            .expect("bind test server");

        // In test mode, confirmation is auto-approved
        let session_id = server
            .session_manager()
            .create_session(
                CapabilitySet::from_iter(vec!["process_control".to_string()]),
                std::process::id() as u64,
            )
            .unwrap()
            .id
            .to_string();

        let request = Request {
            version: 1,
            id: "test-req".to_string(),
            op: "proc.signal".to_string(),
            params: serde_json::json!({"pid": std::process::id() as u64, "signal": 15, "confirm": true}),
            session_id: Some(session_id),
            confirmation_token: None,
        };

        let response = send_request(server.socket_path(), request);
        // In test mode, auto-approval happens so it should succeed
        assert!(response.ok, "test mode should auto-approve");

        drop(server);
        let _ = std::fs::remove_dir_all(&root);
    }
}
