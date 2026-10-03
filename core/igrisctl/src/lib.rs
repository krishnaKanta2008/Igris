//! `igrisctl` client library.
//!
//! Builds structured requests, sends them over the daemon's Unix socket using
//! the shared framing, and returns the structured response. It never sends a
//! shell command and has no capability beyond the protocol.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use igris_proto::{
    read_frame, write_frame, ReadFrame, Request, Response, MAX_REQUEST_SIZE, MAX_RESPONSE_SIZE,
    PROTOCOL_VERSION,
};

/// Error type for client operations.
#[derive(Debug)]
pub enum ClientError {
    /// The daemon socket could not be reached.
    Io(io::Error),
    /// The response could not be parsed.
    Protocol(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "{e}"),
            ClientError::Protocol(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// Resolve the socket path from `IGRIS_SOCKET_PATH` or the shared default.
pub fn resolve_socket_path() -> PathBuf {
    std::env::var_os("IGRIS_SOCKET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(igris_proto::default_socket_path)
}

/// Build a request with a locally unique, human-readable id.
pub fn build_request(op: &str, params: serde_json::Value) -> Request {
    Request {
        version: PROTOCOL_VERSION,
        id: new_request_id(),
        op: op.to_string(),
        params,
    }
}

/// Generate a request id from the process id and a monotonic-ish timestamp.
pub fn new_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", std::process::id(), nanos)
}

/// Send a request to the daemon at `socket_path` and read one response.
pub fn send(socket_path: &Path, request: &Request) -> Result<Response, ClientError> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    let payload = serde_json::to_vec(request)
        .map_err(|e| ClientError::Protocol(format!("failed to encode request: {e}")))?;
    if payload.len() > MAX_REQUEST_SIZE {
        return Err(ClientError::Protocol(
            "request exceeds maximum size".to_string(),
        ));
    }
    write_frame(&mut stream, &payload)?;

    match read_frame(&mut stream, MAX_RESPONSE_SIZE)? {
        ReadFrame::Received(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| ClientError::Protocol(format!("malformed response: {e}"))),
        ReadFrame::TooLarge { declared } => Err(ClientError::Protocol(format!(
            "response declared {declared} bytes, exceeding the maximum"
        ))),
        ReadFrame::Closed => Err(ClientError::Protocol(
            "daemon closed the connection without responding".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_versioned_request() {
        let req = build_request("system.info", serde_json::json!({}));
        assert_eq!(req.version, PROTOCOL_VERSION);
        assert_eq!(req.op, "system.info");
        assert!(!req.id.is_empty());
        assert!(req.params.is_object());
    }

    #[test]
    fn request_ids_are_nonempty_and_unique_enough() {
        let a = new_request_id();
        let b = new_request_id();
        assert!(!a.is_empty());
        assert_ne!(a, b);
    }
}
