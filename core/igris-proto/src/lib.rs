//! Igris IPC protocol: versioned wire types, framing, and shared endpoint paths.
//!
//! Wire format: each message is a 4-byte big-endian `u32` length prefix followed
//! by exactly that many bytes of UTF-8 JSON. The length prefix lets both sides
//! reject oversized messages deterministically *before* reading the body.
//!
//! See `docs/architecture/ipc-protocol.md` for the full specification.

use std::env;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Protocol version implemented by this build.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum accepted request payload size, in bytes (64 KiB).
pub const MAX_REQUEST_SIZE: usize = 64 * 1024;

/// Maximum accepted response payload size, in bytes (1 MiB).
pub const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Maximum request identifier length, in bytes.
pub const MAX_REQUEST_ID_LEN: usize = 128;

/// Number of bytes in the big-endian length prefix.
pub const LENGTH_PREFIX_SIZE: usize = 4;

/// Operation name for system information.
pub const OP_SYSTEM_INFO: &str = "system.info";

/// Operation name for listing a directory.
pub const OP_FS_LIST: &str = "fs.list";

/// Operation name for reading file metadata.
pub const OP_FS_STAT: &str = "fs.stat";

/// Operation name for reading file contents.
pub const OP_FS_READ: &str = "fs.read";

/// Operations supported by this protocol version.
pub const SUPPORTED_OPERATIONS: &[&str] = &[OP_SYSTEM_INFO, OP_FS_LIST, OP_FS_STAT, OP_FS_READ];

/// Default maximum entries returned by `fs.list`.
pub const FS_DEFAULT_MAX_ENTRIES: usize = 256;

/// Hard maximum entries accepted for `fs.list`.
pub const FS_MAX_ENTRIES: usize = 1024;

/// Default maximum bytes returned by `fs.read` (64 KiB).
pub const FS_DEFAULT_MAX_BYTES: usize = 64 * 1024;

/// Hard maximum bytes accepted for `fs.read` (1 MiB).
pub const FS_MAX_BYTES: usize = 1024 * 1024;

/// Well-known error codes returned in error responses.
pub mod error_code {
    /// The request could not be parsed or violates the schema.
    pub const BAD_REQUEST: &str = "BAD_REQUEST";
    /// The request declared an unsupported protocol version.
    pub const UNSUPPORTED_VERSION: &str = "UNSUPPORTED_VERSION";
    /// The requested operation is not recognised.
    pub const UNKNOWN_OPERATION: &str = "UNKNOWN_OPERATION";
    /// The operation was rejected by the permission policy.
    pub const DENIED: &str = "DENIED";
    /// The framed message exceeded the configured size limit.
    pub const TOO_LARGE: &str = "TOO_LARGE";
    /// The requested filesystem path does not exist.
    pub const NOT_FOUND: &str = "NOT_FOUND";
    /// The filesystem operation failed; the message is sanitized.
    pub const FS_ERROR: &str = "FS_ERROR";
    /// An internal server error occurred.
    pub const INTERNAL: &str = "INTERNAL";
}

/// A parsed request. Input is untrusted; use [`validate_request`] before acting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub version: u16,
    pub id: String,
    pub op: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A protocol-level validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: &'static str,
    pub message: String,
}

impl ProtocolError {
    /// Construct a new protocol error.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Validate a parsed request against the protocol contract.
///
/// Checked in order: protocol version, request id, `params` shape, and finally
/// whether the operation is supported.
pub fn validate_request(req: &Request) -> Result<(), ProtocolError> {
    if req.version != PROTOCOL_VERSION {
        return Err(ProtocolError::new(
            error_code::UNSUPPORTED_VERSION,
            format!(
                "unsupported protocol version {} (expected {})",
                req.version, PROTOCOL_VERSION
            ),
        ));
    }
    validate_request_id(&req.id)?;
    if !req.params.is_object() {
        return Err(ProtocolError::new(
            error_code::BAD_REQUEST,
            "`params` must be a JSON object",
        ));
    }
    if !SUPPORTED_OPERATIONS.contains(&req.op.as_str()) {
        return Err(ProtocolError::new(
            error_code::UNKNOWN_OPERATION,
            format!("unknown operation {:?}", req.op),
        ));
    }
    Ok(())
}

/// Validate the `params` object for one specific operation.
///
/// [`validate_request`] proves the request is structurally sound; this proves
/// the operation's own arguments are well-formed. Filesystem path safety
/// (canonicalization and boundary containment) is enforced by the provider,
/// not here.
pub fn validate_operation_params(
    op: &str,
    params: &serde_json::Value,
) -> Result<(), ProtocolError> {
    match op {
        OP_SYSTEM_INFO => Ok(()),
        OP_FS_LIST => {
            validate_path_param(params)?;
            validate_limit_param(params, "max_entries", FS_MAX_ENTRIES)
        }
        OP_FS_STAT => validate_path_param(params),
        OP_FS_READ => {
            validate_path_param(params)?;
            validate_limit_param(params, "max_bytes", FS_MAX_BYTES)
        }
        other => Err(ProtocolError::new(
            error_code::UNKNOWN_OPERATION,
            format!("unknown operation {other:?}"),
        )),
    }
}

/// Require a `path` string that is absolute and contains no NUL bytes.
fn validate_path_param(params: &serde_json::Value) -> Result<(), ProtocolError> {
    let path = params
        .get("path")
        .ok_or_else(|| ProtocolError::new(error_code::BAD_REQUEST, "missing required `path`"))?;
    let path = path
        .as_str()
        .ok_or_else(|| ProtocolError::new(error_code::BAD_REQUEST, "`path` must be a string"))?;
    if path.is_empty() {
        return Err(ProtocolError::new(
            error_code::BAD_REQUEST,
            "`path` must not be empty",
        ));
    }
    if path.contains('\0') {
        return Err(ProtocolError::new(
            error_code::BAD_REQUEST,
            "`path` must not contain NUL bytes",
        ));
    }
    if !path.starts_with('/') {
        return Err(ProtocolError::new(
            error_code::BAD_REQUEST,
            "`path` must be absolute",
        ));
    }
    Ok(())
}

/// Require an optional positive integer limit within `max`.
fn validate_limit_param(
    params: &serde_json::Value,
    key: &str,
    max: usize,
) -> Result<(), ProtocolError> {
    let Some(value) = params.get(key) else {
        return Ok(());
    };
    let limit = value.as_u64().ok_or_else(|| {
        ProtocolError::new(
            error_code::BAD_REQUEST,
            format!("`{key}` must be a positive integer"),
        )
    })?;
    if limit == 0 || limit as usize > max {
        return Err(ProtocolError::new(
            error_code::BAD_REQUEST,
            format!("`{key}` must be between 1 and {max}"),
        ));
    }
    Ok(())
}

/// Validate a request identifier: non-empty, bounded length, no control chars.
pub fn validate_request_id(id: &str) -> Result<(), ProtocolError> {
    if id.is_empty() {
        return Err(ProtocolError::new(
            error_code::BAD_REQUEST,
            "`id` must not be empty",
        ));
    }
    if id.len() > MAX_REQUEST_ID_LEN {
        return Err(ProtocolError::new(
            error_code::BAD_REQUEST,
            "`id` exceeds the maximum length",
        ));
    }
    if id.chars().any(char::is_control) {
        return Err(ProtocolError::new(
            error_code::BAD_REQUEST,
            "`id` contains control characters",
        ));
    }
    Ok(())
}

/// A response sent back to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub version: u16,
    pub id: Option<String>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

/// Structured error payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl Response {
    /// Build a successful response.
    pub fn success(id: String, result: serde_json::Value) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            id: Some(id),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response. `id` is `None` when the request id was unusable.
    pub fn error(id: Option<String>, code: &str, message: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            id,
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code: code.to_string(),
                message: message.into(),
            }),
        }
    }
}

/// Outcome of reading one framed message.
#[derive(Debug)]
pub enum ReadFrame {
    /// A complete payload of the declared length (may be empty).
    Received(Vec<u8>),
    /// The declared length exceeds the limit; the body was not read.
    TooLarge {
        /// The length the peer declared.
        declared: u32,
    },
    /// The peer closed the connection before sending any bytes.
    Closed,
}

/// Read one length-prefixed frame. Returns [`ReadFrame::TooLarge`] without
/// reading the body when the declared length exceeds `max_size`.
pub fn read_frame<R: Read>(reader: &mut R, max_size: usize) -> io::Result<ReadFrame> {
    let mut first = [0u8; 1];
    loop {
        match reader.read(&mut first) {
            Ok(0) => return Ok(ReadFrame::Closed),
            Ok(_) => break,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    let mut rest = [0u8; LENGTH_PREFIX_SIZE - 1];
    reader.read_exact(&mut rest)?;
    let mut header = [0u8; LENGTH_PREFIX_SIZE];
    header[0] = first[0];
    header[1..].copy_from_slice(&rest);

    let declared = u32::from_be_bytes(header);
    if declared as usize > max_size {
        return Ok(ReadFrame::TooLarge { declared });
    }

    let mut buf = vec![0u8; declared as usize];
    reader.read_exact(&mut buf)?;
    Ok(ReadFrame::Received(buf))
}

/// Write one length-prefixed frame.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len =
        u32::try_from(payload.len()).map_err(|_| io::Error::other("payload too large to frame"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

/// Serialize and frame a response, enforcing a maximum response size.
pub fn write_response<W: Write>(
    writer: &mut W,
    response: &Response,
    max_size: usize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    if bytes.len() > max_size {
        return Err(io::Error::other("response exceeds maximum size"));
    }
    write_frame(writer, &bytes)
}

/// Return the process user's home directory, if `HOME` is set.
pub fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

/// Default filesystem root for the read-only tools.
///
/// `~/.igris/share` for the daemon's current user, falling back to the system
/// temporary directory when no home directory is known.
pub fn default_fs_root() -> PathBuf {
    home_dir()
        .unwrap_or_else(env::temp_dir)
        .join(".igris")
        .join("share")
}

/// Default daemon socket path.
///
/// Uses `$XDG_RUNTIME_DIR/igris/igrisd.sock` when available, otherwise
/// `~/.igris/igrisd.sock`. Shared by the daemon and the client so they agree.
pub fn default_socket_path() -> PathBuf {
    if let Some(dir) = env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("igris").join("igrisd.sock");
    }
    home_dir()
        .unwrap_or_else(env::temp_dir)
        .join(".igris")
        .join("igrisd.sock")
}

/// Default audit-log path.
///
/// Uses `$XDG_STATE_HOME/igris/audit.log` when available, otherwise
/// `~/.local/state/igris/audit.log`.
pub fn default_audit_log_path() -> PathBuf {
    if let Some(dir) = env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(dir).join("igris").join("audit.log");
    }
    home_dir()
        .unwrap_or_else(env::temp_dir)
        .join(".local")
        .join("state")
        .join("igris")
        .join("audit.log")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample() -> Request {
        Request {
            version: PROTOCOL_VERSION,
            id: "req-1".to_string(),
            op: OP_SYSTEM_INFO.to_string(),
            params: serde_json::json!({}),
        }
    }

    #[test]
    fn parses_valid_request() {
        let raw = br#"{"version":1,"id":"req-1","op":"system.info","params":{}}"#;
        let req: Request = serde_json::from_slice(raw).expect("valid request parses");
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn rejects_malformed_json() {
        let raw = b"{ this is not json";
        assert!(serde_json::from_slice::<Request>(raw).is_err());
    }

    #[test]
    fn rejects_missing_fields() {
        let raw = br#"{"version":1,"op":"system.info","params":{}}"#;
        assert!(serde_json::from_slice::<Request>(raw).is_err());
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut req = sample();
        req.version = 999;
        let err = validate_request(&req).expect_err("version rejected");
        assert_eq!(err.code, error_code::UNSUPPORTED_VERSION);
    }

    #[test]
    fn rejects_empty_and_long_ids() {
        let mut req = sample();
        req.id = String::new();
        assert_eq!(
            validate_request(&req).expect_err("empty id").code,
            error_code::BAD_REQUEST
        );

        req.id = "x".repeat(MAX_REQUEST_ID_LEN + 1);
        assert_eq!(
            validate_request(&req).expect_err("long id").code,
            error_code::BAD_REQUEST
        );
    }

    #[test]
    fn rejects_non_object_params() {
        let mut req = sample();
        req.params = serde_json::json!("nope");
        assert_eq!(
            validate_request(&req).expect_err("bad params").code,
            error_code::BAD_REQUEST
        );
    }

    #[test]
    fn rejects_unknown_operation() {
        let mut req = sample();
        req.op = "system.exec".to_string();
        assert_eq!(
            validate_request(&req).expect_err("unknown op").code,
            error_code::UNKNOWN_OPERATION
        );
    }

    #[test]
    fn operation_params_accept_valid_fs_requests() {
        assert!(validate_operation_params(
            OP_FS_LIST,
            &serde_json::json!({"path": "/tmp", "max_entries": 10})
        )
        .is_ok());
        assert!(
            validate_operation_params(OP_FS_STAT, &serde_json::json!({"path": "/tmp"})).is_ok()
        );
        assert!(validate_operation_params(
            OP_FS_READ,
            &serde_json::json!({"path": "/tmp", "max_bytes": 1024})
        )
        .is_ok());
        assert!(validate_operation_params(OP_SYSTEM_INFO, &serde_json::json!({})).is_ok());
    }

    #[test]
    fn operation_params_membership_includes_fs_ops() {
        assert!(SUPPORTED_OPERATIONS.contains(&OP_FS_LIST));
        assert!(SUPPORTED_OPERATIONS.contains(&OP_FS_STAT));
        assert!(SUPPORTED_OPERATIONS.contains(&OP_FS_READ));
        assert!(!SUPPORTED_OPERATIONS.contains(&"fs.write"));
    }

    #[test]
    fn operation_params_reject_missing_and_wrong_path() {
        assert_eq!(
            validate_operation_params(OP_FS_LIST, &serde_json::json!({}))
                .expect_err("missing path")
                .code,
            error_code::BAD_REQUEST
        );
        assert_eq!(
            validate_operation_params(OP_FS_STAT, &serde_json::json!({"path": 42}))
                .expect_err("wrong path type")
                .code,
            error_code::BAD_REQUEST
        );
        assert_eq!(
            validate_operation_params(OP_FS_READ, &serde_json::json!({"path": "relative/path"}))
                .expect_err("relative path")
                .code,
            error_code::BAD_REQUEST
        );
        assert_eq!(
            validate_operation_params(OP_FS_READ, &serde_json::json!({"path": "/tmp/a\0b"}))
                .expect_err("NUL path")
                .code,
            error_code::BAD_REQUEST
        );
    }

    #[test]
    fn operation_params_reject_invalid_limits() {
        assert_eq!(
            validate_operation_params(
                OP_FS_LIST,
                &serde_json::json!({"path": "/x", "max_entries": 0})
            )
            .expect_err("zero entries")
            .code,
            error_code::BAD_REQUEST
        );
        assert_eq!(
            validate_operation_params(
                OP_FS_LIST,
                &serde_json::json!({"path": "/x", "max_entries": FS_MAX_ENTRIES + 1})
            )
            .expect_err("too many entries")
            .code,
            error_code::BAD_REQUEST
        );
        assert_eq!(
            validate_operation_params(
                OP_FS_READ,
                &serde_json::json!({"path": "/x", "max_bytes": "lots"})
            )
            .expect_err("string limit")
            .code,
            error_code::BAD_REQUEST
        );
        assert_eq!(
            validate_operation_params(
                OP_FS_READ,
                &serde_json::json!({"path": "/x", "max_bytes": FS_MAX_BYTES + 1})
            )
            .expect_err("too many bytes")
            .code,
            error_code::BAD_REQUEST
        );
    }

    #[test]
    fn framing_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").expect("write frame");
        let mut cursor = Cursor::new(buf);
        match read_frame(&mut cursor, MAX_REQUEST_SIZE).expect("read frame") {
            ReadFrame::Received(payload) => assert_eq!(payload, b"hello"),
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[test]
    fn oversized_declared_length_is_rejected_without_body() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_REQUEST_SIZE as u32 + 1).to_be_bytes());
        let mut cursor = Cursor::new(buf);
        match read_frame(&mut cursor, MAX_REQUEST_SIZE).expect("read frame") {
            ReadFrame::TooLarge { declared } => {
                assert_eq!(declared as usize, MAX_REQUEST_SIZE + 1)
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[test]
    fn clean_close_is_reported() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        match read_frame(&mut cursor, MAX_REQUEST_SIZE).expect("read frame") {
            ReadFrame::Closed => {}
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[test]
    fn response_constructors_set_version_and_shape() {
        let ok = Response::success("id-1".into(), serde_json::json!({"a": 1}));
        assert!(ok.ok && ok.error.is_none());
        assert_eq!(ok.version, PROTOCOL_VERSION);

        let err = Response::error(None, error_code::DENIED, "nope");
        assert!(!err.ok && err.result.is_none());
        assert_eq!(err.error.expect("error body").code, error_code::DENIED);
    }
}
