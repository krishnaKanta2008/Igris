//! Filesystem provider binary.
//!
//! Handles fs.list, fs.stat, fs.read, fs.write, fs.delete operations
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

pub mod fs_ops {
    use std::fs;
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};

    use serde::Serialize;
    use serde_json::Value;

    use igris_proto::{
        error_code, FS_DEFAULT_MAX_BYTES, FS_DEFAULT_MAX_ENTRIES, FS_MAX_BYTES, FS_MAX_ENTRIES,
        FS_WRITE_DEFAULT_MAX_BYTES, FS_WRITE_MAX_BYTES, MAX_RESPONSE_SIZE,
    };

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct ListEntry {
        pub name: String,
        pub kind: String,
        pub size_bytes: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct ListResult {
        pub path: String,
        pub entries: Vec<ListEntry>,
        pub truncated: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct StatResult {
        pub path: String,
        pub kind: String,
        pub size_bytes: u64,
        pub mode: u32,
        pub uid: u32,
        pub gid: u32,
        pub modified_unix: Option<u64>,
        pub accessed_unix: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct WriteResult {
        pub path: String,
        pub size_bytes: u64,
        pub overwritten: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct DeleteResult {
        pub path: String,
        pub deleted: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct ReadResult {
        pub path: String,
        pub size_bytes: u64,
        pub encoding: &'static str,
        pub data: String,
        pub truncated: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FsFailure {
        pub code: &'static str,
        pub message: &'static str,
        pub denied: bool,
    }

    impl FsFailure {
        fn not_found() -> Self {
            Self {
                code: error_code::NOT_FOUND,
                message: "path not found",
                denied: false,
            }
        }
        fn permission_denied() -> Self {
            Self {
                code: error_code::FS_ERROR,
                message: "permission denied",
                denied: false,
            }
        }
        fn not_a_directory() -> Self {
            Self {
                code: error_code::FS_ERROR,
                message: "not a directory",
                denied: false,
            }
        }
        fn invalid_path() -> Self {
            Self {
                code: error_code::BAD_REQUEST,
                message: "invalid path",
                denied: true,
            }
        }
        fn invalid_base64() -> Self {
            Self {
                code: error_code::BAD_REQUEST,
                message: "invalid base64 data",
                denied: true,
            }
        }
        fn write_exceeds_max() -> Self {
            Self {
                code: error_code::BAD_REQUEST,
                message: "content exceeds max_bytes",
                denied: true,
            }
        }
        fn out_of_boundary() -> Self {
            Self {
                code: error_code::BAD_REQUEST,
                message: "path escapes filesystem boundary",
                denied: true,
            }
        }
        fn generic() -> Self {
            Self {
                code: error_code::FS_ERROR,
                message: "filesystem error",
                denied: false,
            }
        }
    }

    impl From<io::Error> for FsFailure {
        fn from(e: io::Error) -> Self {
            match e.kind() {
                io::ErrorKind::NotFound => FsFailure::not_found(),
                io::ErrorKind::PermissionDenied => FsFailure::permission_denied(),
                io::ErrorKind::NotADirectory => FsFailure::not_a_directory(),
                io::ErrorKind::IsADirectory => FsFailure {
                    code: error_code::FS_ERROR,
                    message: "not a file",
                    denied: false,
                },
                _ => FsFailure::generic(),
            }
        }
    }

    pub fn resolve_within(fs_root: &Path, requested: &str) -> Result<PathBuf, FsFailure> {
        if requested.contains('\0') {
            return Err(FsFailure::invalid_path());
        }
        let candidate = Path::new(requested);
        if !candidate.is_absolute() {
            return Err(FsFailure::invalid_path());
        }
        let resolved = candidate.canonicalize().map_err(FsFailure::from)?;
        let root = fs_root.canonicalize().map_err(FsFailure::from)?;
        if resolved.starts_with(&root) {
            Ok(resolved)
        } else {
            Err(FsFailure::out_of_boundary())
        }
    }

    fn resolve_parent_within(
        fs_root: &Path,
        requested: &str,
    ) -> Result<(PathBuf, PathBuf), FsFailure> {
        if requested.contains('\0') {
            return Err(FsFailure::invalid_path());
        }
        let candidate = Path::new(requested);
        if !candidate.is_absolute() {
            return Err(FsFailure::invalid_path());
        }
        let file_name = candidate.file_name().ok_or_else(FsFailure::invalid_path)?;
        let parent = candidate.parent().ok_or_else(FsFailure::invalid_path)?;
        let resolved_parent = parent.canonicalize().map_err(FsFailure::from)?;
        let root = fs_root.canonicalize().map_err(FsFailure::from)?;
        if !resolved_parent.starts_with(&root) {
            return Err(FsFailure::out_of_boundary());
        }
        Ok((resolved_parent, PathBuf::from(file_name)))
    }

    fn is_writable_path(path: &Path, writable_paths: &[PathBuf]) -> bool {
        writable_paths
            .iter()
            .any(|allowed| path.starts_with(allowed))
    }

    fn base64_decode(input: &str) -> Result<Vec<u8>, FsFailure> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let bytes = input.as_bytes();
        if !bytes.len().is_multiple_of(4) {
            return Err(FsFailure::invalid_base64());
        }
        fn value(byte: u8) -> Option<u8> {
            match byte {
                b'A'..=b'Z' => Some(byte - b'A'),
                b'a'..=b'z' => Some(byte - b'a' + 26),
                b'0'..=b'9' => Some(byte - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }
        let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
        for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
            let last = index == bytes.len() / 4 - 1;
            let a = value(chunk[0]).ok_or_else(FsFailure::invalid_base64)?;
            let b = value(chunk[1]).ok_or_else(FsFailure::invalid_base64)?;
            let c = if chunk[2] == b'=' {
                if !last || chunk[3] != b'=' {
                    return Err(FsFailure::invalid_base64());
                }
                0
            } else {
                value(chunk[2]).ok_or_else(FsFailure::invalid_base64)?
            };
            let d = if chunk[3] == b'=' {
                if !last {
                    return Err(FsFailure::invalid_base64());
                }
                0
            } else {
                value(chunk[3]).ok_or_else(FsFailure::invalid_base64)?
            };
            if chunk[2] == b'=' && chunk[3] != b'=' {
                return Err(FsFailure::invalid_base64());
            }
            if chunk[2] == b'=' && (b & 0x0f) != 0 {
                return Err(FsFailure::invalid_base64());
            }
            if chunk[3] == b'=' && chunk[2] != b'=' && (c & 0x03) != 0 {
                return Err(FsFailure::invalid_base64());
            }
            let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | d as u32;
            out.push((n >> 16) as u8);
            if chunk[2] != b'=' {
                out.push((n >> 8) as u8);
            }
            if chunk[3] != b'=' {
                out.push(n as u8);
            }
        }
        Ok(out)
    }

    fn base64_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
            out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[n as usize & 0x3f] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    fn entry_kind(kind: impl FnOnce() -> io::Result<fs::FileType>) -> &'static str {
        match kind() {
            Ok(t) if t.is_dir() => "directory",
            Ok(t) if t.is_file() => "file",
            Ok(t) if t.is_symlink() => "symlink",
            _ => "other",
        }
    }
    fn metadata_kind(md: &fs::Metadata) -> &'static str {
        let t = md.file_type();
        if t.is_dir() {
            "directory"
        } else if t.is_file() {
            "file"
        } else if t.is_symlink() {
            "symlink"
        } else {
            "other"
        }
    }
    fn params_path(params: &Value) -> Result<&str, FsFailure> {
        params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(FsFailure::invalid_path)
    }
    fn params_limit(params: &Value, key: &str, default: usize, hard: usize) -> usize {
        params
            .get(key)
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(default)
            .clamp(1, hard)
    }

    pub fn list(
        fs_root: &Path,
        _writable_paths: &[PathBuf],
        params: &Value,
    ) -> Result<ListResult, FsFailure> {
        let requested = params_path(params)?.to_string();
        let max = params_limit(
            params,
            "max_entries",
            FS_DEFAULT_MAX_ENTRIES,
            FS_MAX_ENTRIES,
        );
        let resolved = resolve_within(fs_root, &requested)?;
        let mut entries = Vec::new();
        let mut overflow = false;
        for entry in fs::read_dir(&resolved).map_err(FsFailure::from)? {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => return Err(FsFailure::from(e)),
            };
            if entries.len() >= max {
                overflow = true;
                break;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let kind = entry_kind(|| entry.file_type());
            let size_bytes = entry.metadata().ok().map(|m| m.len());
            entries.push(ListEntry {
                name,
                kind: kind.to_string(),
                size_bytes,
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(ListResult {
            path: requested,
            entries,
            truncated: overflow,
        })
    }

    pub fn stat(
        fs_root: &Path,
        _writable_paths: &[PathBuf],
        params: &Value,
    ) -> Result<StatResult, FsFailure> {
        let requested = params_path(params)?.to_string();
        let resolved = resolve_within(fs_root, &requested)?;
        let md = fs::metadata(&resolved).map_err(FsFailure::from)?;
        use std::os::unix::fs::MetadataExt;
        fn system_time_unix(t: std::time::SystemTime) -> Option<u64> {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        }
        Ok(StatResult {
            path: requested,
            kind: metadata_kind(&md).to_string(),
            size_bytes: md.len(),
            mode: md.mode() & 0o7777,
            uid: md.uid(),
            gid: md.gid(),
            modified_unix: md.modified().ok().and_then(system_time_unix),
            accessed_unix: md.accessed().ok().and_then(system_time_unix),
        })
    }

    pub fn read(
        fs_root: &Path,
        _writable_paths: &[PathBuf],
        params: &Value,
    ) -> Result<ReadResult, FsFailure> {
        let requested = params_path(params)?.to_string();
        let max = params_limit(params, "max_bytes", FS_DEFAULT_MAX_BYTES, FS_MAX_BYTES);
        let frame_fit = (MAX_RESPONSE_SIZE - 1024) * 3 / 4;
        let effective = max.min(frame_fit);
        let resolved = resolve_within(fs_root, &requested)?;
        let file = fs::File::open(&resolved).map_err(FsFailure::from)?;
        let mut buf = Vec::new();
        file.take(effective as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(FsFailure::from)?;
        let truncated = buf.len() > effective;
        if truncated {
            buf.truncate(effective);
        }
        Ok(ReadResult {
            path: requested,
            size_bytes: buf.len() as u64,
            encoding: "base64",
            data: base64_encode(&buf),
            truncated,
        })
    }

    pub fn write(
        fs_root: &Path,
        writable_paths: &[PathBuf],
        params: &Value,
    ) -> Result<WriteResult, FsFailure> {
        let requested = params_path(params)?.to_string();
        let encoded = params
            .get("content_base64")
            .and_then(|v| v.as_str())
            .ok_or(FsFailure {
                code: error_code::BAD_REQUEST,
                message: "missing or invalid content_base64",
                denied: true,
            })?;
        let max = params_limit(
            params,
            "max_bytes",
            FS_WRITE_DEFAULT_MAX_BYTES,
            FS_WRITE_MAX_BYTES,
        );
        let data = base64_decode(encoded)?;
        if data.len() > max {
            return Err(FsFailure::write_exceeds_max());
        }
        let (parent, file_name) = resolve_parent_within(fs_root, &requested)?;
        if !is_writable_path(&parent, writable_paths) {
            return Err(FsFailure::out_of_boundary());
        }
        let target = parent.join(&file_name);
        let overwritten = match fs::symlink_metadata(&target) {
            Ok(metadata) => {
                let file_type = metadata.file_type();
                if file_type.is_dir() {
                    return Err(FsFailure {
                        code: error_code::FS_ERROR,
                        message: "not a file",
                        denied: false,
                    });
                }
                if file_type.is_symlink() {
                    match target.canonicalize() {
                        Ok(resolved) => {
                            let root = fs_root.canonicalize().map_err(FsFailure::from)?;
                            if !resolved.starts_with(&root)
                                || !is_writable_path(&resolved, writable_paths)
                            {
                                return Err(FsFailure::out_of_boundary());
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => return Err(FsFailure::from(e)),
                    }
                } else if !file_type.is_file() {
                    return Err(FsFailure {
                        code: error_code::FS_ERROR,
                        message: "not a file",
                        denied: false,
                    });
                }
                true
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(FsFailure::from(e)),
        };
        let temp_name = format!(
            ".igris-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let temp_path = parent.join(temp_name);
        let result: Result<(), FsFailure> = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(FsFailure::from)?;
            file.write_all(&data).map_err(FsFailure::from)?;
            file.sync_all().map_err(FsFailure::from)?;
            drop(file);
            fs::rename(&temp_path, &target).map_err(FsFailure::from)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result?;
        Ok(WriteResult {
            path: requested,
            size_bytes: data.len() as u64,
            overwritten,
        })
    }

    pub fn delete(
        fs_root: &Path,
        writable_paths: &[PathBuf],
        params: &Value,
    ) -> Result<DeleteResult, FsFailure> {
        let requested = params_path(params)?.to_string();
        let (parent, file_name) = resolve_parent_within(fs_root, &requested)?;
        if !is_writable_path(&parent, writable_paths) {
            return Err(FsFailure::out_of_boundary());
        }
        let target = parent.join(&file_name);
        let metadata = fs::symlink_metadata(&target).map_err(FsFailure::from)?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            return Err(FsFailure {
                code: error_code::FS_ERROR,
                message: "directory deletion is not permitted",
                denied: false,
            });
        }
        if file_type.is_symlink() {
            match target.canonicalize() {
                Ok(resolved) => {
                    let root = fs_root.canonicalize().map_err(FsFailure::from)?;
                    if !resolved.starts_with(&root) || !is_writable_path(&resolved, writable_paths)
                    {
                        return Err(FsFailure::out_of_boundary());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(FsFailure::from(e)),
            }
        } else if !file_type.is_file() {
            return Err(FsFailure {
                code: error_code::FS_ERROR,
                message: "not a file",
                denied: false,
            });
        }
        fs::remove_file(&target).map_err(FsFailure::from)?;
        Ok(DeleteResult {
            path: requested,
            deleted: true,
        })
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: igris-fs-provider <socket_path> <fs_root> <writable_paths...>");
        std::process::exit(1);
    }
    let socket_path = PathBuf::from(&args[1]);
    let fs_root = PathBuf::from(&args[2]);
    let writable_paths: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();

    // Clone for the closure which needs 'static lifetime
    let fs_root_clone = fs_root.clone();
    let writable_paths_clone = writable_paths.clone();

    run_provider_server(
        &socket_path,
        &fs_root,
        &writable_paths,
        move |req| match req.op.as_str() {
            igris_proto::OP_FS_LIST => {
                let result = fs_ops::list(&fs_root_clone, &writable_paths_clone, &req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_FS_STAT => {
                let result = fs_ops::stat(&fs_root_clone, &writable_paths_clone, &req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_FS_READ => {
                let result = fs_ops::read(&fs_root_clone, &writable_paths_clone, &req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_FS_WRITE => {
                let result = fs_ops::write(&fs_root_clone, &writable_paths_clone, &req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_FS_DELETE => {
                let result = fs_ops::delete(&fs_root_clone, &writable_paths_clone, &req.params)
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
