//! Filesystem provider (`fs.list`, `fs.stat`, `fs.read`, `fs.write`, `fs.delete`).
//!
//! Every request is confined to the configured canonical filesystem root
//! (`Config::fs_root`). Paths are canonicalized before use, symlinks are
//! followed, and the *resolved* target must remain inside the root. Requested
//! paths are absolute, NUL-free, and operation limits are enforced here.
//!
//! Results report the client-requested path; the resolved host path is never
//! exposed in payloads. Error messages are sanitized and never carry raw
//! `std::io::Error` text.
//!
//! Known limitation: canonicalization is not atomic with the subsequent open,
//! so a symlink swapped between the two calls is a residual TOCTOU race
//! (accepted for an unprivileged local daemon; see ADR 0007).

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use igris_proto::{
    error_code, FS_DEFAULT_MAX_BYTES, FS_DEFAULT_MAX_ENTRIES, FS_MAX_BYTES, FS_MAX_ENTRIES,
    FS_WRITE_DEFAULT_MAX_BYTES, FS_WRITE_MAX_BYTES, MAX_RESPONSE_SIZE,
};

/// Outcome of a filesystem operation that must become a protocol error.
///
/// `denied` marks failures where the *request itself* is at fault (path
/// escapes the boundary, invalid path); the audit pipeline records these with
/// decision `deny`. Runtime failures (`not found`, `permission denied`, ...)
/// are recorded as `allow` + error, because policy permitted the operation.
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

/// One directory entry in an `fs.list` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListEntry {
    pub name: String,
    /// `"directory"`, `"file"`, `"symlink"`, or `"other"`.
    pub kind: String,
    /// Size in bytes when safely available.
    pub size_bytes: Option<u64>,
}

/// `fs.list` result payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListResult {
    pub path: String,
    pub entries: Vec<ListEntry>,
    pub truncated: bool,
}

/// `fs.stat` result payload.
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

/// `fs.write` result payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteResult {
    pub path: String,
    pub size_bytes: u64,
    pub overwritten: bool,
}

/// `fs.delete` result payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteResult {
    pub path: String,
    pub deleted: bool,
}

/// `fs.read` result payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadResult {
    pub path: String,
    pub size_bytes: u64,
    pub encoding: &'static str,
    pub data: String,
    pub truncated: bool,
}

/// Canonicalize `requested` and verify it stays inside the canonical root.
///
/// Symlinks are followed by canonicalization; the resolved target must remain
/// under `fs_root`. Returns the resolved path on success.
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

/// Resolve the parent directory of a target that may not exist yet.
///
/// The parent must exist and its canonical target must remain inside the
/// configured filesystem root.
fn resolve_parent_within(fs_root: &Path, requested: &str) -> Result<(PathBuf, PathBuf), FsFailure> {
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

/// Verify that a canonical path is inside at least one configured writable
/// path. The writable paths are canonical directory/path roots.
fn is_writable_path(path: &Path, writable_paths: &[PathBuf]) -> bool {
    writable_paths
        .iter()
        .any(|allowed| path.starts_with(allowed))
}

/// Decode standard padded RFC 4648 base64 without accepting whitespace or
/// non-standard characters.
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

/// `fs.write`: atomically replace/create a regular file inside the writable
/// allow-list.
pub fn write(
    fs_root: &Path,
    writable_paths: &[PathBuf],
    params: &serde_json::Value,
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
                // A symlink being overwritten must not resolve outside the
                // boundary; a dangling link is safe to replace since the
                // rename only replaces the link entry itself.
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

/// `fs.delete`: remove one regular file or symlink. Directories are never
/// recursively or directly deleted.
pub fn delete(
    fs_root: &Path,
    writable_paths: &[PathBuf],
    params: &serde_json::Value,
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
        // Deleting a symlink removes the link entry only. An escaping
        // symlink whose target resolves outside the root/writable set is
        // rejected; a dangling symlink is safely removable because its
        // target simply does not exist.
        match target.canonicalize() {
            Ok(resolved) => {
                let root = fs_root.canonicalize().map_err(FsFailure::from)?;
                if !resolved.starts_with(&root) || !is_writable_path(&resolved, writable_paths) {
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

fn params_path(params: &serde_json::Value) -> Result<&str, FsFailure> {
    params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(FsFailure::invalid_path)
}

fn params_limit(params: &serde_json::Value, key: &str, default: usize, hard: usize) -> usize {
    params
        .get(key)
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(default)
        .clamp(1, hard)
}

/// `fs.list`: list one directory with a bounded, deterministic entry set.
pub fn list(fs_root: &Path, params: &serde_json::Value) -> Result<ListResult, FsFailure> {
    let requested = params_path(params)?.to_string();
    let max = params_limit(
        params,
        "max_entries",
        FS_DEFAULT_MAX_ENTRIES,
        FS_MAX_ENTRIES,
    );
    let resolved = resolve_within(fs_root, &requested)?;

    let mut entries: Vec<ListEntry> = Vec::new();
    let mut overflow = false;
    for entry in fs::read_dir(&resolved).map_err(FsFailure::from)? {
        let entry = match entry {
            Ok(entry) => entry,
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

/// `fs.stat`: metadata for one path (symlinks followed).
pub fn stat(fs_root: &Path, params: &serde_json::Value) -> Result<StatResult, FsFailure> {
    let requested = params_path(params)?.to_string();
    let resolved = resolve_within(fs_root, &requested)?;
    let md = fs::metadata(&resolved).map_err(FsFailure::from)?;

    use std::os::unix::fs::MetadataExt;
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

fn system_time_unix(t: std::time::SystemTime) -> Option<u64> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// `fs.read`: read up to a bounded number of bytes, base64-encoded.
///
/// The effective cap is the request limit clamped to the hard maximum and to
/// what keeps the framed response within `MAX_RESPONSE_SIZE` (base64 inflates
/// the payload by ~4/3).
pub fn read(fs_root: &Path, params: &serde_json::Value) -> Result<ReadResult, FsFailure> {
    let requested = params_path(params)?.to_string();
    let max = params_limit(params, "max_bytes", FS_DEFAULT_MAX_BYTES, FS_MAX_BYTES);
    // base64(n) = 4 * ceil(n/3); leave headroom for the JSON envelope.
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

/// Minimal RFC 4648 base64 encoder (standard alphabet, padded).
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Unique temporary filesystem root, removed on drop.
    struct TestRoot {
        dir: PathBuf,
    }

    impl TestRoot {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir().join(format!(
                "igris-fs-test-{}-{}-{}",
                std::process::id(),
                n,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            fs::create_dir_all(&dir).expect("create test root");
            Self { dir }
        }

        fn path(&self, rel: &str) -> String {
            self.dir.join(rel).to_string_lossy().into_owned()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn resolves_valid_in_root_path() {
        let root = TestRoot::new();
        fs::write(root.path("a.txt"), b"hi").expect("write");
        let resolved = resolve_within(&root.dir, &root.path("a.txt")).expect("resolves");
        assert!(resolved.starts_with(root.dir.canonicalize().unwrap()));
    }

    #[test]
    fn rejects_absolute_outside_root() {
        let root = TestRoot::new();
        let err = resolve_within(&root.dir, "/etc/hostname").expect_err("outside root rejected");
        assert_eq!(err.code, error_code::BAD_REQUEST);
        assert!(err.denied);
    }

    #[test]
    fn rejects_traversal_resolving_outside_root() {
        let root = TestRoot::new();
        let escape = format!("{}/../..", root.dir.display());
        let err = resolve_within(&root.dir, &escape).expect_err("traversal rejected");
        assert!(err.denied);
    }

    #[test]
    fn accepts_dot_dot_that_stays_inside() {
        let root = TestRoot::new();
        fs::create_dir_all(root.path("sub")).expect("mkdir");
        fs::write(root.path("a.txt"), b"x").expect("write");
        let p = format!("{}/sub/../a.txt", root.dir.display());
        assert!(resolve_within(&root.dir, &p).is_ok());
    }

    #[test]
    fn follows_symlink_resolving_inside_root() {
        let root = TestRoot::new();
        fs::write(root.path("real.txt"), b"data").expect("write");
        std::os::unix::fs::symlink(root.path("real.txt"), root.path("link.txt")).expect("symlink");
        assert!(resolve_within(&root.dir, &root.path("link.txt")).is_ok());
    }

    #[test]
    fn rejects_symlink_escaping_root() {
        let root = TestRoot::new();
        std::os::unix::fs::symlink("/etc/hostname", root.path("evil.txt")).expect("symlink");
        let err = resolve_within(&root.dir, &root.path("evil.txt")).expect_err("escape rejected");
        assert!(err.denied);
    }

    #[test]
    fn rejects_nonexistent_path() {
        let root = TestRoot::new();
        let err = resolve_within(&root.dir, &root.path("nope.txt")).expect_err("missing");
        assert_eq!(err.code, error_code::NOT_FOUND);
    }

    #[test]
    fn rejects_nul_path() {
        let root = TestRoot::new();
        let err = resolve_within(&root.dir, "/tmp/a\0b").expect_err("nul");
        assert_eq!(err.code, error_code::BAD_REQUEST);
    }

    #[test]
    fn read_truncates_and_truncates_flag() {
        let root = TestRoot::new();
        fs::write(root.path("big.bin"), vec![b'x'; 5000]).expect("write");
        let res = read(
            &root.dir,
            &serde_json::json!({"path": root.path("big.bin"), "max_bytes": 100}),
        )
        .expect("read");
        assert!(res.truncated);
        assert_eq!(res.size_bytes, 100);
        assert_eq!(res.encoding, "base64");
        assert_eq!(res.path, root.path("big.bin"));
    }

    #[test]
    fn read_hard_maximum_caps_data() {
        let root = TestRoot::new();
        fs::write(root.path("huge.bin"), vec![b'y'; 2 * 1024 * 1024]).expect("write");
        let res = read(
            &root.dir,
            &serde_json::json!({"path": root.path("huge.bin"), "max_bytes": FS_MAX_BYTES}),
        )
        .expect("read");
        assert!(res.truncated);
        // Result must fit in a framed response.
        let payload = serde_json::to_string(&res).expect("json");
        assert!(payload.len() <= MAX_RESPONSE_SIZE);
        assert!(res.size_bytes <= FS_MAX_BYTES as u64);
    }

    #[test]
    fn read_decodes_back_to_original() {
        let root = TestRoot::new();
        let data: Vec<u8> = (0u8..=255).collect();
        fs::write(root.path("bytes.bin"), &data).expect("write");
        let res = read(
            &root.dir,
            &serde_json::json!({"path": root.path("bytes.bin")}),
        )
        .expect("read");
        assert!(!res.truncated);
        assert_eq!(res.size_bytes, 256);
        assert_eq!(res.data.len() % 4, 0);
    }

    #[test]
    fn list_default_limit_and_truncation() {
        let root = TestRoot::new();
        for i in 0..300 {
            fs::write(root.path(&format!("f{i:03}.txt")), b"x").expect("write");
        }
        let res = list(&root.dir, &serde_json::json!({"path": root.path(".")})).expect("list");
        assert!(res.truncated);
        assert_eq!(res.entries.len(), FS_DEFAULT_MAX_ENTRIES);
    }

    #[test]
    fn list_hard_maximum() {
        let root = TestRoot::new();
        for i in 0..1100 {
            fs::write(root.path(&format!("g{i:04}.txt")), b"x").expect("write");
        }
        let res = list(
            &root.dir,
            &serde_json::json!({"path": root.path("."), "max_entries": FS_MAX_ENTRIES}),
        )
        .expect("list");
        assert!(res.truncated);
        assert_eq!(res.entries.len(), FS_MAX_ENTRIES);
    }

    #[test]
    fn list_result_is_sorted_and_typed() {
        let root = TestRoot::new();
        fs::write(root.path("b.txt"), b"12").expect("write");
        fs::create_dir(root.path("adir")).expect("mkdir");
        let res = list(&root.dir, &serde_json::json!({"path": root.path(".")})).expect("list");
        assert!(!res.truncated);
        let names: Vec<&str> = res.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["adir", "b.txt"]);
        assert_eq!(res.entries[0].kind, "directory");
        assert_eq!(res.entries[1].kind, "file");
        assert_eq!(res.entries[1].size_bytes, Some(2));
    }

    #[test]
    fn stat_result_structure() {
        let root = TestRoot::new();
        fs::write(root.path("s.txt"), b"hello").expect("write");
        let res = stat(&root.dir, &serde_json::json!({"path": root.path("s.txt")})).expect("stat");
        assert_eq!(res.kind, "file");
        assert_eq!(res.size_bytes, 5);
        assert!(res.mode > 0);
        assert!(res.modified_unix.is_some());
        assert_eq!(res.path, root.path("s.txt"));
    }

    #[test]
    fn write_creates_new_file() {
        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        fs::create_dir_all(&writable).expect("create writable directory");

        let target = writable.join("created.txt");
        let params = serde_json::json!({
            "path": target,
            "content_base64": "aGVsbG8=",
            "confirm": true
        });

        let result = write(&root.dir, &[writable.canonicalize().unwrap()], &params)
            .expect("write should succeed");

        assert_eq!(result.size_bytes, 5);
        assert!(!result.overwritten);
        assert_eq!(fs::read(&target).unwrap(), b"hello");
    }

    #[test]
    fn write_overwrites_existing_file() {
        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        fs::create_dir_all(&writable).expect("create writable directory");

        let target = writable.join("existing.txt");
        fs::write(&target, b"old").expect("create existing file");

        let params = serde_json::json!({
            "path": target,
            "content_base64": "bmV3",
            "confirm": true
        });

        let result = write(&root.dir, &[writable.canonicalize().unwrap()], &params)
            .expect("write should succeed");

        assert_eq!(result.size_bytes, 3);
        assert!(result.overwritten);
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn write_rejects_path_outside_writable_allow_list() {
        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        let other = root.dir.join("other");

        fs::create_dir_all(&writable).expect("create writable directory");
        fs::create_dir_all(&other).expect("create other directory");

        let target = other.join("blocked.txt");
        let params = serde_json::json!({
            "path": target,
            "content_base64": "aGVsbG8=",
            "confirm": true
        });

        let result = write(&root.dir, &[writable.canonicalize().unwrap()], &params);

        assert_eq!(result.unwrap_err().code, error_code::BAD_REQUEST);
    }

    #[test]
    fn write_rejects_malformed_base64() {
        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        fs::create_dir_all(&writable).expect("create writable directory");

        let target = writable.join("bad.txt");
        let params = serde_json::json!({
            "path": target,
            "content_base64": "not-base64!",
            "confirm": true
        });

        let result = write(&root.dir, &[writable.canonicalize().unwrap()], &params);

        assert_eq!(result.unwrap_err().code, error_code::BAD_REQUEST);
    }

    #[test]
    fn write_enforces_max_bytes() {
        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        fs::create_dir_all(&writable).expect("create writable directory");

        let target = writable.join("large.txt");
        let params = serde_json::json!({
            "path": target,
            "content_base64": "aGVsbG8=",
            "max_bytes": 4,
            "confirm": true
        });

        let result = write(&root.dir, &[writable.canonicalize().unwrap()], &params);

        assert_eq!(result.unwrap_err().code, error_code::BAD_REQUEST);
        assert!(!target.exists());
    }

    #[test]
    fn delete_removes_regular_file() {
        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        fs::create_dir_all(&writable).expect("create writable directory");

        let target = writable.join("delete.txt");
        fs::write(&target, b"remove me").expect("create file");

        let params = serde_json::json!({
            "path": target,
            "confirm": true
        });

        let result = delete(&root.dir, &[writable.canonicalize().unwrap()], &params)
            .expect("delete should succeed");

        assert!(result.deleted);
        assert!(!target.exists());
    }

    #[test]
    fn delete_rejects_directory() {
        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        let target = writable.join("directory");

        fs::create_dir_all(&target).expect("create directory");

        let params = serde_json::json!({
            "path": target,
            "confirm": true
        });

        let result = delete(&root.dir, &[writable.canonicalize().unwrap()], &params);

        assert_eq!(result.unwrap_err().code, error_code::FS_ERROR);
        assert!(target.exists());
    }

    #[test]
    #[cfg(unix)]
    fn delete_removes_symlink_without_deleting_target() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        fs::create_dir_all(&writable).expect("create writable directory");

        let target = writable.join("target.txt");
        let link = writable.join("link.txt");

        fs::write(&target, b"keep me").expect("create target");
        symlink(&target, &link).expect("create symlink");

        let params = serde_json::json!({
            "path": link,
            "confirm": true
        });

        delete(&root.dir, &[writable.canonicalize().unwrap()], &params)
            .expect("delete should succeed");

        assert!(!link.exists());
        assert_eq!(fs::read(&target).unwrap(), b"keep me");
    }

    #[test]
    #[cfg(unix)]
    fn write_rejects_symlink_escaping_writable_area() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        let outside = root.dir.join("outside");

        fs::create_dir_all(&writable).expect("create writable directory");
        fs::create_dir_all(&outside).expect("create outside directory");

        let outside_target = outside.join("secret.txt");
        let link = writable.join("link.txt");

        fs::write(&outside_target, b"protected").expect("create outside target");
        symlink(&outside_target, &link).expect("create symlink");

        let params = serde_json::json!({
            "path": link,
            "content_base64": "bWFsaWNpb3Vz",
            "confirm": true
        });

        let result = write(&root.dir, &[writable.canonicalize().unwrap()], &params);

        assert_eq!(result.unwrap_err().code, error_code::BAD_REQUEST);
        assert_eq!(fs::read(&outside_target).unwrap(), b"protected");
    }

    #[test]
    #[cfg(unix)]
    fn delete_rejects_symlink_escaping_writable_area() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        let outside = root.dir.join("outside");

        fs::create_dir_all(&writable).expect("create writable directory");
        fs::create_dir_all(&outside).expect("create outside directory");

        let outside_target = outside.join("secret.txt");
        let link = writable.join("link.txt");

        fs::write(&outside_target, b"protected").expect("create outside target");
        symlink(&outside_target, &link).expect("create symlink");

        let params = serde_json::json!({
            "path": link,
            "confirm": true
        });

        let result = delete(&root.dir, &[writable.canonicalize().unwrap()], &params);

        assert_eq!(result.unwrap_err().code, error_code::BAD_REQUEST);
        assert!(link.exists());
        assert_eq!(fs::read(&outside_target).unwrap(), b"protected");
    }

    #[test]
    #[cfg(unix)]
    fn delete_removes_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        fs::create_dir_all(&writable).expect("create writable directory");

        let link = writable.join("dangling.txt");
        symlink(writable.join("missing-target.txt"), &link).expect("create dangling symlink");

        let params = serde_json::json!({
            "path": link,
            "confirm": true
        });

        delete(&root.dir, &[writable.canonicalize().unwrap()], &params)
            .expect("dangling symlink should be deletable");

        assert!(!link.exists());
        assert!(!writable.join("missing-target.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn write_over_dangling_symlink_replaces_link() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new();
        let writable = root.dir.join("writable");
        fs::create_dir_all(&writable).expect("create writable directory");

        let link = writable.join("dangling.txt");
        symlink(writable.join("missing-target.txt"), &link).expect("create dangling symlink");

        let params = serde_json::json!({
            "path": link,
            "content_base64": "aGVsbG8=",
            "confirm": true
        });

        write(&root.dir, &[writable.canonicalize().unwrap()], &params)
            .expect("overwrite over dangling link should succeed");

        assert_eq!(fs::read(&link).unwrap(), b"hello");
        assert!(!writable.join("missing-target.txt").exists());
    }

    #[test]
    fn base64_round_trip_matches_known_vector() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
    }
}
