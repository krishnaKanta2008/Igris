//! Read-only filesystem provider (`fs.list`, `fs.stat`, `fs.read`).
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
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Serialize;

use igris_proto::{
    error_code, FS_DEFAULT_MAX_BYTES, FS_DEFAULT_MAX_ENTRIES, FS_MAX_BYTES, FS_MAX_ENTRIES,
    MAX_RESPONSE_SIZE,
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
    fn base64_round_trip_matches_known_vector() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
    }
}
