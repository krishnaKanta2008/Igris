//! Runtime configuration for `igrisd`.
//!
//! Paths are configurable through environment variables so the daemon can be
//! tested in isolation without touching the user's real socket or audit log:
//!
//! - `IGRIS_SOCKET_PATH`    — Unix domain socket to listen on.
//! - `IGRIS_AUDIT_LOG`      — append-only audit log file.
//! - `IGRIS_FS_ROOT`        — canonical root for filesystem tools.
//! - `IGRIS_WRITABLE_PATHS` — colon-separated paths permitted for writes/deletes.
//!
//! The writable path list defaults to empty. An empty list means filesystem
//! writes and deletes remain unavailable.

use std::path::PathBuf;

use igris_proto::{default_audit_log_path, default_fs_root, default_socket_path};

/// Effective daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Path of the Unix domain socket to listen on.
    pub socket_path: PathBuf,

    /// Path of the append-only audit log.
    pub audit_log_path: PathBuf,

    /// Canonical root for `fs.*` operations.
    pub fs_root: PathBuf,

    /// Paths explicitly permitted for filesystem writes/deletes.
    ///
    /// Empty by default. These paths are configuration, not policy grants
    /// by themselves; the daemon will enforce containment before dispatch.
    pub writable_paths: Vec<PathBuf>,

    /// When `true`, process control operations (e.g. `proc.signal`) are
    /// permitted by policy. Defaults to `false` (default-deny).
    pub process_control_enabled: bool,
}

impl Config {
    /// Load configuration from the environment, falling back to defaults.
    pub fn from_env() -> Self {
        Self {
            socket_path: std::env::var_os("IGRIS_SOCKET_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(default_socket_path),

            audit_log_path: std::env::var_os("IGRIS_AUDIT_LOG")
                .map(PathBuf::from)
                .unwrap_or_else(default_audit_log_path),

            fs_root: std::env::var_os("IGRIS_FS_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(default_fs_root),

            writable_paths: std::env::var_os("IGRIS_WRITABLE_PATHS")
                .map(|value| {
                    value
                        .to_string_lossy()
                        .split(':')
                        .filter(|path| !path.is_empty())
                        .map(PathBuf::from)
                        .collect()
                })
                .unwrap_or_default(),

            process_control_enabled: std::env::var_os("IGRIS_PROCESS_CONTROL")
                .map(|v| {
                    let s = v.to_string_lossy();
                    s != "0" && s != "false"
                })
                .unwrap_or(false),
        }
    }

    /// Explicit configuration, primarily for tests.
    ///
    /// Uses the default filesystem root and no writable paths.
    pub fn new(socket_path: impl Into<PathBuf>, audit_log_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            audit_log_path: audit_log_path.into(),
            fs_root: default_fs_root(),
            writable_paths: Vec::new(),
            process_control_enabled: false,
        }
    }

    /// Explicit configuration with an explicit filesystem root, for tests.
    ///
    /// Writable paths remain empty unless supplied through
    /// [`Config::with_writable_paths`].
    pub fn with_fs_root(
        socket_path: impl Into<PathBuf>,
        audit_log_path: impl Into<PathBuf>,
        fs_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            audit_log_path: audit_log_path.into(),
            fs_root: fs_root.into(),
            writable_paths: Vec::new(),
            process_control_enabled: false,
        }
    }

    /// Explicit configuration including writable paths.
    pub fn with_writable_paths(
        socket_path: impl Into<PathBuf>,
        audit_log_path: impl Into<PathBuf>,
        fs_root: impl Into<PathBuf>,
        writable_paths: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            audit_log_path: audit_log_path.into(),
            fs_root: fs_root.into(),
            writable_paths: writable_paths.into_iter().map(Into::into).collect(),
            process_control_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_paths_and_disables_writes() {
        let cfg = Config::new("/tmp/a.sock", "/tmp/a.log");

        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/a.sock"));
        assert_eq!(cfg.audit_log_path, PathBuf::from("/tmp/a.log"));
        assert!(cfg.writable_paths.is_empty());
    }

    #[test]
    fn with_fs_root_sets_all_read_only_paths() {
        let cfg = Config::with_fs_root("/tmp/a.sock", "/tmp/a.log", "/tmp/root");

        assert_eq!(cfg.fs_root, PathBuf::from("/tmp/root"));
        assert!(cfg.writable_paths.is_empty());
    }

    #[test]
    fn with_writable_paths_sets_explicit_paths() {
        let cfg = Config::with_writable_paths(
            "/tmp/a.sock",
            "/tmp/a.log",
            "/tmp/root",
            ["/tmp/root/a", "/tmp/root/b"],
        );

        assert_eq!(
            cfg.writable_paths,
            vec![PathBuf::from("/tmp/root/a"), PathBuf::from("/tmp/root/b")]
        );
    }
}
