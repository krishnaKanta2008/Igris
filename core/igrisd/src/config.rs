//! Runtime configuration for `igrisd`.
//!
//! Paths are configurable through environment variables so the daemon can be
//! tested in isolation without touching the user's real socket or audit log:
//!
//! - `IGRIS_SOCKET_PATH` — Unix domain socket to listen on.
//! - `IGRIS_AUDIT_LOG`   — append-only audit log file.
//!
//! Both default to the shared locations in [`igris_proto`].

use std::path::PathBuf;

use igris_proto::{default_audit_log_path, default_socket_path};

/// Effective daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Path of the Unix domain socket to listen on.
    pub socket_path: PathBuf,
    /// Path of the append-only audit log.
    pub audit_log_path: PathBuf,
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
        }
    }

    /// Explicit configuration, primarily for tests.
    pub fn new(socket_path: impl Into<PathBuf>, audit_log_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            audit_log_path: audit_log_path.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_paths() {
        let cfg = Config::new("/tmp/a.sock", "/tmp/a.log");
        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/a.sock"));
        assert_eq!(cfg.audit_log_path, PathBuf::from("/tmp/a.log"));
    }
}
