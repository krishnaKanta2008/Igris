//! Igris provider sandbox.
//!
//! This crate provides process isolation for providers using Linux namespaces,
//! cgroups (v2), and seccomp. Each provider runs in a dedicated sandboxed
//! process with a minimal attack surface.

use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::Stdio;

use thiserror::Error;

pub mod cgroup;
pub mod namespace;
pub mod seccomp;

/// Errors that can occur during sandbox setup or operation.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("namespace setup failed: {0}")]
    Namespace(#[from] namespace::NamespaceError),
    #[error("cgroup setup failed: {0}")]
    Cgroup(#[from] cgroup::CgroupError),
    #[error("seccomp setup failed: {0}")]
    Seccomp(#[from] seccomp::SeccompError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("provider process exited with status: {0}")]
    ProcessExited(i32),
    #[error("provider process terminated by signal: {0}")]
    ProcessSignaled(i32),
    #[error("socket pair creation failed: {0}")]
    SocketPair(std::io::Error),
}

/// Configuration for a sandboxed provider.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Provider binary name (e.g., "igris-fs-provider", "igris-process-provider").
    pub provider_binary: String,
    /// Arguments to pass to the provider binary.
    pub args: Vec<String>,
    /// Filesystem root for the provider (for path containment).
    pub fs_root: PathBuf,
    /// Writable paths allowed for this provider.
    pub writable_paths: Vec<PathBuf>,
    /// Cgroup memory limit in bytes (optional).
    pub memory_limit: Option<u64>,
    /// Cgroup CPU quota (microseconds per period, optional).
    pub cpu_quota: Option<u64>,
    /// Cgroup CPU period (microseconds, optional).
    pub cpu_period: Option<u64>,
    /// Maximum number of processes in the cgroup (optional).
    pub pids_max: Option<u64>,
    /// Whether to enable network namespace (isolates network).
    pub enable_network_namespace: bool,
    /// Custom seccomp profile name (optional, uses default if not set).
    pub seccomp_profile: Option<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            provider_binary: "igris-provider".to_string(),
            args: Vec::new(),
            fs_root: PathBuf::from("/"),
            writable_paths: Vec::new(),
            memory_limit: Some(64 * 1024 * 1024), // 64 MiB default
            cpu_quota: Some(50000),               // 50% of one CPU core
            cpu_period: Some(100000),             // 100ms period
            pids_max: Some(32),
            enable_network_namespace: true,
            seccomp_profile: None,
        }
    }
}

/// A sandboxed provider process with its communication channel.
pub struct SandboxedProvider {
    /// The child process handle.
    child: std::process::Child,
    /// The Unix stream for communicating with the provider.
    stream: UnixStream,
    /// Cgroup path for cleanup.
    cgroup_path: Option<PathBuf>,
}

impl SandboxedProvider {
    /// Spawn a new sandboxed provider process.
    ///
    /// This function:
    /// 1. Creates a socket pair for communication
    /// 2. Sets up cgroup (if configured)
    /// 3. Spawns the provider process with namespaces and seccomp
    /// 4. Returns the provider handle and communication stream
    pub fn spawn(config: SandboxConfig) -> Result<Self, SandboxError> {
        // Create socket pair for communication
        let (server_stream, _client_stream) = UnixStream::pair()?;

        // Set up cgroup if limits are configured
        let cgroup_path = if config.memory_limit.is_some()
            || config.cpu_quota.is_some()
            || config.pids_max.is_some()
        {
            let cgroup_name = format!("igris-{}", std::process::id());
            let path = cgroup::create_cgroup(&cgroup_name)?;

            if let Some(limit) = config.memory_limit {
                cgroup::set_memory_limit(&path, limit)?;
            }
            if let Some(quota) = config.cpu_quota {
                if let Some(period) = config.cpu_period {
                    cgroup::set_cpu_limit(&path, quota, period)?;
                }
            }
            if let Some(max) = config.pids_max {
                cgroup::set_pids_max(&path, max)?;
            }

            Some(path)
        } else {
            None
        };

        // Build the command with sandbox wrapper
        let mut cmd = std::process::Command::new(&config.provider_binary);
        cmd.args(&config.args);

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        unsafe {
            cmd.pre_exec(move || {
                if config.enable_network_namespace {
                    namespace::setup_network_namespace()
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                }
                namespace::setup_mount_namespace(&config.fs_root, &config.writable_paths)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                namespace::setup_user_namespace()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                namespace::setup_pid_namespace()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                namespace::setup_ipc_namespace()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                namespace::setup_uts_namespace()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;

                seccomp::apply_default_filter(config.seccomp_profile.as_deref())
                    .map_err(|e| std::io::Error::other(e.to_string()))?;

                Ok(())
            });
        }

        let child = cmd.spawn()?;

        Ok(Self {
            child,
            stream: server_stream,
            cgroup_path,
        })
    }

    /// Get a reference to the communication stream.
    pub fn stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Get a mutable reference to the communication stream.
    pub fn stream_mut(&mut self) -> &mut UnixStream {
        &mut self.stream
    }

    /// Wait for the provider process to exit.
    pub fn wait(&mut self) -> Result<std::process::ExitStatus, SandboxError> {
        let status = self.child.wait()?;
        if let Some(code) = status.code() {
            if code != 0 {
                return Err(SandboxError::ProcessExited(code));
            }
        } else if let Some(signal) = status.signal() {
            return Err(SandboxError::ProcessSignaled(signal));
        }
        Ok(status)
    }

    /// Try to wait for the provider without blocking.
    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, SandboxError> {
        match self.child.try_wait()? {
            Some(status) => {
                if let Some(code) = status.code() {
                    if code != 0 {
                        return Err(SandboxError::ProcessExited(code));
                    }
                } else if let Some(signal) = status.signal() {
                    return Err(SandboxError::ProcessSignaled(signal));
                }
                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    /// Forcefully terminate the provider process.
    pub fn kill(&mut self) -> Result<(), SandboxError> {
        self.child.kill()?;
        Ok(())
    }

    /// Get the process ID of the provider.
    pub fn id(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for SandboxedProvider {
    fn drop(&mut self) {
        let _ = self.kill();
        let _ = self.wait();
        if let Some(path) = &self.cgroup_path {
            let _ = cgroup::remove_cgroup(path);
        }
    }
}

/// Provider-side sandbox initialization.
///
/// This function should be called early in the provider binary's main()
/// to apply sandboxing when running as a sandboxed provider.
pub fn init_provider_sandbox(
    fs_root: &std::path::Path,
    writable_paths: &[PathBuf],
    enable_network_namespace: bool,
    seccomp_profile: Option<&str>,
) -> Result<(), SandboxError> {
    if enable_network_namespace {
        namespace::setup_network_namespace()?;
    }
    namespace::setup_mount_namespace(fs_root, writable_paths)?;
    namespace::setup_user_namespace()?;
    namespace::setup_pid_namespace()?;
    namespace::setup_ipc_namespace()?;
    namespace::setup_uts_namespace()?;

    seccomp::apply_default_filter(seccomp_profile)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn sandbox_config_defaults() {
        let config = SandboxConfig::default();
        assert_eq!(config.memory_limit, Some(64 * 1024 * 1024));
        assert_eq!(config.cpu_quota, Some(50000));
        assert_eq!(config.pids_max, Some(32));
        assert!(config.enable_network_namespace);
    }

    #[test]
    fn init_provider_sandbox_works_in_test() {
        let temp = TempDir::new().unwrap();
        let fs_root = temp.path().to_path_buf();
        fs::create_dir_all(&fs_root).unwrap();

        let _ = init_provider_sandbox(&fs_root, &[], false, None);
    }
}
