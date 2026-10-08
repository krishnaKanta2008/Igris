//! Sandboxed provider management for igrisd.
//!
//! This module spawns and manages sandboxed provider processes, each running
//! in its own isolated environment with namespace, cgroup, and seccomp isolation.
//! Providers communicate with igrisd over Unix domain sockets.

use std::io;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use igris_proto::{read_frame, write_frame, ReadFrame, Request, Response, MAX_RESPONSE_SIZE};

use igris_sandbox::{cgroup, namespace, seccomp};

/// Convert CgroupError to io::Error
fn cgroup_err_to_io(e: cgroup::CgroupError) -> io::Error {
    io::Error::other(e.to_string())
}

/// Configuration for a managed provider.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: &'static str,
    pub binary: &'static str,
    pub socket_path: PathBuf,
    pub fs_root: PathBuf,
    pub writable_paths: Vec<PathBuf>,
    pub memory_limit: Option<u64>,
    pub cpu_quota: Option<u64>,
    pub cpu_period: Option<u64>,
    pub pids_max: Option<u64>,
    pub enable_network_namespace: bool,
}

/// A handle to a running sandboxed provider.
pub struct ProviderHandle {
    pub name: &'static str,
    pub socket_path: PathBuf,
    pub process: Arc<Mutex<std::process::Child>>,
    pub cgroup_path: Option<PathBuf>,
}

impl ProviderHandle {
    /// Send a request to the provider and wait for response.
    pub fn call(&self, request: &Request) -> io::Result<Response> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;

        // Serialize and frame the request
        let request_bytes = serde_json::to_vec(request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_frame(&mut stream, &request_bytes)?;

        // Read response
        let frame = read_frame(&mut stream, MAX_RESPONSE_SIZE)?;
        match frame {
            ReadFrame::Received(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            ReadFrame::TooLarge { declared } => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("response too large: {declared} bytes"),
            )),
            ReadFrame::Closed => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "provider closed connection",
            )),
        }
    }

    /// Check if the provider process is still alive.
    pub fn is_alive(&self) -> bool {
        let mut process = self.process.lock().unwrap();
        match process.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => false,
        }
    }

    /// Terminate the provider process.
    pub fn kill(&self) -> io::Result<()> {
        let mut process = self.process.lock().unwrap();
        process.kill()
    }
}

/// Manager for all sandboxed providers.
pub struct ProviderManager {
    pub providers: Vec<ProviderHandle>,
    pub provider_dir: PathBuf,
}

impl ProviderManager {
    /// Create a new provider manager and spawn all providers.
    pub fn spawn_all(
        fs_root: &Path,
        writable_paths: &[PathBuf],
        provider_dir: &Path,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(provider_dir)?;

        let mut providers = Vec::new();

        // Spawn filesystem provider
        let fs_socket = provider_dir.join("igris-fs.sock");
        let fs_provider = Self::spawn_provider(ProviderConfig {
            name: "fs",
            binary: "igris-fs-provider",
            socket_path: fs_socket.clone(),
            fs_root: fs_root.to_path_buf(),
            writable_paths: writable_paths.to_vec(),
            memory_limit: Some(64 * 1024 * 1024),
            cpu_quota: Some(50000),
            cpu_period: Some(100000),
            pids_max: Some(32),
            enable_network_namespace: true,
        })?;
        providers.push(fs_provider);

        // Spawn process provider
        let process_socket = provider_dir.join("igris-process.sock");
        let process_provider = Self::spawn_provider(ProviderConfig {
            name: "process",
            binary: "igris-process-provider",
            socket_path: process_socket.clone(),
            fs_root: PathBuf::from("/"),
            writable_paths: vec![],
            memory_limit: Some(32 * 1024 * 1024),
            cpu_quota: Some(50000),
            cpu_period: Some(100000),
            pids_max: Some(16),
            enable_network_namespace: true,
        })?;
        providers.push(process_provider);

        // Spawn system provider
        let system_socket = provider_dir.join("igris-system.sock");
        let system_provider = Self::spawn_provider(ProviderConfig {
            name: "system",
            binary: "igris-system-provider",
            socket_path: system_socket.clone(),
            fs_root: PathBuf::from("/"),
            writable_paths: vec![],
            memory_limit: Some(16 * 1024 * 1024),
            cpu_quota: Some(25000),
            cpu_period: Some(100000),
            pids_max: Some(8),
            enable_network_namespace: true,
        })?;
        providers.push(system_provider);

        // Spawn events provider
        let events_socket = provider_dir.join("igris-events.sock");
        let events_provider = Self::spawn_provider(ProviderConfig {
            name: "events",
            binary: "igris-events-provider",
            socket_path: events_socket.clone(),
            fs_root: fs_root.to_path_buf(),
            writable_paths: writable_paths.to_vec(),
            memory_limit: Some(32 * 1024 * 1024),
            cpu_quota: Some(50000),
            cpu_period: Some(100000),
            pids_max: Some(16),
            enable_network_namespace: true,
        })?;
        providers.push(events_provider);

        // Wait for all providers to be ready
        for provider in &providers {
            Self::wait_for_provider(&provider.socket_path)?;
        }

        Ok(Self {
            providers,
            provider_dir: provider_dir.to_path_buf(),
        })
    }

    /// Spawn a single provider process.
    fn spawn_provider(config: ProviderConfig) -> io::Result<ProviderHandle> {
        let socket_path = config.socket_path.clone();

        // Create the provider directory for cgroup
        let cgroup_name = format!("igris-{}", config.name);
        let cgroup_path = cgroup::create_cgroup(&cgroup_name).map_err(cgroup_err_to_io)?;

        if let Some(limit) = config.memory_limit {
            cgroup::set_memory_limit(&cgroup_path, limit).map_err(cgroup_err_to_io)?;
        }
        if let Some(quota) = config.cpu_quota {
            if let Some(period) = config.cpu_period {
                cgroup::set_cpu_limit(&cgroup_path, quota, period).map_err(cgroup_err_to_io)?;
            }
        }
        if let Some(max) = config.pids_max {
            cgroup::set_pids_max(&cgroup_path, max).map_err(cgroup_err_to_io)?;
        }

        // Build the command
        let mut cmd = std::process::Command::new(config.binary);
        cmd.arg(&socket_path).arg(&config.fs_root);

        for wp in &config.writable_paths {
            cmd.arg(wp);
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        // Apply sandboxing in pre_exec
        let fs_root = config.fs_root.clone();
        let writable_paths = config.writable_paths.clone();
        let enable_network = config.enable_network_namespace;
        let cgroup_path_for_child = cgroup_path.clone();

        unsafe {
            cmd.pre_exec(move || {
                if enable_network {
                    namespace::setup_network_namespace()
                        .map_err(|e| io::Error::other(e.to_string()))?;
                }
                namespace::setup_mount_namespace(&fs_root, &writable_paths)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                namespace::setup_user_namespace().map_err(|e| io::Error::other(e.to_string()))?;
                namespace::setup_pid_namespace().map_err(|e| io::Error::other(e.to_string()))?;
                namespace::setup_ipc_namespace().map_err(|e| io::Error::other(e.to_string()))?;
                namespace::setup_uts_namespace().map_err(|e| io::Error::other(e.to_string()))?;

                seccomp::apply_default_filter(None).map_err(|e| io::Error::other(e.to_string()))?;

                // Attach to cgroup
                cgroup::attach_current_process(&cgroup_path_for_child).map_err(cgroup_err_to_io)?;

                Ok(())
            });
        }

        let child = cmd.spawn()?;

        // Attach the child process to the cgroup
        cgroup::attach_current_process(&cgroup_path).map_err(cgroup_err_to_io)?;

        Ok(ProviderHandle {
            name: config.name,
            socket_path,
            process: Arc::new(Mutex::new(child)),
            cgroup_path: Some(cgroup_path),
        })
    }

    /// Wait for a provider socket to become available.
    fn wait_for_provider(socket_path: &Path) -> io::Result<()> {
        for _ in 0..100 {
            if UnixStream::connect(socket_path).is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("provider at {:?} did not start in time", socket_path),
        ))
    }

    /// Get a provider by name.
    pub fn get(&self, name: &str) -> Option<&ProviderHandle> {
        self.providers.iter().find(|p| p.name == name)
    }

    /// Forward a request to the appropriate provider.
    pub fn forward_request(&self, request: &Request) -> io::Result<Response> {
        let provider_name = match request.op.as_str() {
            igris_proto::OP_SYSTEM_INFO => "system",
            igris_proto::OP_FS_LIST
            | igris_proto::OP_FS_STAT
            | igris_proto::OP_FS_READ
            | igris_proto::OP_FS_WRITE
            | igris_proto::OP_FS_DELETE => "fs",
            igris_proto::OP_PROCESS_LIST
            | igris_proto::OP_PROCESS_STAT
            | igris_proto::OP_PROCESS_CHILDREN
            | igris_proto::OP_PROC_SIGNAL => "process",
            igris_proto::OP_EVENTS_WATCH
            | igris_proto::OP_EVENTS_POLL
            | igris_proto::OP_EVENTS_UNWATCH => "events",
            _ => {
                return Ok(Response::error(
                    Some(request.id.clone()),
                    igris_proto::error_code::UNKNOWN_OPERATION,
                    "unsupported operation",
                ));
            }
        };

        let provider = self.get(provider_name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("provider {} not found", provider_name),
            )
        })?;

        provider.call(request)
    }

    /// Shutdown all providers.
    pub fn shutdown(&mut self) {
        for provider in &self.providers {
            let _ = provider.kill();
        }
        for provider in &self.providers {
            let mut process = provider.process.lock().unwrap();
            let _ = process.wait();
        }
        for provider in &self.providers {
            if let Some(cgroup_path) = &provider.cgroup_path {
                let _ = cgroup::remove_cgroup(cgroup_path).map_err(cgroup_err_to_io);
            }
        }
    }
}

impl Drop for ProviderManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}
