//! cgroup v2 operations for resource limiting.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Errors from cgroup operations.
#[derive(Debug, Error)]
pub enum CgroupError {
    #[error("cgroup v2 not available: {0}")]
    NotAvailable(String),
    #[error("cgroup path not found: {0}")]
    NotFound(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("invalid cgroup path: {0}")]
    InvalidPath(String),
}

/// Find the cgroup v2 mount point.
fn find_cgroup_mount() -> Result<PathBuf, CgroupError> {
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "cgroup2" {
            return Ok(PathBuf::from(parts[1]));
        }
    }
    Err(CgroupError::NotAvailable(
        "cgroup v2 filesystem not mounted".to_string(),
    ))
}

/// Create a new cgroup under the igris slice.
pub fn create_cgroup(name: &str) -> Result<PathBuf, CgroupError> {
    let mount = find_cgroup_mount()?;
    let igris_slice = mount.join("igris");

    // Create igris slice if it doesn't exist
    if !igris_slice.exists() {
        std::fs::create_dir_all(&igris_slice)?;
        // Enable controllers
        let controllers = ["memory", "cpu", "pids"];
        for ctrl in &controllers {
            let path = mount.join("cgroup.subtree_control");
            if path.exists() {
                let _ = std::fs::write(&path, format!("+{}", ctrl));
            }
        }
    }

    let cgroup_path = igris_slice.join(name);
    std::fs::create_dir_all(&cgroup_path)?;

    // Enable controllers for this cgroup
    let subtree_control = cgroup_path.join("cgroup.subtree_control");
    if subtree_control.exists() {
        let _ = std::fs::write(&subtree_control, "+memory +cpu +pids");
    }

    Ok(cgroup_path)
}

/// Set memory limit for a cgroup (in bytes).
pub fn set_memory_limit(cgroup_path: &Path, limit_bytes: u64) -> Result<(), CgroupError> {
    let max_path = cgroup_path.join("memory.max");
    std::fs::write(&max_path, limit_bytes.to_string())?;
    Ok(())
}

/// Set CPU limit for a cgroup (quota/period in microseconds).
pub fn set_cpu_limit(cgroup_path: &Path, quota_us: u64, period_us: u64) -> Result<(), CgroupError> {
    let max_path = cgroup_path.join("cpu.max");
    std::fs::write(&max_path, format!("{} {}", quota_us, period_us))?;
    Ok(())
}

/// Set maximum number of processes in a cgroup.
pub fn set_pids_max(cgroup_path: &Path, max: u64) -> Result<(), CgroupError> {
    let max_path = cgroup_path.join("pids.max");
    std::fs::write(&max_path, max.to_string())?;
    Ok(())
}

/// Add current process to a cgroup.
pub fn attach_current_process(cgroup_path: &Path) -> Result<(), CgroupError> {
    let procs_path = cgroup_path.join("cgroup.procs");
    let pid = std::process::id();
    std::fs::write(&procs_path, pid.to_string())?;
    Ok(())
}

/// Remove a cgroup (must be empty).
pub fn remove_cgroup(cgroup_path: &Path) -> Result<(), CgroupError> {
    if cgroup_path.exists() {
        std::fs::remove_dir_all(cgroup_path)?;
    }
    Ok(())
}

/// Get memory usage for a cgroup (in bytes).
pub fn get_memory_usage(cgroup_path: &Path) -> Result<u64, CgroupError> {
    let current_path = cgroup_path.join("memory.current");
    let content = std::fs::read_to_string(&current_path)?;
    content.trim().parse().map_err(|e| {
        CgroupError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse memory.current: {}", e),
        ))
    })
}

/// Get CPU usage for a cgroup (in microseconds).
pub fn get_cpu_usage(cgroup_path: &Path) -> Result<u64, CgroupError> {
    let stat_path = cgroup_path.join("cpu.stat");
    let content = std::fs::read_to_string(&stat_path)?;
    for line in content.lines() {
        if line.starts_with("usage_usec ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                return parts[1].parse().map_err(|e| {
                    CgroupError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("failed to parse cpu.stat: {}", e),
                    ))
                });
            }
        }
    }
    Err(CgroupError::NotFound(cgroup_path.join("cpu.stat")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_cgroup_mount() {
        // This test may fail in environments without cgroup v2
        // We just verify it doesn't panic
        let _ = find_cgroup_mount();
    }
}
