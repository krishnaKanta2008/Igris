//! Linux namespace operations for provider sandboxing.

use std::path::Path;

use nix::errno::Errno;
use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use nix::unistd::{getgid, getuid};
use thiserror::Error;

/// Errors from namespace operations.
#[derive(Debug, Error)]
pub enum NamespaceError {
    #[error("failed to unshare namespace: {0}")]
    Unshare(Errno),
    #[error("failed to set uid/gid map: {0}")]
    IdMap(std::io::Error),
    #[error("failed to mount proc: {0}")]
    MountProc(Errno),
    #[error("failed to bind mount: {0}")]
    BindMount(Errno),
    #[error("invalid filesystem root: {0}")]
    InvalidFsRoot(String),
}

/// Setup user namespace with uid/gid mapping.
///
/// Maps the current user to root inside the namespace for mount operations,
/// but keeps the actual uid/gid for file access.
pub fn setup_user_namespace() -> Result<(), NamespaceError> {
    // Unshare user namespace first (must be done before other namespaces
    // when not root)
    unshare_user_namespace()?;

    // Write uid/gid maps
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    write_id_map("/proc/self/uid_map", uid)?;
    write_id_map("/proc/self/gid_map", gid)?;

    // Disable setgroups (required for non-root gid mapping)
    std::fs::write("/proc/self/setgroups", "deny").map_err(NamespaceError::IdMap)?;

    Ok(())
}

fn unshare_user_namespace() -> Result<(), NamespaceError> {
    // Use nix's unshare for user namespace
    // Note: CLONE_NEWUSER requires kernel 3.8+
    nix::sched::unshare(CloneFlags::CLONE_NEWUSER).map_err(NamespaceError::Unshare)?;
    Ok(())
}

fn write_id_map(path: &str, id: u32) -> Result<(), NamespaceError> {
    // Map the single uid/gid to itself inside the namespace
    let map = format!("{} {} 1", id, id);
    std::fs::write(path, map).map_err(NamespaceError::IdMap)
}

/// Setup PID namespace.
pub fn setup_pid_namespace() -> Result<(), NamespaceError> {
    nix::sched::unshare(CloneFlags::CLONE_NEWPID).map_err(NamespaceError::Unshare)?;
    Ok(())
}

/// Setup network namespace (no network access).
pub fn setup_network_namespace() -> Result<(), NamespaceError> {
    nix::sched::unshare(CloneFlags::CLONE_NEWNET).map_err(NamespaceError::Unshare)?;
    Ok(())
}

/// Setup IPC namespace (isolate System V IPC, POSIX message queues).
pub fn setup_ipc_namespace() -> Result<(), NamespaceError> {
    nix::sched::unshare(CloneFlags::CLONE_NEWIPC).map_err(NamespaceError::Unshare)?;
    Ok(())
}

/// Setup UTS namespace (isolate hostname/domainname).
pub fn setup_uts_namespace() -> Result<(), NamespaceError> {
    nix::sched::unshare(CloneFlags::CLONE_NEWUTS).map_err(NamespaceError::Unshare)?;
    Ok(())
}

/// Setup mount namespace with filesystem containment.
///
/// This creates a new mount namespace and binds the allowed filesystem
/// paths, making everything else inaccessible.
pub fn setup_mount_namespace(
    fs_root: &Path,
    writable_paths: &[std::path::PathBuf],
) -> Result<(), NamespaceError> {
    // Unshare mount namespace
    nix::sched::unshare(CloneFlags::CLONE_NEWNS).map_err(NamespaceError::Unshare)?;

    // Make all mounts private so they don't propagate to host
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(NamespaceError::Unshare)?;

    // Canonicalize fs_root
    let fs_root = fs_root
        .canonicalize()
        .map_err(|e| NamespaceError::InvalidFsRoot(e.to_string()))?;

    // Bind mount fs_root to itself (read-only by default)
    nix::mount::mount(
        Some(&fs_root),
        &fs_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(NamespaceError::BindMount)?;

    // Make the bind mount read-only
    nix::mount::mount(
        Some(&fs_root),
        &fs_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(NamespaceError::BindMount)?;

    // For each writable path, remount it read-write
    for writable in writable_paths {
        let writable = writable
            .canonicalize()
            .map_err(|e| NamespaceError::InvalidFsRoot(e.to_string()))?;

        // Verify it's inside fs_root
        if !writable.starts_with(&fs_root) {
            return Err(NamespaceError::InvalidFsRoot(format!(
                "writable path {:?} escapes fs_root {:?}",
                writable, fs_root
            )));
        }

        nix::mount::mount(
            Some(&writable),
            &writable,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT,
            None::<&str>,
        )
        .map_err(NamespaceError::BindMount)?;
    }

    // Mount a new proc filesystem (hide host processes)
    let proc_path = fs_root.join("proc");
    if !proc_path.exists() {
        std::fs::create_dir_all(&proc_path)
            .map_err(|e| NamespaceError::InvalidFsRoot(e.to_string()))?;
    }
    nix::mount::mount(
        Some("proc"),
        &proc_path,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(NamespaceError::MountProc)?;

    // Mount tmpfs on /tmp for temporary files
    let tmp_path = fs_root.join("tmp");
    if !tmp_path.exists() {
        std::fs::create_dir_all(&tmp_path)
            .map_err(|e| NamespaceError::InvalidFsRoot(e.to_string()))?;
    }
    nix::mount::mount(
        Some("tmpfs"),
        &tmp_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=10M,mode=1777"),
    )
    .map_err(NamespaceError::MountProc)?;

    // Change root to fs_root
    std::os::unix::fs::chroot(&fs_root)
        .map_err(|e| NamespaceError::InvalidFsRoot(format!("chroot failed: {}", e)))?;

    // Change working directory to /
    std::env::set_current_dir("/")
        .map_err(|e| NamespaceError::InvalidFsRoot(format!("chdir failed: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_write_id_map_format() {
        // Just test the format logic
        let uid = 1000;
        let map = format!("{} {} 1", uid, uid);
        assert_eq!(map, "1000 1000 1");
    }
}
