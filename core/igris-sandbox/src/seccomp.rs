//! Seccomp filter for provider sandboxing.

use libc::c_ulong;
use thiserror::Error;

/// Errors from seccomp operations.
#[derive(Debug, Error)]
pub enum SeccompError {
    #[error("seccomp not available: {0}")]
    NotAvailable(String),
    #[error("failed to load filter: {0}")]
    LoadFilter(std::io::Error),
    #[error("invalid filter: {0}")]
    InvalidFilter(String),
    #[error("architecture mismatch: {0}")]
    ArchMismatch(String),
}

/// Seccomp operation codes.
#[allow(dead_code)]
mod seccomp_sys {
    use libc::{c_int, c_uint, c_ulong};

    pub const SECCOMP_SET_MODE_FILTER: c_int = 1;
    pub const SECCOMP_GET_ACTION_AVAIL: c_int = 2;
    pub const SECCOMP_FILTER_FLAG_TSYNC: c_uint = 1 << 0;
    pub const SECCOMP_FILTER_FLAG_LOG: c_uint = 1 << 1;
    pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: c_uint = 1 << 2;

    pub const SECCOMP_RET_KILL_PROCESS: c_uint = 0x80000000;
    pub const SECCOMP_RET_KILL_THREAD: c_uint = 0x00000000;
    pub const SECCOMP_RET_TRAP: c_uint = 0x00030000;
    pub const SECCOMP_RET_ERRNO: c_uint = 0x00050000;
    pub const SECCOMP_RET_TRACE: c_uint = 0x7ff00000;
    pub const SECCOMP_RET_LOG: c_uint = 0x7ffc0000;
    pub const SECCOMP_RET_ALLOW: c_uint = 0x7fff0000;

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct sock_filter {
        pub code: u16,
        pub jt: u8,
        pub jf: u8,
        pub k: c_ulong,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct sock_fprog {
        pub len: u16,
        pub filter: *const sock_filter,
    }
}

/// BPF instruction macros.
macro_rules! BPF_STMT {
    ($code:expr, $k:expr) => {
        seccomp_sys::sock_filter {
            code: $code,
            jt: 0,
            jf: 0,
            k: $k as c_ulong,
        }
    };
}

macro_rules! BPF_JUMP {
    ($code:expr, $k:expr, $jt:expr, $jf:expr) => {
        seccomp_sys::sock_filter {
            code: $code,
            jt: $jt,
            jf: $jf,
            k: $k as c_ulong,
        }
    };
}

/// BPF instruction classes.
#[allow(dead_code)]
mod bpf {
    pub const BPF_LD: u16 = 0x00;
    pub const BPF_LDX: u16 = 0x01;
    pub const BPF_ST: u16 = 0x02;
    pub const BPF_STX: u16 = 0x03;
    pub const BPF_ALU: u16 = 0x04;
    pub const BPF_JMP: u16 = 0x05;
    pub const BPF_RET: u16 = 0x06;
    pub const BPF_MISC: u16 = 0x07;

    pub const BPF_W: u16 = 0x00;
    pub const BPF_H: u16 = 0x08;
    pub const BPF_B: u16 = 0x10;

    pub const BPF_IMM: u16 = 0x00;
    pub const BPF_ABS: u16 = 0x20;
    pub const BPF_IND: u16 = 0x40;
    pub const BPF_MEM: u16 = 0x60;
    pub const BPF_LEN: u16 = 0x80;
    pub const BPF_MSH: u16 = 0xa0;

    pub const BPF_JA: u16 = 0x00;
    pub const BPF_JEQ: u16 = 0x10;
    pub const BPF_JGT: u16 = 0x20;
    pub const BPF_JGE: u16 = 0x30;
    pub const BPF_JSET: u16 = 0x40;

    pub const BPF_K: u16 = 0x00;
    pub const BPF_X: u16 = 0x08;

    pub const BPF_ADD: u16 = 0x00;
    pub const BPF_SUB: u16 = 0x10;
    pub const BPF_MUL: u16 = 0x20;
    pub const BPF_DIV: u16 = 0x30;
    pub const BPF_OR: u16 = 0x40;
    pub const BPF_AND: u16 = 0x50;
    pub const BPF_LSH: u16 = 0x60;
    pub const BPF_RSH: u16 = 0x70;
    pub const BPF_NEG: u16 = 0x80;
    pub const BPF_MOD: u16 = 0x90;
    pub const BPF_XOR: u16 = 0xa0;

    // seccomp data offsets
    pub const SECCOMP_DATA_NR: usize = 0;
    pub const SECCOMP_DATA_ARCH: usize = 4;
}

/// Architecture constants.
#[allow(dead_code)]
mod arch {
    pub const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
    pub const AUDIT_ARCH_AARCH64: u32 = 0xc00000b7;
}

/// Allowed syscalls for the default provider profile.
///
/// This is a minimal set of syscalls needed for a Rust provider that:
/// - Reads from /proc and /sys (filesystem read-only)
/// - Communicates over Unix domain sockets
/// - Uses standard library (alloc, threads, etc.)
const DEFAULT_ALLOWED_SYSCALLS: &[i64] = &[
    // Process/thread management
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_getppid,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_futex,
    libc::SYS_set_tid_address,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_sched_yield,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    // Memory management
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_brk,
    // File operations (read-only focus)
    libc::SYS_openat,
    libc::SYS_close,
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_lseek,
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_access,
    libc::SYS_faccessat,
    libc::SYS_getdents64,
    libc::SYS_readlinkat,
    libc::SYS_fcntl,
    libc::SYS_ioctl,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    // Socket operations (Unix domain sockets)
    libc::SYS_socket,
    libc::SYS_connect,
    libc::SYS_accept4,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_shutdown,
    libc::SYS_socketpair,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    // Filesystem metadata
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    // Time
    libc::SYS_clock_gettime,
    libc::SYS_gettimeofday,
    libc::SYS_time,
    // Process info
    libc::SYS_getuid,
    libc::SYS_getgid,
    libc::SYS_geteuid,
    libc::SYS_getegid,
    libc::SYS_prlimit64,
    // Random
    libc::SYS_getrandom,
    // Thread-local storage
    libc::SYS_arch_prctl,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    // Rseq (restartable sequences)
    libc::SYS_rseq,
    // Eventfd (for notifications)
    libc::SYS_eventfd2,
    // Timerfd
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    // Signal fd
    libc::SYS_signalfd4,
    // Inotify (for filesystem events)
    libc::SYS_inotify_init1,
    libc::SYS_inotify_add_watch,
    libc::SYS_inotify_rm_watch,
];

/// Build the default seccomp filter.
fn build_default_filter() -> Vec<seccomp_sys::sock_filter> {
    use bpf::*;
    use seccomp_sys::*;

    let mut filter = Vec::new();

    // Load architecture
    filter.push(BPF_STMT!(
        BPF_LD | BPF_W | BPF_ABS,
        SECCOMP_DATA_ARCH as u32
    ));

    // Check for x86_64
    #[cfg(target_arch = "x86_64")]
    {
        filter.push(BPF_JUMP!(
            BPF_JMP | BPF_JEQ | BPF_K,
            arch::AUDIT_ARCH_X86_64,
            1,
            0
        ));
        filter.push(BPF_STMT!(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    // Check for aarch64
    #[cfg(target_arch = "aarch64")]
    {
        filter.push(BPF_JUMP!(
            BPF_JMP | BPF_JEQ | BPF_K,
            arch::AUDIT_ARCH_AARCH64,
            1,
            0
        ));
        filter.push(BPF_STMT!(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    // Load syscall number
    filter.push(BPF_STMT!(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR as u32));

    // For each allowed syscall, add a check
    for (i, &syscall) in DEFAULT_ALLOWED_SYSCALLS.iter().enumerate() {
        let is_last = i == DEFAULT_ALLOWED_SYSCALLS.len() - 1;
        filter.push(BPF_JUMP!(
            BPF_JMP | BPF_JEQ | BPF_K,
            syscall as u32,
            0,
            if is_last { 1 } else { 0 }
        ));
        filter.push(BPF_STMT!(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    // Default: kill process
    filter.push(BPF_STMT!(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    filter
}

/// Apply the default seccomp filter.
pub fn apply_default_filter(profile: Option<&str>) -> Result<(), SeccompError> {
    let filter = match profile {
        Some("default") | None => build_default_filter(),
        Some(name) => {
            return Err(SeccompError::InvalidFilter(format!(
                "unknown seccomp profile: {}",
                name
            )));
        }
    };

    let prog = seccomp_sys::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // Load the filter
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            seccomp_sys::SECCOMP_SET_MODE_FILTER,
            seccomp_sys::SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const _,
        )
    };

    if ret < 0 {
        return Err(SeccompError::LoadFilter(std::io::Error::last_os_error()));
    }

    Ok(())
}

/// Check if seccomp is available on the current kernel.
pub fn is_seccomp_available() -> bool {
    // Try to check if SECCOMP_GET_ACTION_AVAIL works
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            seccomp_sys::SECCOMP_GET_ACTION_AVAIL,
            0,
            seccomp_sys::SECCOMP_RET_ALLOW,
        )
    };
    ret >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_default_filter() {
        let filter = build_default_filter();
        assert!(!filter.is_empty());
        // Should have architecture check, syscall checks, and default deny
        assert!(filter.len() > DEFAULT_ALLOWED_SYSCALLS.len());
    }

    #[test]
    fn test_is_seccomp_available() {
        // Just verify it runs
        let _ = is_seccomp_available();
    }
}
