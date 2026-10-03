//! `system.info` provider.
//!
//! Reads a fixed, non-sensitive set of system facts from well-known `/proc` and
//! `/sys` files. It never accepts a caller-supplied path and never performs an
//! arbitrary filesystem read, so it cannot be turned into a generic file-read
//! primitive.
//!
//! Sources:
//! - `/proc/sys/kernel/hostname`
//! - `/proc/sys/kernel/osrelease`
//! - `/proc/sys/kernel/version`
//! - `/proc/sys/kernel/arch`
//! - `/proc/uptime`
//! - `/proc/meminfo`
//! - `/proc/cpuinfo`
//! - `/sys/devices/system/cpu/online`

use std::fs;
use std::io;
use std::path::Path;

use serde::Serialize;

/// CPU facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CpuInfo {
    /// Human-readable CPU model, when the platform reports one.
    pub model: Option<String>,
    /// Number of online logical CPUs.
    pub logical_cores: usize,
}

/// Memory facts, in kibibytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemoryInfo {
    /// Total usable RAM.
    pub total_kb: u64,
    /// Free RAM.
    pub free_kb: u64,
    /// Memory available for new workloads (kernel estimate).
    pub available_kb: u64,
}

/// The `system.info` result payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SystemInfo {
    /// System hostname.
    pub hostname: String,
    /// Kernel release (for example `6.18.40.1-microsoft-standard-WSL2`).
    pub kernel_release: String,
    /// Kernel build/version string.
    pub kernel_version: String,
    /// Machine architecture (for example `x86_64`).
    pub architecture: String,
    /// CPU information.
    pub cpu: CpuInfo,
    /// Memory information.
    pub memory: MemoryInfo,
    /// System uptime in seconds.
    pub uptime_seconds: f64,
}

/// Read and parse all `system.info` fields from the real system.
///
/// Returns an error only when a required source is unreadable or malformed;
/// optional fields (such as the CPU model) degrade gracefully.
pub fn collect() -> io::Result<SystemInfo> {
    let hostname = read_trimmed(Path::new("/proc/sys/kernel/hostname"))?;
    let kernel_release = read_trimmed(Path::new("/proc/sys/kernel/osrelease"))?;
    let kernel_version = read_trimmed(Path::new("/proc/sys/kernel/version"))?;
    let architecture = read_trimmed(Path::new("/proc/sys/kernel/arch"))?;

    let uptime_raw = read_trimmed(Path::new("/proc/uptime"))?;
    let uptime_seconds = parse_uptime(&uptime_raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc/uptime"))?;

    let meminfo = read_to_string(Path::new("/proc/meminfo"))?;
    let memory = parse_meminfo(&meminfo)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc/meminfo"))?;

    let cpuinfo = read_to_string(Path::new("/proc/cpuinfo")).unwrap_or_default();
    let online = read_trimmed(Path::new("/sys/devices/system/cpu/online")).unwrap_or_default();
    let logical_cores = parse_cpu_count(&online)
        .or_else(|| count_cpuinfo_processors(&cpuinfo))
        .unwrap_or(1);

    Ok(SystemInfo {
        hostname,
        kernel_release,
        kernel_version,
        architecture,
        cpu: CpuInfo {
            model: parse_cpuinfo_model(&cpuinfo),
            logical_cores,
        },
        memory,
        uptime_seconds,
    })
}

fn read_trimmed(path: &Path) -> io::Result<String> {
    Ok(read_to_string(path)?.trim().to_string())
}

fn read_to_string(path: &Path) -> io::Result<String> {
    fs::read_to_string(path)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to read {}: {e}", path.display())))
}

/// Parse the first value of `/proc/uptime` (seconds since boot).
fn parse_uptime(raw: &str) -> Option<f64> {
    raw.split_whitespace().next()?.parse::<f64>().ok()
}

/// Parse `MemTotal`, `MemFree`, and `MemAvailable` from `/proc/meminfo`.
fn parse_meminfo(raw: &str) -> Option<MemoryInfo> {
    let mut total = None;
    let mut free = None;
    let mut available = None;
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        match key {
            "MemTotal:" => total = parse_meminfo_value(parts.next()),
            "MemFree:" => free = parse_meminfo_value(parts.next()),
            "MemAvailable:" => available = parse_meminfo_value(parts.next()),
            _ => {}
        }
    }
    match (total, free, available) {
        (Some(total_kb), Some(free_kb), Some(available_kb)) => Some(MemoryInfo {
            total_kb,
            free_kb,
            available_kb,
        }),
        _ => None,
    }
}

fn parse_meminfo_value(value: Option<&str>) -> Option<u64> {
    value.and_then(|v| v.parse::<u64>().ok())
}

/// Parse the CPU model name from `/proc/cpuinfo`.
fn parse_cpuinfo_model(raw: &str) -> Option<String> {
    for line in raw.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == "model name" {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Count `processor` entries in `/proc/cpuinfo` as a fallback.
fn count_cpuinfo_processors(raw: &str) -> Option<usize> {
    let count = raw
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.trim() == "processor")
        .count();
    if count == 0 {
        None
    } else {
        Some(count)
    }
}

/// Convert a CPU list such as `0-15` or `0-3,5` into a count.
fn parse_cpu_count(list: &str) -> Option<usize> {
    let mut count = 0usize;
    for part in list.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        match part.split_once('-') {
            Some((start, end)) => {
                let start: usize = start.parse().ok()?;
                let end: usize = end.parse().ok()?;
                if end < start {
                    return None;
                }
                count += end - start + 1;
            }
            None => {
                part.parse::<usize>().ok()?;
                count += 1;
            }
        }
    }
    if count == 0 {
        None
    } else {
        Some(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uptime() {
        assert_eq!(parse_uptime("433.73 6871.98\n"), Some(433.73));
        assert_eq!(parse_uptime("0.00 0.00"), Some(0.0));
        assert_eq!(parse_uptime("garbage"), None);
        assert_eq!(parse_uptime(""), None);
    }

    #[test]
    fn parses_meminfo() {
        let sample = "MemTotal:        7791200 kB\nMemFree:         6682716 kB\nMemAvailable:    7285092 kB\nBuffers: 9908 kB\n";
        let mem = parse_meminfo(sample).expect("parses");
        assert_eq!(mem.total_kb, 7_791_200);
        assert_eq!(mem.free_kb, 6_682_716);
        assert_eq!(mem.available_kb, 7_285_092);
    }

    #[test]
    fn meminfo_missing_available_is_none() {
        let sample = "MemTotal: 100 kB\nMemFree: 50 kB\n";
        assert!(parse_meminfo(sample).is_none());
    }

    #[test]
    fn parses_cpu_model() {
        let sample = "processor\t: 0\nmodel name\t: AMD Ryzen 7 5700U with Radeon Graphics\n";
        assert_eq!(
            parse_cpuinfo_model(sample).as_deref(),
            Some("AMD Ryzen 7 5700U with Radeon Graphics")
        );
        assert!(parse_cpuinfo_model("processor : 0\n").is_none());
    }

    #[test]
    fn counts_processors() {
        let sample = "processor : 0\nprocessor : 1\nprocessor : 2\n";
        assert_eq!(count_cpuinfo_processors(sample), Some(3));
        assert_eq!(count_cpuinfo_processors("model name : x\n"), None);
    }

    #[test]
    fn parses_cpu_counts() {
        assert_eq!(parse_cpu_count("0-15"), Some(16));
        assert_eq!(parse_cpu_count("0-3,5"), Some(5));
        assert_eq!(parse_cpu_count("0"), Some(1));
        assert_eq!(parse_cpu_count("3-1"), None);
        assert_eq!(parse_cpu_count("x-y"), None);
        assert_eq!(parse_cpu_count(""), None);
    }

    #[test]
    fn collect_reads_real_system() {
        let info = collect().expect("system.info collects on Linux");
        assert!(!info.hostname.is_empty());
        assert!(!info.kernel_release.is_empty());
        assert!(!info.architecture.is_empty());
        assert!(info.memory.total_kb > 0);
        assert!(info.cpu.logical_cores >= 1);
        assert!(info.uptime_seconds >= 0.0);
    }
}
