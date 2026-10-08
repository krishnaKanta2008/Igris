//! Igris sandbox CLI tool.
//!
//! This binary provides commands for testing and debugging the sandbox.

use std::env;
use std::path::PathBuf;

use igris_sandbox::{cgroup, namespace, seccomp, SandboxConfig, SandboxedProvider};

fn print_usage() {
    eprintln!("Usage: igris-sandbox <command> [args...]");
    eprintln!("Commands:");
    eprintln!("  namespace [fs_root] [network]  - Test namespace setup");
    eprintln!("  cgroup <name> [memory] [cpu_quota] [cpu_period] [pids] - Test cgroup operations");
    eprintln!("  seccomp [profile]              - Test seccomp filter");
    eprintln!("  spawn <binary> <fs_root> [memory] - Spawn a sandboxed provider");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "namespace" => {
            let fs_root = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp/igris-test"));
            let network = args.get(3).map(|s| s == "true").unwrap_or(false);

            println!("Testing namespace setup...");
            println!("fs_root: {:?}", fs_root);
            println!("network: {}", network);

            std::fs::create_dir_all(&fs_root)?;

            println!("Setting up user namespace...");
            namespace::setup_user_namespace()?;
            println!("User namespace OK");

            println!("Setting up PID namespace...");
            namespace::setup_pid_namespace()?;
            println!("PID namespace OK");

            if network {
                println!("Setting up network namespace...");
                namespace::setup_network_namespace()?;
                println!("Network namespace OK");
            }

            println!("Setting up IPC namespace...");
            namespace::setup_ipc_namespace()?;
            println!("IPC namespace OK");

            println!("Setting up UTS namespace...");
            namespace::setup_uts_namespace()?;
            println!("UTS namespace OK");

            println!("Setting up mount namespace...");
            namespace::setup_mount_namespace(&fs_root, &[])?;
            println!("Mount namespace OK");

            println!("All namespace tests passed!");
        }
        "cgroup" => {
            if args.len() < 3 {
                print_usage();
                std::process::exit(1);
            }
            let name = &args[2];
            let memory = args.get(3).and_then(|s| s.parse().ok());
            let cpu_quota = args.get(4).and_then(|s| s.parse().ok());
            let cpu_period = args.get(5).and_then(|s| s.parse().ok());
            let pids = args.get(6).and_then(|s| s.parse().ok());

            println!("Testing cgroup operations...");
            println!("name: {}", name);

            let path = cgroup::create_cgroup(name)?;
            println!("Created cgroup at: {:?}", path);

            if let Some(mem) = memory {
                cgroup::set_memory_limit(&path, mem)?;
                println!("Set memory limit: {} bytes", mem);
            }
            if let Some(quota) = cpu_quota {
                let period = cpu_period.unwrap_or(100000);
                cgroup::set_cpu_limit(&path, quota, period)?;
                println!("Set CPU limit: quota={} period={}", quota, period);
            }
            if let Some(max) = pids {
                cgroup::set_pids_max(&path, max)?;
                println!("Set pids.max: {}", max);
            }

            cgroup::attach_current_process(&path)?;
            println!("Attached current process to cgroup");

            if let Ok(usage) = cgroup::get_memory_usage(&path) {
                println!("Memory usage: {} bytes", usage);
            }
            if let Ok(usage) = cgroup::get_cpu_usage(&path) {
                println!("CPU usage: {} us", usage);
            }

            cgroup::remove_cgroup(&path)?;
            println!("Removed cgroup");
        }
        "seccomp" => {
            let profile = args.get(3).map(|s| s.as_str()).unwrap_or("default");

            println!("Testing seccomp filter...");
            println!("profile: {}", profile);

            if !seccomp::is_seccomp_available() {
                eprintln!("Warning: seccomp not available on this kernel");
            } else {
                seccomp::apply_default_filter(Some(profile))?;
                println!("Seccomp filter applied successfully");
            }
        }
        "spawn" => {
            if args.len() < 4 {
                print_usage();
                std::process::exit(1);
            }
            let binary = &args[2];
            let fs_root = PathBuf::from(&args[3]);
            let memory = args.get(4).and_then(|s| s.parse().ok());

            println!("Spawning sandboxed provider...");
            println!("binary: {}", binary);
            println!("fs_root: {:?}", fs_root);

            std::fs::create_dir_all(&fs_root)?;

            let config = SandboxConfig {
                provider_binary: binary.to_string(),
                fs_root,
                memory_limit: memory,
                ..Default::default()
            };

            let mut provider = SandboxedProvider::spawn(config)?;
            println!("Provider spawned with PID: {}", provider.id());

            std::thread::sleep(std::time::Duration::from_secs(1));

            match provider.try_wait()? {
                Some(status) => println!("Provider exited: {:?}", status),
                None => {
                    println!("Provider still running, killing...");
                    provider.kill()?;
                    provider.wait()?;
                    println!("Provider terminated");
                }
            }
        }
        _ => {
            print_usage();
            std::process::exit(1);
        }
    }

    Ok(())
}
