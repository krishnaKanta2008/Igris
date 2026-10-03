//! `igrisctl` command-line client.
//!
//! Usage:
//!   igrisctl system.info [--json]
//!   igrisctl fs.list --path PATH [--max-entries N] [--json]
//!   igrisctl fs.stat --path PATH [--json]
//!   igrisctl fs.read --path PATH [--max-bytes N] [--json]
//!   igrisctl --version
//!   igrisctl --help

use std::process::ExitCode;

use igris_proto::OP_SYSTEM_INFO;
use igrisctl::{build_request, resolve_socket_path, send};

const USAGE: &str = "\
igrisctl - Igris core service client

USAGE:
    igrisctl system.info [--json]
    igrisctl fs.list --path PATH [--max-entries N] [--json]
    igrisctl fs.stat --path PATH [--json]
    igrisctl fs.read --path PATH [--max-bytes N] [--json]
    igrisctl --version
    igrisctl --help

OPTIONS:
    --json        Print the raw JSON response instead of a summary.
    -h, --help    Show this help.

ENVIRONMENT:
    IGRIS_SOCKET_PATH   Daemon socket path (defaults to the shared location).
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    match args[0].as_str() {
        "-h" | "--help" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        "-V" | "--version" => {
            println!("igrisctl {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        OP_SYSTEM_INFO => {
            let json = args.iter().any(|a| a == "--json");
            run_system_info(json)
        }
        op @ ("fs.list" | "fs.stat" | "fs.read") => run_fs(op, &args[1..]),
        other => {
            eprintln!("igrisctl: unknown command {other:?}");
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_system_info(json: bool) -> ExitCode {
    let socket_path = resolve_socket_path();
    let request = build_request(OP_SYSTEM_INFO, serde_json::json!({}));

    let response = match send(&socket_path, &request) {
        Ok(response) => response,
        Err(e) => {
            eprintln!(
                "igrisctl: could not reach daemon at {}: {e}",
                socket_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    if json {
        match serde_json::to_string_pretty(&response) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("igrisctl: failed to render response: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else if response.ok {
        print_human(&response);
    } else {
        let code = response
            .error
            .as_ref()
            .map(|e| e.code.as_str())
            .unwrap_or("UNKNOWN");
        let message = response
            .error
            .as_ref()
            .map(|e| e.message.as_str())
            .unwrap_or("no error detail");
        eprintln!("igrisctl: request failed [{code}]: {message}");
        return ExitCode::FAILURE;
    }

    if response.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Parse `--path`, optional numeric limit, and `--json` from trailing args.
fn parse_fs_args(args: &[String]) -> Result<(String, Option<u64>, &str, bool), String> {
    let mut path = None;
    let mut numeric: Option<u64> = None;
    let mut numeric_key: Option<&str> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--path" => {
                i += 1;
                path = args.get(i).cloned();
            }
            "--max-entries" | "--max-bytes" => {
                numeric_key = Some(if args[i] == "--max-entries" {
                    "max_entries"
                } else {
                    "max_bytes"
                });
                i += 1;
                numeric = args.get(i).and_then(|v| v.parse::<u64>().ok());
                if numeric.is_none() {
                    return Err(format!("{} requires a numeric value", args[i - 1]));
                }
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
        i += 1;
    }
    let Some(path) = path else {
        return Err("missing required --path".to_string());
    };
    let numeric_key = numeric_key.unwrap_or("");
    Ok((path, numeric, numeric_key, json))
}

fn run_fs(op: &str, args: &[String]) -> ExitCode {
    let (path, numeric, numeric_key, json) = match parse_fs_args(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("igrisctl: {e}");
            return ExitCode::from(2);
        }
    };

    let mut params = serde_json::json!({ "path": path });
    if let Some(value) = numeric {
        params[numeric_key] = serde_json::json!(value);
    }

    let socket_path = resolve_socket_path();
    let request = build_request(op, params);
    let response = match send(&socket_path, &request) {
        Ok(response) => response,
        Err(e) => {
            eprintln!(
                "igrisctl: could not reach daemon at {}: {e}",
                socket_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    if json {
        match serde_json::to_string_pretty(&response) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("igrisctl: failed to render response: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else if response.ok {
        print_fs_human(op, &response);
    } else {
        let code = response
            .error
            .as_ref()
            .map(|e| e.code.as_str())
            .unwrap_or("UNKNOWN");
        let message = response
            .error
            .as_ref()
            .map(|e| e.message.as_str())
            .unwrap_or("no error detail");
        eprintln!("igrisctl: request failed [{code}]: {message}");
        return ExitCode::FAILURE;
    }

    if response.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_fs_human(op: &str, response: &igris_proto::Response) {
    let Some(result) = response.result.as_ref() else {
        println!("(empty response)");
        return;
    };
    match op {
        "fs.list" => {
            println!("path      : {}", field(result, "path"));
            println!("truncated : {}", field(result, "truncated"));
            if let Some(entries) = result["entries"].as_array() {
                for entry in entries {
                    let name = entry["name"].as_str().unwrap_or("?");
                    let kind = entry["kind"].as_str().unwrap_or("?");
                    match entry["size_bytes"].as_u64() {
                        Some(size) => println!("{kind:<10} {size:>12}  {name}"),
                        None => println!("{kind:<10} {:>12}  {name}", "-"),
                    }
                }
            }
        }
        "fs.stat" => {
            println!("path     : {}", field(result, "path"));
            println!("kind     : {}", field(result, "kind"));
            println!("size     : {} bytes", field(result, "size_bytes"));
            println!("mode     : {:o}", result["mode"].as_u64().unwrap_or(0));
            println!(
                "uid/gid  : {}/{}",
                field(result, "uid"),
                field(result, "gid")
            );
            println!("modified : {}", field(result, "modified_unix"));
        }
        "fs.read" => {
            println!("path     : {}", field(result, "path"));
            println!("size     : {} bytes", field(result, "size_bytes"));
            println!("encoding : {}", field(result, "encoding"));
            println!("truncated: {}", field(result, "truncated"));
            let data = field(result, "data");
            println!("data     : {}...", &data[..data.len().min(64)]);
        }
        _ => println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        ),
    }
}

fn print_human(response: &igris_proto::Response) {
    let Some(result) = response.result.as_ref() else {
        println!("(empty response)");
        return;
    };
    println!("hostname        : {}", field(result, "hostname"));
    println!("kernel release  : {}", field(result, "kernel_release"));
    println!("kernel version  : {}", field(result, "kernel_version"));
    println!("architecture    : {}", field(result, "architecture"));
    println!("cpu model       : {}", nested(result, &["cpu", "model"]));
    println!(
        "cpu logical     : {}",
        nested(result, &["cpu", "logical_cores"])
    );
    println!(
        "memory total    : {} kB",
        nested(result, &["memory", "total_kb"])
    );
    println!(
        "memory free     : {} kB",
        nested(result, &["memory", "free_kb"])
    );
    println!(
        "memory available: {} kB",
        nested(result, &["memory", "available_kb"])
    );
    println!("uptime          : {} s", field(result, "uptime_seconds"));
}

fn field(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .map(render)
        .unwrap_or_else(|| "(missing)".to_string())
}

fn nested(value: &serde_json::Value, path: &[&str]) -> String {
    let mut current = value;
    for key in path {
        match current.get(key) {
            Some(next) => current = next,
            None => return "(missing)".to_string(),
        }
    }
    render(current)
}

fn render(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
