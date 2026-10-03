//! `igrisctl` command-line client.
//!
//! Usage:
//!   igrisctl system.info [--json]
//!   igrisctl --version
//!   igrisctl --help

use std::process::ExitCode;

use igris_proto::OP_SYSTEM_INFO;
use igrisctl::{build_request, resolve_socket_path, send};

const USAGE: &str = "\
igrisctl - Igris core service client

USAGE:
    igrisctl system.info [--json]
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
