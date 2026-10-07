//! `igrisd` daemon entry point.

use std::process::ExitCode;
use std::sync::Arc;

use igris_permd::Policy;
use igrisd::config::Config;
use igrisd::server::Server;

fn main() -> ExitCode {
    let config = Config::from_env();
    let writes_enabled = !config.writable_paths.is_empty();
    let process_control_enabled = config.process_control_enabled;
    let events_enabled = config.events_enabled;
    let policy = Policy::milestone_six(writes_enabled, process_control_enabled, events_enabled);

    let server = match Server::bind(&config, policy) {
        Ok(server) => Arc::new(server),
        Err(e) => {
            eprintln!("igrisd: failed to start: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "igrisd {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        server.socket_path().display()
    );
    println!("igrisd audit log: {}", config.audit_log_path.display());
    println!("igrisd fs root: {}", config.fs_root.display());

    if let Err(e) = server.run() {
        eprintln!("igrisd: server error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
