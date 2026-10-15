//! Process provider binary.
//!
//! Handles process.list, process.stat, process.children, proc.signal operations
//! within a sandboxed environment.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use igris_proto::{
    error_code, read_frame, validate_request, write_response, ReadFrame, Request, Response,
    MAX_REQUEST_SIZE, MAX_RESPONSE_SIZE,
};

use igris_sandbox::init_provider_sandbox;

fn run_provider_server<F>(
    socket_path: &Path,
    fs_root: &Path,
    writable_paths: &[PathBuf],
    test_mode: bool,
    handler: F,
) -> std::io::Result<()>
where
    F: Fn(&Request) -> Result<serde_json::Value, (String, String)> + Send + Sync + 'static,
{
    // Apply sandboxing unless in test mode
    if !test_mode {
        // Process provider runs without PID namespace to see host PIDs for process management
        init_provider_sandbox(fs_root, writable_paths, true, false, None)
            .map_err(|e| std::io::Error::other(format!("sandbox init failed: {}", e)))?;
    }

    // Bind socket
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    let handler = Arc::new(handler);

    // Handle connections
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let handler = Arc::clone(&handler);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(&mut stream, &handler) {
                        eprintln!("provider connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("provider accept error: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_connection<F>(
    stream: &mut std::os::unix::net::UnixStream,
    handler: &Arc<F>,
) -> std::io::Result<()>
where
    F: Fn(&Request) -> Result<serde_json::Value, (String, String)> + Send + Sync,
{
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    loop {
        let frame = match read_frame(stream, MAX_REQUEST_SIZE) {
            Ok(frame) => frame,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        match frame {
            ReadFrame::Closed => return Ok(()),
            ReadFrame::TooLarge { declared } => {
                let response = Response::error(
                    None,
                    igris_proto::error_code::TOO_LARGE,
                    format!(
                        "request declared {} bytes, exceeding the {}-byte maximum",
                        declared, MAX_REQUEST_SIZE
                    ),
                );
                let _ = write_response(stream, &response, MAX_RESPONSE_SIZE);
                return Ok(());
            }
            ReadFrame::Received(bytes) => {
                let request: Request = match serde_json::from_slice(&bytes) {
                    Ok(req) => req,
                    Err(e) => {
                        let response = Response::error(
                            None,
                            igris_proto::error_code::BAD_REQUEST,
                            format!("malformed request: {}", e),
                        );
                        let _ = write_response(stream, &response, MAX_RESPONSE_SIZE);
                        continue;
                    }
                };

                let id_for_error = if request.id.is_empty() {
                    None
                } else {
                    Some(request.id.clone())
                };

                if let Err(e) = validate_request(&request) {
                    let response = Response::error(id_for_error, e.code, e.message);
                    let _ = write_response(stream, &response, MAX_RESPONSE_SIZE);
                    continue;
                }

                let response = match handler(&request) {
                    Ok(result) => Response::success(request.id, result),
                    Err((code, message)) => Response::error(Some(request.id), &code, message),
                };

                if write_response(stream, &response, MAX_RESPONSE_SIZE).is_err() {
                    return Ok(());
                }
            }
        }
    }
}

mod process_ops;

fn main() {
    use std::path::PathBuf;

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: igris-process-provider <socket_path> [fs_root] [writable_paths...]");
        std::process::exit(1);
    }
    let socket_path = PathBuf::from(&args[1]);
    let fs_root = PathBuf::from("/"); // Process provider doesn't need fs_root
    let writable_paths: Vec<PathBuf> = vec![];

    let mut test_mode = false;

    // Parse arguments: socket_path, [--test-mode]
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--test-mode" {
            test_mode = true;
        }
        i += 1;
    }

    run_provider_server(
        &socket_path,
        &fs_root,
        &writable_paths,
        test_mode,
        move |req| match req.op.as_str() {
            igris_proto::OP_PROCESS_LIST => {
                let result = process_ops::list(&req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_PROCESS_STAT => {
                let result = process_ops::stat(&req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_PROCESS_CHILDREN => {
                let result = process_ops::children(&req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_PROC_SIGNAL => {
                let result = process_ops::signal(&req.params)
                    .map_err(|e| (e.code.to_string(), e.message.to_string()))?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            _ => Err((
                error_code::UNKNOWN_OPERATION.to_string(),
                "unsupported operation".to_string(),
            )),
        },
    )
    .expect("provider server failed");
}
