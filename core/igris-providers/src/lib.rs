//! Igris sandboxed provider binaries.
//!
//! This crate contains the provider binaries that run in sandboxed processes.
//! Each provider communicates with igrisd over a Unix domain socket using the
//! same protocol as the client.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[allow(unused_imports)]
use igris_proto::{
    error_code, read_frame, validate_request, write_response, ReadFrame, Request, Response,
    ALLOWED_SIGNALS, MAX_PID, MAX_POLL_EVENTS, MAX_REQUEST_SIZE, MAX_RESPONSE_SIZE,
    PROCESS_DEFAULT_MAX, PROCESS_MAX,
};

use igris_sandbox::init_provider_sandbox;

#[allow(dead_code)]
pub mod events_provider;
#[allow(dead_code)]
pub mod fs_provider;
#[allow(dead_code)]
pub mod process_provider;
#[allow(dead_code)]
pub mod system_provider;

/// Common provider server loop.
///
/// Listens on a Unix domain socket and handles requests using the provided handler.
pub fn run_provider_server<F>(
    socket_path: &Path,
    fs_root: &Path,
    writable_paths: &[PathBuf],
    handler: F,
) -> std::io::Result<()>
where
    F: Fn(&Request) -> Result<serde_json::Value, (String, String)> + Send + Sync + 'static,
{
    // Apply sandboxing
    init_provider_sandbox(fs_root, writable_paths, true, None)
        .map_err(|e| std::io::Error::other(format!("sandbox init failed: {}", e)))?;

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
