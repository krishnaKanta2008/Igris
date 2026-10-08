//! Events provider binary.
//!
//! Handles events.watch, events.poll, events.unwatch operations
//! within a sandboxed environment using inotify.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use igris_proto::{
    error_code, read_frame, validate_request, write_response, Event, PollResult, ReadFrame,
    Request, Response, WatchResult, MAX_EVENT_WATCHES, MAX_POLL_EVENTS, MAX_QUEUED_EVENTS,
    MAX_REQUEST_SIZE, MAX_RESPONSE_SIZE,
};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};

use igris_sandbox::init_provider_sandbox;

const MAX_EVENTS_PER_WATCH: usize = MAX_QUEUED_EVENTS / MAX_EVENT_WATCHES;

fn run_provider_server<F>(
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

/// Resolve path within filesystem root (copied from fs_provider).
fn resolve_within(fs_root: &Path, requested: &str) -> Result<PathBuf, ProviderError> {
    if requested.contains('\0') {
        return Err(ProviderError::InvalidPath);
    }
    let candidate = Path::new(requested);
    if !candidate.is_absolute() {
        return Err(ProviderError::InvalidPath);
    }
    let resolved = candidate
        .canonicalize()
        .map_err(|_| ProviderError::Internal)?;
    let root = fs_root
        .canonicalize()
        .map_err(|_| ProviderError::Internal)?;
    if resolved.starts_with(&root) {
        Ok(resolved)
    } else {
        Err(ProviderError::PathOutsideRoot)
    }
}

#[allow(dead_code)]
struct Watch {
    watch_id: u64,
    owner: u64,
    path: PathBuf,
    wd: WatchDescriptor,
    events: Vec<Event>,
}

impl Watch {
    fn new(watch_id: u64, owner: u64, path: PathBuf, wd: WatchDescriptor) -> Self {
        Self {
            watch_id,
            owner,
            path,
            wd,
            events: Vec::with_capacity(MAX_EVENTS_PER_WATCH),
        }
    }
    fn enqueue(
        &mut self,
        name: String,
        kind: Option<String>,
        filename: Option<&std::ffi::OsStr>,
    ) -> bool {
        if self.events.len() >= MAX_EVENTS_PER_WATCH {
            self.events.remove(0);
        }
        let full_path = filename
            .map(|n| self.path.join(n).display().to_string())
            .unwrap_or_else(|| self.path.display().to_string());
        let event = Event {
            name,
            path: full_path,
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            kind,
        };
        self.events.push(event);
        true
    }
    fn drain_events(&mut self, max: usize) -> Vec<Event> {
        let take = max.min(self.events.len());
        self.events.drain(0..take).collect()
    }
    fn queued_count(&self) -> usize {
        self.events.len()
    }
}

#[allow(dead_code)]
struct WatchRegistry {
    watches: HashMap<u64, Watch>,
    next_watch_id: u64,
    watches_per_connection: HashMap<u64, u32>,
    wd_refcounts: HashMap<WatchDescriptor, u32>,
    total_queued_events: usize,
}

impl WatchRegistry {
    fn new() -> Self {
        Self {
            watches: HashMap::new(),
            next_watch_id: 1,
            watches_per_connection: HashMap::new(),
            wd_refcounts: HashMap::new(),
            total_queued_events: 0,
        }
    }
    fn allocate_id(&mut self) -> Option<u64> {
        (1..=MAX_EVENT_WATCHES as u64).find(|id| !self.watches.contains_key(id))
    }
    fn create_watch(
        &mut self,
        owner: u64,
        path: PathBuf,
        wd: WatchDescriptor,
    ) -> Result<u64, ProviderError> {
        if self.watches.len() >= MAX_EVENT_WATCHES {
            return Err(ProviderError::MaxWatches);
        }
        let watch_id = self.allocate_id().ok_or(ProviderError::MaxWatches)?;
        self.watches
            .insert(watch_id, Watch::new(watch_id, owner, path, wd.clone()));
        *self.watches_per_connection.entry(owner).or_insert(0) += 1;
        *self.wd_refcounts.entry(wd).or_insert(0) += 1;
        Ok(watch_id)
    }
    #[allow(dead_code)]
    fn increment_wd_refcount(&mut self, wd: WatchDescriptor) {
        *self.wd_refcounts.entry(wd).or_insert(0) += 1;
    }
    fn decrement_wd_refcount(&mut self, wd: &WatchDescriptor) -> bool {
        if let Some(count) = self.wd_refcounts.get_mut(wd) {
            *count -= 1;
            if *count == 0 {
                self.wd_refcounts.remove(wd);
                return true;
            }
        }
        false
    }
    fn remove_watch(&mut self, owner: u64, watch_id: u64) -> Result<bool, ProviderError> {
        let watch = self
            .watches
            .get(&watch_id)
            .ok_or(ProviderError::WatchNotFound)?;
        if watch.owner != owner {
            return Err(ProviderError::WatchNotFound);
        }
        let wd = watch.wd.clone();
        self.total_queued_events = self
            .total_queued_events
            .saturating_sub(watch.queued_count());
        self.watches.remove(&watch_id);
        if let Some(count) = self.watches_per_connection.get_mut(&owner) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.watches_per_connection.remove(&owner);
            }
        }
        Ok(self.decrement_wd_refcount(&wd))
    }
    fn poll_events(
        &mut self,
        owner: u64,
        watch_id: u64,
        max: usize,
    ) -> Result<Vec<Event>, ProviderError> {
        let max = max.clamp(1, MAX_POLL_EVENTS);
        let watch = self
            .watches
            .get(&watch_id)
            .ok_or(ProviderError::WatchNotFound)?;
        if watch.owner != owner {
            return Err(ProviderError::WatchNotFound);
        }
        let events = self
            .watches
            .get_mut(&watch_id)
            .ok_or(ProviderError::WatchNotFound)?
            .drain_events(max);
        self.total_queued_events = self.total_queued_events.saturating_sub(events.len());
        Ok(events)
    }
    #[allow(dead_code)]
    fn cleanup_connection(&mut self, owner: u64) {
        let watch_ids: Vec<u64> = self
            .watches
            .iter()
            .filter(|(_, w)| w.owner == owner)
            .map(|(id, _)| *id)
            .collect();
        for id in watch_ids {
            let _ = self.remove_watch(owner, id);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum ProviderError {
    MaxWatches,
    WatchNotFound,
    InvalidPath,
    PathOutsideRoot,
    Internal,
    QueueOverflow,
    WatchInvalidated,
}

impl From<ProviderError> for (String, String) {
    fn from(e: ProviderError) -> Self {
        match e {
            ProviderError::MaxWatches => (
                error_code::FS_ERROR.to_string(),
                "maximum event watches reached".to_string(),
            ),
            ProviderError::WatchNotFound => (
                error_code::NOT_FOUND.to_string(),
                "watch not found".to_string(),
            ),
            ProviderError::InvalidPath => (
                error_code::BAD_REQUEST.to_string(),
                "invalid path".to_string(),
            ),
            ProviderError::PathOutsideRoot => (
                error_code::BAD_REQUEST.to_string(),
                "path escapes filesystem boundary".to_string(),
            ),
            ProviderError::Internal => (
                error_code::FS_ERROR.to_string(),
                "filesystem error".to_string(),
            ),
            ProviderError::QueueOverflow => (
                error_code::QUEUE_OVERFLOW.to_string(),
                "event queue overflowed, events lost".to_string(),
            ),
            ProviderError::WatchInvalidated => (
                error_code::FS_ERROR.to_string(),
                "watch invalidated by kernel".to_string(),
            ),
        }
    }
}

struct InotifySource {
    inotify: Inotify,
    buffer: Vec<u8>,
}
impl InotifySource {
    fn new() -> Result<Self, std::io::Error> {
        Ok(Self {
            inotify: Inotify::init()?,
            buffer: vec![0u8; 8192],
        })
    }
    fn add_watch(
        &mut self,
        path: &PathBuf,
        mask: WatchMask,
    ) -> Result<WatchDescriptor, std::io::Error> {
        self.inotify.watches().add(path, mask)
    }
    fn remove_watch(&mut self, wd: WatchDescriptor) -> Result<(), std::io::Error> {
        self.inotify.watches().remove(wd)
    }
    fn read_events(&mut self) -> Result<Vec<inotify::Event<&std::ffi::OsStr>>, std::io::Error> {
        match self.inotify.read_events(&mut self.buffer) {
            Ok(events) => Ok(events.into_iter().collect()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

struct EventProvider {
    fs_root: PathBuf,
    registry: Mutex<WatchRegistry>,
    inotify_source: Mutex<InotifySource>,
}

impl EventProvider {
    fn new(fs_root: PathBuf) -> Self {
        Self {
            fs_root,
            registry: Mutex::new(WatchRegistry::new()),
            inotify_source: Mutex::new(InotifySource::new().expect("inotify init")),
        }
    }
    fn watch(&self, owner: u64, path: &str) -> Result<WatchResult, (String, String)> {
        let resolved =
            resolve_within(&self.fs_root, path).map_err(Into::<(String, String)>::into)?;
        let watch_path = if resolved.is_file() {
            resolved.parent().unwrap_or(&resolved).to_path_buf()
        } else {
            resolved.clone()
        };
        let mask = WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::MODIFY
            | WatchMask::MOVE
            | WatchMask::CLOSE_WRITE;
        let wd = {
            let mut inotify = self
                .inotify_source
                .lock()
                .map_err(|_| ProviderError::Internal)?;
            inotify
                .add_watch(&watch_path, mask)
                .map_err(|_| ProviderError::Internal)?
        };
        let watch_id = {
            let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
            registry.create_watch(owner, resolved, wd)?
        };
        Ok(WatchResult { watch_id })
    }
    fn poll(&self, owner: u64, watch_id: u64, max: usize) -> Result<PollResult, (String, String)> {
        self.read_pending_inotify_events()?;
        let events = {
            let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
            registry.poll_events(owner, watch_id, max)?
        };
        Ok(PollResult { events })
    }
    fn read_pending_inotify_events(&self) -> Result<(), (String, String)> {
        let mut inotify = self
            .inotify_source
            .lock()
            .map_err(|_| ProviderError::Internal)?;
        let events = inotify.read_events().map_err(|_| ProviderError::Internal)?;
        if events.is_empty() {
            return Ok(());
        }
        let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
        for event in events {
            let wd = event.wd;
            if let Some(watch) = registry.watches.values_mut().find(|w| w.wd == wd) {
                let mask = event.mask;
                if mask.contains(EventMask::Q_OVERFLOW) {
                    watch.enqueue("fs.overflow".into(), Some("overflow".into()), None);
                    continue;
                }
                if mask.contains(EventMask::IGNORED) {
                    registry.watches.retain(|_, w| w.wd != wd);
                    registry.wd_refcounts.remove(&wd);
                    continue;
                }
                if mask.contains(EventMask::DELETE_SELF) {
                    watch.enqueue("fs.delete".into(), Some("directory".into()), event.name);
                    registry.watches.retain(|_, w| w.wd != wd);
                    registry.wd_refcounts.remove(&wd);
                    continue;
                }
                if mask.contains(EventMask::MOVE_SELF) {
                    watch.enqueue("fs.move".into(), Some("directory".into()), event.name);
                    continue;
                }
                let filename = event.name;
                if mask.contains(EventMask::CREATE) {
                    watch.enqueue("fs.create".into(), Some("file".into()), filename);
                }
                if mask.contains(EventMask::DELETE) {
                    watch.enqueue("fs.delete".into(), Some("file".into()), filename);
                }
                if mask.contains(EventMask::MODIFY) {
                    watch.enqueue("fs.modify".into(), Some("file".into()), filename);
                }
                if mask.contains(EventMask::MOVED_TO) || mask.contains(EventMask::MOVED_FROM) {
                    watch.enqueue("fs.move".into(), Some("file".into()), filename);
                }
                if mask.contains(EventMask::CLOSE_WRITE) {
                    watch.enqueue("fs.modify".into(), Some("file".into()), filename);
                }
            }
        }
        Ok(())
    }
    fn unwatch(&self, owner: u64, watch_id: u64) -> Result<bool, (String, String)> {
        let (should_remove, wd) = {
            let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
            let watch = registry
                .watches
                .get(&watch_id)
                .ok_or(ProviderError::WatchNotFound)?;
            if watch.owner != owner {
                return Err(ProviderError::WatchNotFound.into());
            }
            let wd = watch.wd.clone();
            let should_remove = registry.remove_watch(owner, watch_id)?;
            (should_remove, wd)
        };
        if should_remove {
            let mut inotify = self
                .inotify_source
                .lock()
                .map_err(|_| ProviderError::Internal)?;
            inotify
                .remove_watch(wd)
                .map_err(|_| ProviderError::Internal)?;
        }
        Ok(true)
    }
    #[allow(dead_code)]
    fn cleanup_connection(&self, owner: u64) {
        let wds_to_remove = {
            let mut registry = match self.registry.lock() {
                Ok(r) => r,
                Err(_) => return,
            };
            let watch_ids: Vec<u64> = registry
                .watches
                .iter()
                .filter(|(_, w)| w.owner == owner)
                .map(|(id, _)| *id)
                .collect();
            let mut wds = Vec::new();
            for id in watch_ids {
                if let Some(watch) = registry.watches.get(&id) {
                    let wd = watch.wd.clone();
                    if let Ok(should_remove) = registry.remove_watch(owner, id) {
                        if should_remove {
                            wds.push(wd);
                        }
                    }
                }
            }
            wds
        };
        let mut inotify = match self.inotify_source.lock() {
            Ok(i) => i,
            Err(_) => return,
        };
        for wd in wds_to_remove {
            let should_remove = {
                let mut registry = match self.registry.lock() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                registry.decrement_wd_refcount(&wd)
            };
            if should_remove {
                let _ = inotify.remove_watch(wd);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: igris-events-provider <socket_path> <fs_root> [writable_paths...]");
        std::process::exit(1);
    }
    let socket_path = PathBuf::from(&args[1]);
    let fs_root = PathBuf::from(&args[2]);
    let writable_paths: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();

    let provider = EventProvider::new(fs_root.clone());

    run_provider_server(
        &socket_path,
        &fs_root,
        &writable_paths,
        move |req| match req.op.as_str() {
            igris_proto::OP_EVENTS_WATCH => {
                let path = req.params.get("path").and_then(|v| v.as_str()).ok_or((
                    error_code::BAD_REQUEST.to_string(),
                    "missing required `path`".to_string(),
                ))?;
                let result = provider.watch(req.id.parse().unwrap_or(0), path)?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_EVENTS_POLL => {
                let watch_id = req.params.get("watch_id").and_then(|v| v.as_u64()).ok_or((
                    error_code::BAD_REQUEST.to_string(),
                    "missing required `watch_id`".to_string(),
                ))?;
                let max = req
                    .params
                    .get("max")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(MAX_POLL_EVENTS);
                let result = provider.poll(req.id.parse().unwrap_or(0), watch_id, max)?;
                serde_json::to_value(result).map_err(|_| {
                    (
                        error_code::INTERNAL.to_string(),
                        "failed to encode".to_string(),
                    )
                })
            }
            igris_proto::OP_EVENTS_UNWATCH => {
                let watch_id = req.params.get("watch_id").and_then(|v| v.as_u64()).ok_or((
                    error_code::BAD_REQUEST.to_string(),
                    "missing required `watch_id`".to_string(),
                ))?;
                let result = provider.unwatch(req.id.parse().unwrap_or(0), watch_id)?;
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
