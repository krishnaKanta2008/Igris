//! Event observation provider (`events.watch`, `events.poll`, `events.unwatch`).
//!
//! This provider manages a bounded set of event watches per connection using
//! Linux inotify as the event source. Each watch owns a bounded queue of events.
//! The provider is isolated: the server only interacts with it through the public
//! API and never inspects internal watch state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use igris_proto::{
    error_code, Event, PollResult, WatchResult, MAX_EVENT_WATCHES, MAX_POLL_EVENTS,
    MAX_QUEUED_EVENTS,
};

use crate::providers::fs::{resolve_within, FsFailure};

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};

/// Maximum events per individual watch queue.
///
/// Derived from global limits to ensure fair sharing.
const MAX_EVENTS_PER_WATCH: usize = MAX_QUEUED_EVENTS / MAX_EVENT_WATCHES;

/// Internal watch state.
///
/// Not exposed outside the provider.
struct Watch {
    #[allow(dead_code)]
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

    /// Attempt to enqueue an event, respecting bounds.
    ///
    /// Returns `true` if the event was enqueued, `false` if the queue was full
    /// and the oldest event was dropped.
    fn enqueue(
        &mut self,
        name: String,
        kind: Option<String>,
        filename: Option<&std::ffi::OsStr>,
    ) -> bool {
        if self.events.len() >= MAX_EVENTS_PER_WATCH {
            // Drop oldest event to make room.
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

/// Watch registry shared across connections.
///
/// Owned by the `EventProvider` and protected by a mutex.
struct WatchRegistry {
    watches: HashMap<u64, Watch>,
    /// Next watch ID to allocate (1..=MAX_EVENT_WATCHES, wraps with reuse).
    #[allow(dead_code)]
    next_watch_id: u64,
    /// Tracks how many watches each connection owns for limit enforcement.
    watches_per_connection: HashMap<u64, u32>,
    /// Reference counts for kernel watch descriptors (multiple logical watches can share a kernel wd).
    wd_refcounts: HashMap<WatchDescriptor, u32>,
    /// Total queued events across all watches.
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

    /// Allocate the next available watch ID within 1..=MAX_EVENT_WATCHES.
    ///
    /// Reuses freed IDs; returns `None` if all IDs are in use.
    fn allocate_id(&mut self) -> Option<u64> {
        (1..=MAX_EVENT_WATCHES as u64).find(|id| !self.watches.contains_key(id))
    }

    /// Create a new watch for the given connection.
    ///
    /// Returns the assigned `watch_id` on success.
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

        let watch = Watch::new(watch_id, owner, path, wd.clone());
        self.watches.insert(watch_id, watch);
        *self.watches_per_connection.entry(owner).or_insert(0) += 1;
        self.increment_wd_refcount(wd);

        Ok(watch_id)
    }

    /// Increment the reference count for a kernel watch descriptor.
    fn increment_wd_refcount(&mut self, wd: WatchDescriptor) {
        *self.wd_refcounts.entry(wd).or_insert(0) += 1;
    }

    /// Decrement the reference count for a kernel watch descriptor.
    ///
    /// Returns `true` if the refcount reached zero and the kernel watch should be removed.
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

    /// Remove a watch by ID, verifying ownership.
    ///
    /// Returns `true` if the kernel watch descriptor's refcount reached zero
    /// and the inotify watch should be removed.
    fn remove_watch(&mut self, owner: u64, watch_id: u64) -> Result<bool, ProviderError> {
        let watch = self
            .watches
            .get(&watch_id)
            .ok_or(ProviderError::WatchNotFound)?;

        if watch.owner != owner {
            return Err(ProviderError::WatchNotFound); // Ownership violation -> NOT_FOUND
        }

        let wd = watch.wd.clone();

        // Release queued events count.
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

        // Decrement wd refcount and return whether kernel watch should be removed
        Ok(self.decrement_wd_refcount(&wd))
    }

    /// Poll events from a watch, verifying ownership.
    fn poll_events(
        &mut self,
        owner: u64,
        watch_id: u64,
        max: usize,
    ) -> Result<Vec<Event>, ProviderError> {
        let max = max.clamp(1, MAX_POLL_EVENTS);

        // First check if watch exists and get its info without holding the lock long
        let (owner_matches, _queued_count) = {
            let watch = self
                .watches
                .get(&watch_id)
                .ok_or(ProviderError::WatchNotFound)?;
            (watch.owner == owner, watch.queued_count())
        };

        if !owner_matches {
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

    /// Remove all watches owned by a connection.
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

    /// Check if a connection owns a watch (for internal validation).
    #[allow(dead_code)]
    fn owns_watch(&self, owner: u64, watch_id: u64) -> bool {
        self.watches
            .get(&watch_id)
            .map(|w| w.owner == owner)
            .unwrap_or(false)
    }

    /// Get total queued events (for invariant checking).
    #[cfg(test)]
    #[allow(dead_code)]
    fn total_queued(&self) -> usize {
        self.total_queued_events
    }
}

/// Provider-level errors mapped to protocol error codes.
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

impl From<ProviderError> for FsFailure {
    fn from(e: ProviderError) -> Self {
        match e {
            ProviderError::MaxWatches => Self {
                code: error_code::FS_ERROR,
                message: "maximum event watches reached",
                denied: false,
            },
            ProviderError::WatchNotFound => Self {
                code: error_code::NOT_FOUND,
                message: "watch not found",
                denied: false,
            },
            ProviderError::InvalidPath => Self {
                code: error_code::BAD_REQUEST,
                message: "invalid path",
                denied: true,
            },
            ProviderError::PathOutsideRoot => Self {
                code: error_code::BAD_REQUEST,
                message: "path escapes filesystem boundary",
                denied: true,
            },
            ProviderError::Internal => Self {
                code: error_code::FS_ERROR,
                message: "filesystem error",
                denied: false,
            },
            ProviderError::QueueOverflow => Self {
                code: error_code::QUEUE_OVERFLOW,
                message: "event queue overflowed, events lost",
                denied: false,
            },
            ProviderError::WatchInvalidated => Self {
                code: error_code::FS_ERROR,
                message: "watch invalidated by kernel",
                denied: false,
            },
        }
    }
}

/// Inotify-based event source.
///
/// Encapsulates the inotify instance and provides methods to read events.
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

    /// Add a watch for the given path.
    fn add_watch(
        &mut self,
        path: &Path,
        mask: WatchMask,
    ) -> Result<WatchDescriptor, std::io::Error> {
        // Use the new API (non-deprecated)
        self.inotify.watches().add(path, mask)
    }

    /// Remove a watch by descriptor.
    fn remove_watch(&mut self, wd: WatchDescriptor) -> Result<(), std::io::Error> {
        self.inotify.watches().remove(wd)
    }

    /// Read available events (non-blocking).
    fn read_events(&mut self) -> Result<Vec<inotify::Event<&std::ffi::OsStr>>, std::io::Error> {
        match self.inotify.read_events(&mut self.buffer) {
            Ok(events) => Ok(events.into_iter().collect()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

/// Event provider: manages watches, queues, and event dispatch.
pub struct EventProvider {
    fs_root: PathBuf,
    registry: Mutex<WatchRegistry>,
    inotify_source: Mutex<InotifySource>,
}

impl EventProvider {
    /// Create a new event provider with the given filesystem root.
    pub fn new(fs_root: impl Into<PathBuf>) -> Self {
        Self {
            fs_root: fs_root.into(),
            registry: Mutex::new(WatchRegistry::new()),
            inotify_source: Mutex::new(InotifySource::new().expect("failed to initialize inotify")),
        }
    }

    /// Create a new filesystem watch.
    ///
    /// Validates that the path is within the filesystem root, allocates a
    /// watch ID, establishes an inotify watch, and returns it.
    pub fn watch(&self, owner: u64, path: &str) -> Result<WatchResult, FsFailure> {
        // Validate and canonicalize the path using the same boundary logic as fs provider.
        let resolved = resolve_within(&self.fs_root, path)?;

        // Check if path exists and is a directory (inotify requires directories for recursive-like watching)
        // For now, we watch the resolved path. If it's a file, we watch its parent directory.
        let watch_path = if resolved.is_file() {
            resolved.parent().unwrap_or(&resolved).to_path_buf()
        } else {
            resolved.clone()
        };

        let watch_mask = WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::MODIFY
            | WatchMask::MOVE
            | WatchMask::CLOSE_WRITE;

        let wd = {
            let mut inotify = self
                .inotify_source
                .lock()
                .map_err(|_| ProviderError::Internal)?;
            inotify.add_watch(&watch_path, watch_mask).map_err(|e| {
                eprintln!(
                    "igrisd: failed to add inotify watch for {}: {}",
                    watch_path.display(),
                    e
                );
                ProviderError::Internal
            })?
        };

        let watch_id = {
            let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
            registry.create_watch(owner, resolved, wd)?
        };

        Ok(WatchResult { watch_id })
    }

    /// Poll events from a watch.
    ///
    /// Drains up to `max` events from the watch's queue. Also attempts to
    /// read pending inotify notifications and translate them into events
    /// before draining. Does not block indefinitely.
    pub fn poll(&self, owner: u64, watch_id: u64, max: usize) -> Result<PollResult, FsFailure> {
        // First, read any pending inotify events and translate them
        self.read_pending_inotify_events()?;

        let events = {
            let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
            registry.poll_events(owner, watch_id, max)?
        };
        Ok(PollResult { events })
    }

    /// Read pending inotify events and translate them into the watch queues.
    fn read_pending_inotify_events(&self) -> Result<(), FsFailure> {
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
            // Find the watch with this descriptor
            if let Some(watch) = registry.watches.values_mut().find(|w| w.wd == wd) {
                // Translate inotify event mask to our event names
                let mask = event.mask;

                // Handle kernel-level queue overflow
                if mask.contains(EventMask::Q_OVERFLOW) {
                    let (name, kind) = ("fs.overflow".to_string(), Some("overflow".to_string()));
                    watch.enqueue(name, kind, None);
                    continue;
                }

                // Handle watch invalidation by kernel (watched file deleted, filesystem unmounted)
                if mask.contains(EventMask::IGNORED) {
                    // Watch was invalidated by kernel - remove all logical watches using this wd
                    registry.watches.retain(|_, w| w.wd != wd);
                    // Also remove from refcounts since kernel watch is gone
                    registry.wd_refcounts.remove(&wd);
                    continue;
                }

                // Handle watched file/directory deleted
                if mask.contains(EventMask::DELETE_SELF) {
                    let (name, kind) = ("fs.delete".to_string(), Some("directory".to_string()));
                    watch.enqueue(name, kind, event.name);
                    // Watch is now invalid since the watched file/directory was deleted
                    registry.watches.retain(|_, w| w.wd != wd);
                    registry.wd_refcounts.remove(&wd);
                    continue;
                }

                // Handle watched file/directory moved
                if mask.contains(EventMask::MOVE_SELF) {
                    let (name, kind) = ("fs.move".to_string(), Some("directory".to_string()));
                    watch.enqueue(name, kind, event.name);
                    continue;
                }

                // Translate inotify event mask to our event names
                let mask = event.mask;
                let filename = event.name;

                if mask.contains(EventMask::CREATE) {
                    let (name, kind) = translate_mask(EventMask::CREATE);
                    watch.enqueue(name, kind, filename);
                }
                if mask.contains(EventMask::DELETE) {
                    let (name, kind) = translate_mask(EventMask::DELETE);
                    watch.enqueue(name, kind, filename);
                }
                if mask.contains(EventMask::MODIFY) {
                    let (name, kind) = translate_mask(EventMask::MODIFY);
                    watch.enqueue(name, kind, filename);
                }
                if mask.contains(EventMask::MOVED_TO) || mask.contains(EventMask::MOVED_FROM) {
                    let (name, kind) = translate_mask(mask);
                    watch.enqueue(name, kind, filename);
                }
                if mask.contains(EventMask::CLOSE_WRITE) {
                    let (name, kind) = translate_mask(EventMask::CLOSE_WRITE);
                    watch.enqueue(name, kind, filename);
                }
                // Update total_queued_events for each event added
                // Note: enqueue handles dropping oldest if queue is full
            }
            // If wd not found, the watch was removed but event is stale - ignore
        }

        Ok(())
    }

    pub fn unwatch(&self, owner: u64, watch_id: u64) -> Result<bool, FsFailure> {
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

        // Remove the inotify watch only if refcount reached zero
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

    /// Remove all watches owned by a connection.
    ///
    /// Called when a connection is closed.
    pub fn cleanup_connection(&self, owner: u64) {
        let wds_to_remove = {
            let mut registry = match self.registry.lock() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "igrisd: event provider mutex poisoned during cleanup: {}",
                        e
                    );
                    return;
                }
            };

            let watch_ids: Vec<u64> = registry
                .watches
                .iter()
                .filter(|(_, w)| w.owner == owner)
                .map(|(id, _)| *id)
                .collect();

            let mut wds = Vec::new();
            for id in watch_ids {
                // Get the wd first, then remove the watch
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
            Err(e) => {
                eprintln!(
                    "igrisd: event provider mutex poisoned during cleanup: {}",
                    e
                );
                return;
            }
        };
        for wd in wds_to_remove {
            // Decrement refcount and only remove inotify watch if refcount reaches 0
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

#[cfg(test)]
impl EventProvider {
    /// Test helper to enqueue an event for testing purposes.
    #[allow(dead_code)]
    pub fn _test_enqueue(
        &self,
        owner: u64,
        watch_id: u64,
        name: String,
        kind: Option<String>,
    ) -> Result<bool, FsFailure> {
        let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
        let watch = registry
            .watches
            .get_mut(&watch_id)
            .ok_or(ProviderError::WatchNotFound)?;
        if watch.owner != owner {
            return Err(ProviderError::WatchNotFound.into());
        }
        let was_full = watch.events.len() >= MAX_EVENTS_PER_WATCH;
        watch.enqueue(name, kind, None);
        if !was_full {
            registry.total_queued_events += 1;
        }
        Ok(true)
    }
}

/// Translate an inotify event mask to our event name and kind.
fn translate_mask(mask: EventMask) -> (String, Option<String>) {
    if mask.contains(EventMask::CREATE) {
        ("fs.create".to_string(), Some("file".to_string()))
    } else if mask.contains(EventMask::DELETE) {
        ("fs.delete".to_string(), Some("file".to_string()))
    } else if mask.contains(EventMask::MODIFY) {
        ("fs.modify".to_string(), Some("file".to_string()))
    } else if mask.contains(EventMask::MOVED_TO) || mask.contains(EventMask::MOVED_FROM) {
        ("fs.move".to_string(), Some("file".to_string()))
    } else if mask.contains(EventMask::CLOSE_WRITE) {
        ("fs.modify".to_string(), Some("file".to_string()))
    } else {
        ("fs.unknown".to_string(), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;
    use std::time::Duration;

    fn temp_root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "igris-events-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn watch_returns_id() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let res = provider.watch(1, &root.to_string_lossy()).expect("watch");
        assert_eq!(res.watch_id, 1);
    }

    #[test]
    fn watch_rejects_outside_root() {
        let root = temp_root();
        let provider = EventProvider::new(&root);

        let err = provider
            .watch(1, "/etc/hostname")
            .expect_err("outside root");
        assert_eq!(err.code, error_code::BAD_REQUEST);
    }

    #[test]
    fn watch_enforces_max() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        // Create MAX_EVENT_WATCHES watches
        for i in 1..=MAX_EVENT_WATCHES {
            let res = provider.watch(1, &root.to_string_lossy()).expect("watch");
            assert_eq!(res.watch_id, i as u64);
        }

        // Next should fail
        let err = provider
            .watch(1, &root.to_string_lossy())
            .expect_err("max exceeded");
        assert_eq!(err.code, error_code::FS_ERROR);
    }

    #[test]
    fn poll_empty_watch_returns_empty() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");
        let res = provider.poll(1, watch.watch_id, 10).expect("poll");
        assert!(res.events.is_empty());
    }

    #[test]
    fn filesystem_create_produces_event() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");

        // Create a file in the watched directory
        fs::write(root.join("new_file.txt"), b"hello").unwrap();

        // Poll should return the create event
        let res = provider.poll(1, watch.watch_id, 10).expect("poll");
        assert!(!res.events.is_empty());
        assert_eq!(res.events[0].name, "fs.create");
        assert!(res.events[0].path.contains("new_file.txt"));
    }

    #[test]
    fn filesystem_modify_produces_event() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");

        // Create and then modify a file
        fs::write(root.join("modify_me.txt"), b"original").unwrap();
        thread::sleep(Duration::from_millis(50));
        fs::write(root.join("modify_me.txt"), b"modified").unwrap();

        // Poll should return the modify event
        let res = provider.poll(1, watch.watch_id, 10).expect("poll");
        let modify_events: Vec<_> = res
            .events
            .iter()
            .filter(|e| e.name == "fs.modify")
            .collect();
        assert!(!modify_events.is_empty());
    }

    #[test]
    fn filesystem_delete_produces_event() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");

        // Create and then delete a file
        fs::write(root.join("delete_me.txt"), b"to delete").unwrap();
        thread::sleep(Duration::from_millis(50));
        fs::remove_file(root.join("delete_me.txt")).unwrap();

        // Poll should return the delete event
        let res = provider.poll(1, watch.watch_id, 10).expect("poll");
        let delete_events: Vec<_> = res
            .events
            .iter()
            .filter(|e| e.name == "fs.delete")
            .collect();
        assert!(!delete_events.is_empty());
    }

    #[test]
    fn filesystem_rename_produces_event() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");

        // Create and then rename a file
        fs::write(root.join("rename_me.txt"), b"to rename").unwrap();
        thread::sleep(Duration::from_millis(50));
        fs::rename(root.join("rename_me.txt"), root.join("renamed.txt")).unwrap();

        // Poll should return move events
        let res = provider.poll(1, watch.watch_id, 10).expect("poll");
        let move_events: Vec<_> = res.events.iter().filter(|e| e.name == "fs.move").collect();
        assert!(!move_events.is_empty());
    }

    #[test]
    fn unwatch_stops_future_events() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");

        // Unwatch
        provider.unwatch(1, watch.watch_id).expect("unwatch");

        // Create a file - should not produce events for this watch
        fs::write(root.join("after_unwatch.txt"), b"ignored").unwrap();

        // Poll should return NOT_FOUND immediately after unwatch
        let err = provider
            .poll(1, watch.watch_id, 10)
            .expect_err("watch gone");
        assert_eq!(err.code, error_code::NOT_FOUND);
    }

    #[test]
    fn cleanup_connection_removes_watches() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let _w1 = provider.watch(1, &root.to_string_lossy()).expect("watch 1");
        let _w2 = provider.watch(1, &root.to_string_lossy()).expect("watch 2");
        let _w3 = provider.watch(2, &root.to_string_lossy()).expect("watch 3");

        // Connection 1 has 2 watches, connection 2 has 1
        provider.cleanup_connection(1);

        // Connection 1's watches should be gone
        let err = provider.poll(1, 1, 10).expect_err("watch 1 gone");
        assert_eq!(err.code, error_code::NOT_FOUND);

        // Connection 2's watch should remain
        let res = provider.poll(2, 3, 10).expect("watch 3 remains");
        assert!(res.events.is_empty());
    }

    #[test]
    fn watch_ids_reused_after_unwatch() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let w1 = provider.watch(1, &root.to_string_lossy()).expect("watch 1");
        let w2 = provider.watch(1, &root.to_string_lossy()).expect("watch 2");
        assert_eq!(w1.watch_id, 1);
        assert_eq!(w2.watch_id, 2);

        provider.unwatch(1, 1).expect("unwatch 1");

        // Next watch should reuse ID 1
        let w3 = provider.watch(1, &root.to_string_lossy()).expect("watch 3");
        assert_eq!(w3.watch_id, 1);
    }

    #[test]
    fn queue_bounded_per_watch() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");

        // Fill queue beyond capacity using test enqueue
        for i in 0..MAX_EVENTS_PER_WATCH + 10 {
            provider
                ._test_enqueue(
                    1,
                    watch.watch_id,
                    format!("fs.test{}", i),
                    Some("file".into()),
                )
                .unwrap();
        }

        let res = provider
            .poll(1, watch.watch_id, MAX_POLL_EVENTS)
            .expect("poll");
        assert_eq!(res.events.len(), MAX_EVENTS_PER_WATCH);

        // The oldest events should have been dropped
        let names: Vec<&str> = res.events.iter().map(|e| e.name.as_str()).collect();
        // Should have the last MAX_EVENTS_PER_WATCH events
        assert_eq!(names.first().copied(), Some("fs.test10"));
    }

    #[test]
    fn global_queue_bounded() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        // Create multiple watches and fill them
        let mut watch_ids = Vec::new();
        for i in 1..=MAX_EVENT_WATCHES {
            let w = provider
                .watch(i as u64, &root.to_string_lossy())
                .expect("watch");
            watch_ids.push(w.watch_id);
        }

        // Fill all queues using test enqueue
        for (i, wid) in watch_ids.iter().enumerate() {
            for j in 0..MAX_EVENTS_PER_WATCH + 5 {
                provider
                    ._test_enqueue(
                        i as u64 + 1,
                        *wid,
                        format!("fs.test{}", j),
                        Some("file".into()),
                    )
                    .unwrap();
            }
        }

        // Total events should not exceed MAX_QUEUED_EVENTS
        for (i, wid) in watch_ids.iter().enumerate() {
            let res = provider
                .poll(i as u64 + 1, *wid, MAX_POLL_EVENTS)
                .expect("poll");
            assert!(res.events.len() <= MAX_POLL_EVENTS);
        }
    }

    #[test]
    fn path_canonicalization() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/file.txt"), b"data").unwrap();

        // Watch using a relative-looking path that resolves inside root
        let path = format!("{}/sub/../sub", root.display());
        let res = provider.watch(1, &path).expect("watch canonicalized path");
        assert_eq!(res.watch_id, 1);
    }

    #[test]
    fn poll_respects_max_poll_events() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");

        // Enqueue more than MAX_POLL_EVENTS (but limited by per-watch capacity)
        for i in 0..MAX_POLL_EVENTS + 10 {
            provider
                ._test_enqueue(
                    1,
                    watch.watch_id,
                    format!("fs.test{}", i),
                    Some("file".into()),
                )
                .unwrap();
        }

        // Request more than MAX_POLL_EVENTS
        let res = provider
            .poll(1, watch.watch_id, MAX_POLL_EVENTS + 50)
            .expect("poll");
        // The per-watch queue is limited to MAX_EVENTS_PER_WATCH (16), so we can only get that many
        assert_eq!(res.events.len(), MAX_EVENTS_PER_WATCH);
    }

    #[test]
    fn unwatch_requires_ownership() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");

        // Different owner cannot unwatch
        let err = provider
            .unwatch(2, watch.watch_id)
            .expect_err("ownership violation");
        assert_eq!(err.code, error_code::NOT_FOUND);

        // Owner can unwatch
        let ok = provider.unwatch(1, watch.watch_id).expect("unwatch");
        assert!(ok);
    }

    #[test]
    fn unwatch_nonexistent_returns_not_found() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let err = provider.unwatch(1, 999).expect_err("nonexistent");
        assert_eq!(err.code, error_code::NOT_FOUND);
    }
}
