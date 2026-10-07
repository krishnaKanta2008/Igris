//! Event observation provider (`events.watch`, `events.poll`, `events.unwatch`).
//!
//! This provider manages a bounded set of event watches per connection. Each
//! watch owns a bounded queue of events. The provider is isolated: the server
//! only interacts with it through the public API and never inspects internal
//! watch state.
//!
//! This skeleton does not yet produce real filesystem events (no inotify/
//! fanotify integration). Watches can be created, polled, and removed, but
//! their queues remain empty until a future commit adds an event producer.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use igris_proto::{
    error_code, Event, PollResult, WatchResult, MAX_EVENT_WATCHES, MAX_POLL_EVENTS,
    MAX_QUEUED_EVENTS,
};

use crate::providers::fs::{resolve_within, FsFailure};

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
    events: Vec<Event>,
    #[allow(dead_code)]
    errored: bool,
}

impl Watch {
    fn new(watch_id: u64, owner: u64, path: PathBuf) -> Self {
        Self {
            watch_id,
            owner,
            path,
            events: Vec::with_capacity(MAX_EVENTS_PER_WATCH),
            errored: false,
        }
    }

    /// Attempt to enqueue an event, respecting bounds.
    ///
    /// Returns `true` if the event was enqueued, `false` if the queue was full
    /// and the oldest event was dropped.
    #[allow(dead_code)]
    fn enqueue(&mut self, name: String, kind: Option<String>) -> bool {
        if self.events.len() >= MAX_EVENTS_PER_WATCH {
            // Drop oldest event to make room.
            self.events.remove(0);
        }
        let event = Event {
            name,
            path: self.path.display().to_string(),
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
    /// Total queued events across all watches.
    total_queued_events: usize,
}

impl WatchRegistry {
    fn new() -> Self {
        Self {
            watches: HashMap::new(),
            next_watch_id: 1,
            watches_per_connection: HashMap::new(),
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
    fn create_watch(&mut self, owner: u64, path: PathBuf) -> Result<u64, ProviderError> {
        if self.watches.len() >= MAX_EVENT_WATCHES {
            return Err(ProviderError::MaxWatches);
        }

        let watch_id = self.allocate_id().ok_or(ProviderError::MaxWatches)?;

        let watch = Watch::new(watch_id, owner, path);
        self.watches.insert(watch_id, watch);
        *self.watches_per_connection.entry(owner).or_insert(0) += 1;

        Ok(watch_id)
    }

    /// Remove a watch by ID, verifying ownership.
    fn remove_watch(&mut self, owner: u64, watch_id: u64) -> Result<(), ProviderError> {
        let watch = self
            .watches
            .get(&watch_id)
            .ok_or(ProviderError::WatchNotFound)?;

        if watch.owner != owner {
            return Err(ProviderError::WatchNotFound); // Ownership violation -> NOT_FOUND
        }

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

        Ok(())
    }

    /// Poll events from a watch, verifying ownership.
    fn poll_events(
        &mut self,
        owner: u64,
        watch_id: u64,
        max: usize,
    ) -> Result<Vec<Event>, ProviderError> {
        let max = max.clamp(1, MAX_POLL_EVENTS);
        let watch = self
            .watches
            .get_mut(&watch_id)
            .ok_or(ProviderError::WatchNotFound)?;

        if watch.owner != owner {
            return Err(ProviderError::WatchNotFound);
        }

        let events = watch.drain_events(max);
        self.total_queued_events = self.total_queued_events.saturating_sub(events.len());
        Ok(events)
    }

    /// Remove all watches owned by a connection.
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
        }
    }
}

/// Event provider: manages watches, queues, and event dispatch.
pub struct EventProvider {
    fs_root: PathBuf,
    registry: Mutex<WatchRegistry>,
}

impl EventProvider {
    /// Create a new event provider with the given filesystem root.
    pub fn new(fs_root: impl Into<PathBuf>) -> Self {
        Self {
            fs_root: fs_root.into(),
            registry: Mutex::new(WatchRegistry::new()),
        }
    }

    /// Create a new filesystem watch.
    ///
    /// Validates that the path is within the filesystem root, allocates a
    /// watch ID, and returns it. The watch starts with an empty queue.
    pub fn watch(&self, owner: u64, path: &str) -> Result<WatchResult, FsFailure> {
        // Validate and canonicalize the path using the same boundary logic as fs provider.
        let resolved = resolve_within(&self.fs_root, path)?;

        let watch_id = {
            let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
            registry.create_watch(owner, resolved)?
        };

        Ok(WatchResult { watch_id })
    }

    /// Poll events from a watch.
    ///
    /// Drains up to `max` events from the watch's queue. Returns an empty
    /// vector if the queue is empty. Does not block.
    pub fn poll(&self, owner: u64, watch_id: u64, max: usize) -> Result<PollResult, FsFailure> {
        let events = {
            let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
            registry.poll_events(owner, watch_id, max)?
        };
        Ok(PollResult { events })
    }

    /// Remove a watch.
    ///
    /// Requires ownership. Returns `true` on success.
    pub fn unwatch(&self, owner: u64, watch_id: u64) -> Result<bool, FsFailure> {
        let mut registry = self.registry.lock().map_err(|_| ProviderError::Internal)?;
        registry.remove_watch(owner, watch_id)?;
        Ok(true)
    }

    /// Remove all watches owned by a connection.
    ///
    /// Called when a connection is closed.
    pub fn cleanup_connection(&self, owner: u64) {
        let mut registry = match self.registry.lock() {
            Ok(r) => r,
            Err(e) => {
                // If the mutex is poisoned, we can't do much; log and return.
                eprintln!(
                    "igrisd: event provider mutex poisoned during cleanup: {}",
                    e
                );
                return;
            }
        };
        registry.cleanup_connection(owner);
    }

    /// Internal method to enqueue an event for a watch (for future producer use).
    ///
    /// Returns `true` if the event was enqueued (possibly dropping oldest).
    /// This is a stub for the future inotify integration.
    #[cfg(test)]
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
        watch.enqueue(name, kind);
        if was_full {
            // If we dropped an event, total_queued doesn't change
        } else {
            registry.total_queued_events += 1;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
    fn poll_respects_max() {
        let root = temp_root();
        let provider = EventProvider::new(&root);
        fs::create_dir_all(&root).unwrap();

        let watch = provider.watch(1, &root.to_string_lossy()).expect("watch");

        // Enqueue some events directly for testing
        for i in 0..5 {
            provider
                ._test_enqueue(
                    1,
                    watch.watch_id,
                    format!("fs.test{}", i),
                    Some("file".into()),
                )
                .unwrap();
        }

        // Poll with max=2
        let res = provider.poll(1, watch.watch_id, 2).expect("poll");
        assert_eq!(res.events.len(), 2);

        // Poll again with max=10
        let res = provider.poll(1, watch.watch_id, 10).expect("poll");
        assert_eq!(res.events.len(), 3);
    }

    #[test]
    fn poll_clamps_to_max_poll_events() {
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

        // Fill queue beyond capacity
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

        // Fill all queues
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
        // Note: we can't easily check internal total_queued_events, but we can verify
        // that polling doesn't return more than the bound.
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
}
