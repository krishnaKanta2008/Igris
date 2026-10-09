//! Igris session and capability management.
//!
//! This crate manages AI agent sessions and their associated capabilities.
//! Sessions are isolated, have explicit capabilities, and automatically expire.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use getrandom::getrandom;
use igris_tool_registry::{ToolId, ToolRegistry};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod error;

pub use error::{SessionError, SessionResult};

/// Default session duration (1 hour).
pub const DEFAULT_SESSION_DURATION: Duration = Duration::from_secs(3600);

/// Maximum number of capabilities per session.
pub const MAX_CAPABILITIES_PER_SESSION: usize = 32;

/// Generate a cryptographically secure random session ID.
fn generate_session_id() -> SessionId {
    let mut bytes = [0u8; 16];
    getrandom(&mut bytes).expect("OS RNG failure");
    SessionId(Uuid::from_bytes(bytes))
}

/// Generate a cryptographically secure random confirmation token.
fn generate_confirmation_token() -> ConfirmationToken {
    let mut bytes = [0u8; 16];
    getrandom(&mut bytes).expect("OS RNG failure");
    ConfirmationToken(Uuid::from_bytes(bytes))
}

/// Opaque session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn new() -> Self {
        generate_session_id()
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for SessionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(SessionId)
    }
}

/// Opaque confirmation token for sensitive operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfirmationToken(Uuid);

impl ConfirmationToken {
    pub fn new() -> Self {
        generate_confirmation_token()
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl Default for ConfirmationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ConfirmationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ConfirmationToken {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(ConfirmationToken)
    }
}

/// A set of capabilities granted to a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    capabilities: BTreeSet<String>,
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self {
            capabilities: BTreeSet::new(),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self {
            capabilities: iter.into_iter().collect(),
        }
    }

    pub fn add(&mut self, capability: String) -> bool {
        if self.capabilities.len() >= MAX_CAPABILITIES_PER_SESSION {
            return false;
        }
        self.capabilities.insert(capability)
    }

    pub fn remove(&mut self, capability: &str) -> bool {
        self.capabilities.remove(capability)
    }

    pub fn contains(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.capabilities.iter()
    }

    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    pub fn union(&self, other: &CapabilitySet) -> CapabilitySet {
        CapabilitySet {
            capabilities: self
                .capabilities
                .union(&other.capabilities)
                .cloned()
                .collect(),
        }
    }

    pub fn intersection(&self, other: &CapabilitySet) -> CapabilitySet {
        CapabilitySet {
            capabilities: self
                .capabilities
                .intersection(&other.capabilities)
                .cloned()
                .collect(),
        }
    }

    pub fn difference(&self, other: &CapabilitySet) -> CapabilitySet {
        CapabilitySet {
            capabilities: self
                .capabilities
                .difference(&other.capabilities)
                .cloned()
                .collect(),
        }
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::new()
    }
}

impl From<BTreeSet<String>> for CapabilitySet {
    fn from(capabilities: BTreeSet<String>) -> Self {
        Self { capabilities }
    }
}

/// Session context containing identity, capabilities, and lifecycle info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub id: SessionId,
    pub capabilities: CapabilitySet,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
}

impl SessionContext {
    pub fn new(capabilities: CapabilitySet, duration: Duration) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::new(),
            capabilities,
            created_at: now,
            expires_at: now
                + chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::hours(1)),
            revoked_at: None,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        self.revoked_at.is_none() && self.expires_at > now
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn revoke(&mut self) {
        self.revoked_at = Some(Utc::now());
    }

    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

    pub fn has_all_capabilities(&self, capabilities: &[&str]) -> bool {
        capabilities.iter().all(|c| self.capabilities.contains(c))
    }

    pub fn remaining_duration(&self) -> Option<Duration> {
        let now = Utc::now();
        if now >= self.expires_at {
            return None;
        }
        let diff = self.expires_at - now;
        diff.to_std().ok()
    }
}

/// Session manager for creating and managing agent sessions.
#[derive(Debug)]
pub struct SessionManager {
    sessions: RwLock<std::collections::HashMap<SessionId, SessionContext>>,
    default_duration: Duration,
    tool_registry: Arc<ToolRegistry>,
}

impl SessionManager {
    pub fn new(tool_registry: Arc<ToolRegistry>) -> Self {
        Self {
            sessions: RwLock::new(std::collections::HashMap::new()),
            default_duration: DEFAULT_SESSION_DURATION,
            tool_registry,
        }
    }

    pub fn with_default_duration(mut self, duration: Duration) -> Self {
        self.default_duration = duration;
        self
    }

    /// Create a new session with the given capabilities.
    pub fn create_session(&self, capabilities: CapabilitySet) -> SessionResult<SessionContext> {
        // Validate that all capabilities are known
        for cap in capabilities.iter() {
            if !self.is_known_capability(cap) {
                return Err(SessionError::UnknownCapability(cap.clone()));
            }
        }

        let session = SessionContext::new(capabilities, self.default_duration);
        let id = session.id.clone();

        self.sessions.write().insert(id, session.clone());
        Ok(session)
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: &SessionId) -> Option<SessionContext> {
        self.sessions.read().get(id).cloned()
    }

    /// Get a session by ID, checking validity.
    pub fn get_valid_session(&self, id: &SessionId) -> SessionResult<SessionContext> {
        let session = self
            .sessions
            .read()
            .get(id)
            .cloned()
            .ok_or(SessionError::SessionNotFound(id.to_string()))?;

        if !session.is_valid() {
            if session.is_revoked() {
                return Err(SessionError::SessionRevoked);
            }
            if session.is_expired() {
                return Err(SessionError::SessionExpired);
            }
        }

        Ok(session)
    }

    /// Revoke a session.
    pub fn revoke_session(&self, id: &SessionId) -> SessionResult<()> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(id)
            .ok_or(SessionError::SessionNotFound(id.to_string()))?;
        session.revoke();
        Ok(())
    }

    /// Remove a session entirely.
    pub fn remove_session(&self, id: &SessionId) -> SessionResult<()> {
        self.sessions
            .write()
            .remove(id)
            .ok_or(SessionError::SessionNotFound(id.to_string()))?;
        Ok(())
    }

    /// Clean up expired and revoked sessions.
    pub fn cleanup(&self) -> usize {
        let mut sessions = self.sessions.write();
        let before = sessions.len();
        sessions.retain(|_, s| s.is_valid());
        before - sessions.len()
    }

    /// Check if a capability is known (registered in tool registry).
    fn is_known_capability(&self, capability: &str) -> bool {
        for tool in self.tool_registry.tools() {
            if tool.required_capability() == capability {
                return true;
            }
        }
        false
    }

    /// Validate that a session has the required capability for a tool.
    pub fn validate_capability(
        &self,
        session_id: &SessionId,
        tool_id: &ToolId,
    ) -> SessionResult<()> {
        let session = self.get_valid_session(session_id)?;
        let tool = self
            .tool_registry
            .get(tool_id)
            .ok_or(SessionError::ToolNotFound(tool_id.to_string()))?;

        if !session.has_capability(tool.required_capability()) {
            return Err(SessionError::MissingCapability(
                tool.required_capability().to_string(),
            ));
        }

        Ok(())
    }

    /// Get the tool registry.
    pub fn tool_registry(&self) -> &Arc<ToolRegistry> {
        &self.tool_registry
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn session_id_generation() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn session_id_from_str() {
        let id = SessionId::new();
        let s = id.to_string();
        let parsed = SessionId::from_str(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn capability_set_operations() {
        let mut caps = CapabilitySet::new();
        caps.add("filesystem_read".to_string());
        caps.add("filesystem_write".to_string());

        assert!(caps.contains("filesystem_read"));
        assert!(caps.contains("filesystem_write"));
        assert!(!caps.contains("process_control"));

        caps.remove("filesystem_read");
        assert!(!caps.contains("filesystem_read"));
    }

    #[test]
    fn session_context_lifecycle() {
        let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
        let session = SessionContext::new(caps, DEFAULT_SESSION_DURATION);

        assert!(session.is_valid());
        assert!(!session.is_expired());
        assert!(!session.is_revoked());
        assert!(session.has_capability("filesystem_read"));
    }

    #[test]
    fn session_revocation() {
        let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
        let mut session = SessionContext::new(caps, DEFAULT_SESSION_DURATION);

        assert!(session.is_valid());
        session.revoke();
        assert!(!session.is_valid());
        assert!(session.is_revoked());
    }

    #[test]
    fn session_manager_create_and_get() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let manager = SessionManager::new(registry);

        let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
        let session = manager.create_session(caps).unwrap();

        let retrieved = manager.get_session(&session.id).unwrap();
        assert_eq!(session.id, retrieved.id);
        assert!(retrieved.is_valid());
    }

    #[test]
    fn session_manager_unknown_capability_rejected() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let manager = SessionManager::new(registry);

        let caps = CapabilitySet::from_iter(vec!["unknown_capability".to_string()]);
        let result = manager.create_session(caps);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SessionError::UnknownCapability(_)
        ));
    }

    #[test]
    fn session_manager_missing_capability_rejected() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let manager = SessionManager::new(registry);

        let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
        let session = manager.create_session(caps).unwrap();

        // fs.write requires filesystem_write capability
        let tool_id = ToolId::new("fs.write");
        let result = manager.validate_capability(&session.id, &tool_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SessionError::MissingCapability(_)
        ));
    }

    #[test]
    fn session_manager_valid_capability_allowed() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let manager = SessionManager::new(registry);

        let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
        let session = manager.create_session(caps).unwrap();

        // fs.read requires filesystem_read capability
        let tool_id = ToolId::new("fs.read");
        let result = manager.validate_capability(&session.id, &tool_id);
        assert!(result.is_ok());
    }

    #[test]
    fn session_manager_revoked_session_rejected() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let manager = SessionManager::new(registry);

        let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
        let session = manager.create_session(caps).unwrap();

        manager.revoke_session(&session.id).unwrap();

        let result = manager.get_valid_session(&session.id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SessionError::SessionRevoked));
    }

    #[test]
    fn session_manager_expired_session_rejected() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let manager = SessionManager::new(registry).with_default_duration(Duration::from_nanos(1));

        let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
        let session = manager.create_session(caps).unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        let result = manager.get_valid_session(&session.id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SessionError::SessionExpired));
    }
}
