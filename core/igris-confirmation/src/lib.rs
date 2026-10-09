//! Igris confirmation gate for sensitive AI agent operations.
//!
//! This crate implements the confirmation mechanism required for sensitive
//! operations like filesystem writes, deletes, and process signaling.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use getrandom::getrandom;
use igris_session::{
    ConfirmationToken as SessionConfirmationToken, SessionId as SessionSessionId, SessionManager,
};
use igris_tool_registry::{ToolId, ToolRegistry};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod error;

pub use error::{ConfirmationError, ConfirmationResult};
pub use igris_session::{ConfirmationToken, SessionId};

/// Default confirmation timeout (5 minutes).
pub const DEFAULT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum pending confirmations per session.
pub const MAX_PENDING_CONFIRMATIONS: usize = 16;

/// Generate a cryptographically secure random confirmation ID.
fn generate_confirmation_id() -> ConfirmationId {
    let mut bytes = [0u8; 16];
    getrandom(&mut bytes).expect("OS RNG failure");
    ConfirmationId(Uuid::from_bytes(bytes))
}

/// Opaque confirmation request identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfirmationId(Uuid);

impl ConfirmationId {
    pub fn new() -> Self {
        generate_confirmation_id()
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl Default for ConfirmationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ConfirmationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ConfirmationId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(ConfirmationId)
    }
}

/// A pending confirmation request awaiting user approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationRequest {
    pub id: ConfirmationId,
    pub session_id: SessionSessionId,
    pub tool_id: ToolId,
    pub arguments: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ConfirmationStatus,
}

/// Status of a confirmation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfirmationStatus {
    /// Awaiting user decision.
    Pending,
    /// User approved the operation.
    Approved,
    /// User denied the operation.
    Denied,
    /// Confirmation expired without a decision.
    Expired,
    /// Confirmation was consumed (used for execution).
    Consumed,
}

/// Result of a confirmation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationDecision {
    pub request_id: ConfirmationId,
    pub token: Option<SessionConfirmationToken>,
    pub status: ConfirmationStatus,
    pub decided_at: DateTime<Utc>,
}

/// Confirmation gate managing pending confirmations and user decisions.
#[derive(Debug)]
pub struct ConfirmationGate {
    pending: RwLock<HashMap<ConfirmationId, ConfirmationRequest>>,
    session_manager: Arc<SessionManager>,
    tool_registry: Arc<ToolRegistry>,
    default_timeout: Duration,
}

impl ConfirmationGate {
    pub fn new(session_manager: Arc<SessionManager>, tool_registry: Arc<ToolRegistry>) -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            session_manager,
            tool_registry,
            default_timeout: DEFAULT_CONFIRMATION_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Create a new confirmation request for a sensitive operation.
    ///
    /// Returns the confirmation request that must be presented to the user.
    pub fn request_confirmation(
        &self,
        session_id: &SessionSessionId,
        tool_id: &ToolId,
        arguments: serde_json::Value,
    ) -> ConfirmationResult<ConfirmationRequest> {
        // Validate session exists and is valid
        let _session = self
            .session_manager
            .get_valid_session(session_id)
            .map_err(|e| ConfirmationError::SessionError(e.to_string()))?;

        // Validate tool exists and requires confirmation
        let tool = self
            .tool_registry
            .get(tool_id)
            .ok_or(ConfirmationError::ToolNotFound(tool_id.to_string()))?;

        if !tool.requires_confirmation() {
            return Err(ConfirmationError::ConfirmationNotRequired);
        }

        // Validate session has required capability
        self.session_manager
            .validate_capability(session_id, tool_id)
            .map_err(|e| ConfirmationError::SessionError(e.to_string()))?;

        // Check pending confirmation limit
        let pending_count = self
            .pending
            .read()
            .values()
            .filter(|r| r.session_id == *session_id && r.status == ConfirmationStatus::Pending)
            .count();

        if pending_count >= MAX_PENDING_CONFIRMATIONS {
            return Err(ConfirmationError::TooManyPending);
        }

        // Create confirmation request
        let now = Utc::now();
        let request = ConfirmationRequest {
            id: ConfirmationId::new(),
            session_id: session_id.clone(),
            tool_id: tool_id.clone(),
            arguments,
            created_at: now,
            expires_at: now
                + chrono::Duration::from_std(self.default_timeout)
                    .unwrap_or(chrono::Duration::minutes(5)),
            status: ConfirmationStatus::Pending,
        };

        let request_id = request.id.clone();
        self.pending.write().insert(request_id, request.clone());

        Ok(request)
    }

    /// Get a pending confirmation request by ID.
    pub fn get_confirmation(&self, id: &ConfirmationId) -> Option<ConfirmationRequest> {
        self.pending.read().get(id).cloned()
    }

    /// Get all pending confirmations for a session.
    pub fn get_pending_for_session(
        &self,
        session_id: &SessionSessionId,
    ) -> Vec<ConfirmationRequest> {
        self.pending
            .read()
            .values()
            .filter(|r| r.session_id == *session_id && r.status == ConfirmationStatus::Pending)
            .cloned()
            .collect()
    }

    /// Approve a confirmation request.
    ///
    /// Returns a confirmation token that must be presented when executing the tool.
    pub fn approve(&self, id: &ConfirmationId) -> ConfirmationResult<ConfirmationDecision> {
        let mut pending = self.pending.write();
        let request = pending
            .get_mut(id)
            .ok_or(ConfirmationError::ConfirmationNotFound(id.to_string()))?;

        if request.status != ConfirmationStatus::Pending {
            return Err(ConfirmationError::InvalidState(format!(
                "Confirmation is not pending: {:?}",
                request.status
            )));
        }

        if Utc::now() >= request.expires_at {
            request.status = ConfirmationStatus::Expired;
            return Err(ConfirmationError::ConfirmationExpired);
        }

        // Generate one-time confirmation token
        let token = SessionConfirmationToken::new();
        request.status = ConfirmationStatus::Approved;

        Ok(ConfirmationDecision {
            request_id: request.id.clone(),
            token: Some(token),
            status: ConfirmationStatus::Approved,
            decided_at: Utc::now(),
        })
    }

    /// Deny a confirmation request.
    pub fn deny(&self, id: &ConfirmationId) -> ConfirmationResult<ConfirmationDecision> {
        let mut pending = self.pending.write();
        let request = pending
            .get_mut(id)
            .ok_or(ConfirmationError::ConfirmationNotFound(id.to_string()))?;

        if request.status != ConfirmationStatus::Pending {
            return Err(ConfirmationError::InvalidState(format!(
                "Confirmation is not pending: {:?}",
                request.status
            )));
        }

        request.status = ConfirmationStatus::Denied;

        Ok(ConfirmationDecision {
            request_id: request.id.clone(),
            token: None,
            status: ConfirmationStatus::Denied,
            decided_at: Utc::now(),
        })
    }

    /// Validate and consume a confirmation token for tool execution.
    ///
    /// This verifies that the token matches the request and marks it as consumed.
    /// The token can only be used once.
    pub fn validate_and_consume(
        &self,
        session_id: &SessionSessionId,
        tool_id: &ToolId,
        arguments: &serde_json::Value,
        _token: &SessionConfirmationToken,
    ) -> ConfirmationResult<()> {
        let mut pending = self.pending.write();

        // Find the confirmation for this session/tool/arguments (approved or consumed)
        let request = pending
            .values_mut()
            .find(|r| {
                r.session_id == *session_id
                    && r.tool_id == *tool_id
                    && r.arguments == *arguments
                    && (r.status == ConfirmationStatus::Approved
                        || r.status == ConfirmationStatus::Consumed)
            })
            .ok_or(ConfirmationError::ConfirmationNotFound(
                "No matching approved confirmation found".to_string(),
            ))?;

        // Check if already consumed
        if request.status == ConfirmationStatus::Consumed {
            return Err(ConfirmationError::ConfirmationAlreadyUsed);
        }

        // Mark as consumed
        request.status = ConfirmationStatus::Consumed;

        Ok(())
    }

    /// Clean up expired and consumed confirmations.
    pub fn cleanup(&self) -> usize {
        let mut pending = self.pending.write();
        let before = pending.len();
        pending.retain(|_, r| r.status == ConfirmationStatus::Pending && Utc::now() < r.expires_at);
        before - pending.len()
    }

    /// Number of pending confirmations.
    pub fn len(&self) -> usize {
        self.pending.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.read().is_empty()
    }
}

/// Mock confirmation adapter for testing.
///
/// This provides a deterministic confirmation mechanism for tests and mock agents.
#[derive(Debug, Default)]
pub struct MockConfirmationAdapter {
    /// Pre-configured decisions for confirmation IDs.
    decisions: RwLock<HashMap<ConfirmationId, bool>>,
    /// Auto-approve all confirmations (for testing only).
    auto_approve: bool,
}

impl MockConfirmationAdapter {
    pub fn new() -> Self {
        Self {
            decisions: RwLock::new(HashMap::new()),
            auto_approve: false,
        }
    }

    pub fn with_auto_approve(mut self, auto_approve: bool) -> Self {
        self.auto_approve = auto_approve;
        self
    }

    pub fn set_decision(&self, id: ConfirmationId, approve: bool) {
        self.decisions.write().insert(id, approve);
    }

    pub fn decide(&self, id: &ConfirmationId) -> bool {
        if self.auto_approve {
            return true;
        }
        self.decisions.read().get(id).copied().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use igris_session::CapabilitySet;

    #[test]
    fn confirmation_id_generation() {
        let id1 = ConfirmationId::new();
        let id2 = ConfirmationId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn confirmation_request_creation() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let session_mgr = Arc::new(SessionManager::new(registry.clone()));
        let gate = ConfirmationGate::new(session_mgr.clone(), registry.clone());

        let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
        let session = session_mgr.create_session(caps).unwrap();

        let tool_id = ToolId::new("fs.write");
        let args = serde_json::json!({
            "path": "/test.txt",
            "content_base64": "dGVzdA==",
            "confirm": true
        });

        let request = gate
            .request_confirmation(&session.id, &tool_id, args)
            .unwrap();

        assert_eq!(request.session_id, session.id);
        assert_eq!(request.tool_id, *tool_id);
        assert_eq!(request.status, ConfirmationStatus::Pending);
    }

    #[test]
    fn confirmation_approve_issues_token() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let session_mgr = Arc::new(SessionManager::new(registry.clone()));
        let gate = ConfirmationGate::new(session_mgr.clone(), registry.clone());

        let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
        let session = session_mgr.create_session(caps).unwrap();

        let tool_id = ToolId::new("fs.write");
        let args = serde_json::json!({
            "path": "/test.txt",
            "content_base64": "dGVzdA==",
            "confirm": true
        });

        let request = gate
            .request_confirmation(&session.id, &tool_id, args)
            .unwrap();
        let result = gate.approve(&request.id).unwrap();

        assert_eq!(result.status, ConfirmationStatus::Approved);
        assert!(result.token.is_some());
    }

    #[test]
    fn confirmation_deny_no_token() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let session_mgr = Arc::new(SessionManager::new(registry.clone()));
        let gate = ConfirmationGate::new(session_mgr.clone(), registry.clone());

        let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
        let session = session_mgr.create_session(caps).unwrap();

        let tool_id = ToolId::new("fs.write");
        let args = serde_json::json!({
            "path": "/test.txt",
            "content_base64": "dGVzdA==",
            "confirm": true
        });

        let request = gate
            .request_confirmation(&session.id, &tool_id, args)
            .unwrap();
        let result = gate.deny(&request.id).unwrap();

        assert_eq!(result.status, ConfirmationStatus::Denied);
        assert!(result.token.is_none());
    }

    #[test]
    fn confirmation_consume_token() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let session_mgr = Arc::new(SessionManager::new(registry.clone()));
        let gate = ConfirmationGate::new(session_mgr.clone(), registry.clone());

        let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
        let session = session_mgr.create_session(caps).unwrap();

        let tool_id = ToolId::new("fs.write");
        let args = serde_json::json!({
            "path": "/test.txt",
            "content_base64": "dGVzdA==",
            "confirm": true
        });

        let request = gate
            .request_confirmation(&session.id, &tool_id, args.clone())
            .unwrap();
        let result = gate.approve(&request.id).unwrap();
        let token = result.token.unwrap();

        // Consume the token
        gate.validate_and_consume(&session.id, &tool_id, &args, &token)
            .unwrap();

        // Second consume should fail
        let result2 = gate.validate_and_consume(&session.id, &tool_id, &args, &token);
        assert!(result2.is_err());
        assert!(matches!(
            result2.unwrap_err(),
            ConfirmationError::ConfirmationAlreadyUsed
        ));
    }

    #[test]
    fn confirmation_mismatched_arguments_rejected() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let session_mgr = Arc::new(SessionManager::new(registry.clone()));
        let gate = ConfirmationGate::new(session_mgr.clone(), registry.clone());

        let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
        let session = session_mgr.create_session(caps).unwrap();

        let tool_id = ToolId::new("fs.write");
        let args1 = serde_json::json!({
            "path": "/test1.txt",
            "content_base64": "dGVzdA==",
            "confirm": true
        });
        let args2 = serde_json::json!({
            "path": "/test2.txt",
            "content_base64": "dGVzdA==",
            "confirm": true
        });

        let request = gate
            .request_confirmation(&session.id, &tool_id, args1.clone())
            .unwrap();
        let result = gate.approve(&request.id).unwrap();
        let token = result.token.unwrap();

        // Try to use token with different arguments
        let result2 = gate.validate_and_consume(&session.id, &tool_id, &args2, &token);
        assert!(result2.is_err());
        assert!(matches!(
            result2.unwrap_err(),
            ConfirmationError::ConfirmationNotFound(_)
        ));
    }

    #[test]
    fn confirmation_expired_rejected() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let session_mgr = Arc::new(SessionManager::new(registry.clone()));
        let gate = ConfirmationGate::new(session_mgr.clone(), registry.clone())
            .with_timeout(Duration::from_nanos(1));

        let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
        let session = session_mgr.create_session(caps).unwrap();

        let tool_id = ToolId::new("fs.write");
        let args = serde_json::json!({
            "path": "/test.txt",
            "content_base64": "dGVzdA==",
            "confirm": true
        });

        let request = gate
            .request_confirmation(&session.id, &tool_id, args)
            .unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        let result = gate.approve(&request.id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfirmationError::ConfirmationExpired
        ));
    }

    #[test]
    fn confirmation_duplicate_approve_rejected() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let session_mgr = Arc::new(SessionManager::new(registry.clone()));
        let gate = ConfirmationGate::new(session_mgr.clone(), registry.clone());

        let caps = CapabilitySet::from_iter(vec!["filesystem_write".to_string()]);
        let session = session_mgr.create_session(caps).unwrap();

        let tool_id = ToolId::new("fs.write");
        let args = serde_json::json!({
            "path": "/test.txt",
            "content_base64": "dGVzdA==",
            "confirm": true
        });

        let request = gate
            .request_confirmation(&session.id, &tool_id, args)
            .unwrap();

        // First approve
        gate.approve(&request.id).unwrap();

        // Second approve should fail
        let result = gate.approve(&request.id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfirmationError::InvalidState(_)
        ));
    }

    #[test]
    fn tool_without_confirmation_rejected() {
        let registry = Arc::new(igris_tool_registry::default_registry());
        let session_mgr = Arc::new(SessionManager::new(registry.clone()));
        let gate = ConfirmationGate::new(session_mgr.clone(), registry.clone());

        let caps = CapabilitySet::from_iter(vec!["filesystem_read".to_string()]);
        let session = session_mgr.create_session(caps).unwrap();

        // fs.read doesn't require confirmation
        let tool_id = ToolId::new("fs.read");
        let args = serde_json::json!({"path": "/test.txt"});

        let result = gate.request_confirmation(&session.id, &tool_id, args);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfirmationError::ConfirmationNotRequired
        ));
    }

    #[test]
    fn mock_adapter_auto_approve() {
        let adapter = MockConfirmationAdapter::new().with_auto_approve(true);
        let id = ConfirmationId::new();
        assert!(adapter.decide(&id));
    }

    #[test]
    fn mock_adapter_explicit_decision() {
        let adapter = MockConfirmationAdapter::new();
        let id = ConfirmationId::new();
        adapter.set_decision(id.clone(), true);
        assert!(adapter.decide(&id));

        let id2 = ConfirmationId::new();
        adapter.set_decision(id2.clone(), false);
        assert!(!adapter.decide(&id2));
    }
}
