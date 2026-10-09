//! Error types for session management.

use thiserror::Error;

/// Errors that can occur in session management.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session has expired")]
    SessionExpired,

    #[error("session has been revoked")]
    SessionRevoked,

    #[error("unknown capability: {0}")]
    UnknownCapability(String),

    #[error("missing required capability: {0}")]
    MissingCapability(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("capacity limit exceeded: maximum {max} capabilities per session")]
    CapacityExceeded { max: usize },

    #[error("invalid session state: {0}")]
    InvalidState(String),

    #[error("confirmation token not found: {0}")]
    ConfirmationNotFound(String),

    #[error("confirmation token already used: {0}")]
    ConfirmationAlreadyUsed(String),

    #[error("confirmation token expired: {0}")]
    ConfirmationExpired(String),

    #[error("confirmation token does not match request")]
    ConfirmationMismatch,
}

/// Result type for session operations.
pub type SessionResult<T> = Result<T, SessionError>;
