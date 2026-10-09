//! Error types for confirmation gate.

use thiserror::Error;

/// Errors that can occur in confirmation management.
#[derive(Debug, Error)]
pub enum ConfirmationError {
    #[error("session error: {0}")]
    SessionError(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("confirmation not required for this tool")]
    ConfirmationNotRequired,

    #[error("confirmation not found: {0}")]
    ConfirmationNotFound(String),

    #[error("confirmation already used")]
    ConfirmationAlreadyUsed,

    #[error("confirmation expired")]
    ConfirmationExpired,

    #[error("confirmation token does not match request")]
    ConfirmationMismatch,

    #[error("too many pending confirmations for session")]
    TooManyPending,

    #[error("invalid confirmation state: {0}")]
    InvalidState(String),
}

/// Result type for confirmation operations.
pub type ConfirmationResult<T> = Result<T, ConfirmationError>;
