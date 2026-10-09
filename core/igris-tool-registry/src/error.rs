//! Error types for the tool registry.

use thiserror::Error;

/// Errors that can occur when working with the tool registry.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("tool already registered: {0}")]
    ToolAlreadyRegistered(String),

    #[error("invalid tool schema: {0}")]
    InvalidSchema(String),

    #[error("invalid tool ID: {0}")]
    InvalidToolId(String),

    #[error("schema validation failed: {0}")]
    SchemaValidationFailed(String),

    #[error("capability not found: {0}")]
    CapabilityNotFound(String),

    #[error("registry version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Result type for registry operations.
pub type RegistryResult<T> = Result<T, RegistryError>;
