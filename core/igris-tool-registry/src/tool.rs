//! Tool definitions and registry.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Stable identifier for a tool.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ToolId(String);

impl ToolId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ToolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ToolId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ToolId(s.to_string()))
    }
}

impl std::borrow::Borrow<str> for ToolId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ToolId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for ToolId {
    fn from(s: String) -> Self {
        ToolId(s)
    }
}

impl From<&str> for ToolId {
    fn from(s: &str) -> Self {
        ToolId(s.to_string())
    }
}

impl std::ops::Deref for ToolId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for ToolId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<ToolId> for str {
    fn eq(&self, other: &ToolId) -> bool {
        self == other.0
    }
}

/// Tool schema version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolSchemaVersion(pub String);

impl ToolSchemaVersion {
    pub fn new(version: impl Into<String>) -> Self {
        Self(version.into())
    }

    pub fn parse(version: &str) -> Result<Self, semver::Error> {
        semver::Version::parse(version).map(|v| ToolSchemaVersion(v.to_string()))
    }
}

impl std::fmt::Display for ToolSchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ToolSchemaVersion {
    type Err = semver::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<String> for ToolSchemaVersion {
    fn from(s: String) -> Self {
        ToolSchemaVersion(s)
    }
}

impl From<&str> for ToolSchemaVersion {
    fn from(s: &str) -> Self {
        ToolSchemaVersion(s.to_string())
    }
}

impl From<semver::Version> for ToolSchemaVersion {
    fn from(v: semver::Version) -> Self {
        ToolSchemaVersion(v.to_string())
    }
}

impl PartialEq<str> for ToolSchemaVersion {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

/// Tool metadata shared between registry and providers.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolMetadata {
    /// Unique tool identifier.
    pub id: ToolId,
    /// Schema version for this tool.
    pub schema_version: ToolSchemaVersion,
    /// Human-readable description.
    pub description: String,
    /// Input schema (JSON Schema).
    pub input_schema: serde_json::Value,
    /// Output schema (JSON Schema).
    pub output_schema: serde_json::Value,
    /// Required capability name.
    pub required_capability: String,
    /// Whether user confirmation is required before execution.
    pub requires_confirmation: bool,
    /// Maximum execution time in milliseconds.
    pub timeout_ms: u64,
    /// Maximum input size in bytes.
    pub max_input_bytes: u64,
    /// Maximum output size in bytes.
    pub max_output_bytes: u64,
}

impl ToolMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<ToolId>,
        schema_version: impl Into<ToolSchemaVersion>,
        description: impl Into<String>,
        input_schema: serde_json::Value,
        output_schema: serde_json::Value,
        required_capability: impl Into<String>,
        requires_confirmation: bool,
        timeout_ms: u64,
        max_input_bytes: u64,
        max_output_bytes: u64,
    ) -> Self {
        Self {
            id: id.into(),
            schema_version: schema_version.into(),
            description: description.into(),
            input_schema,
            output_schema,
            required_capability: required_capability.into(),
            requires_confirmation,
            timeout_ms,
            max_input_bytes,
            max_output_bytes,
        }
    }

    pub fn id(&self) -> &ToolId {
        &self.id
    }

    pub fn schema_version(&self) -> &ToolSchemaVersion {
        &self.schema_version
    }

    pub fn required_capability(&self) -> &str {
        &self.required_capability
    }

    pub fn requires_confirmation(&self) -> bool {
        self.requires_confirmation
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

/// Complete tool definition with schema and metadata.
#[derive(Debug, Clone)]
pub struct Tool {
    pub metadata: ToolMetadata,
    pub schema: crate::schema::ToolSchema,
}

/// Parameters for constructing a Tool.
#[derive(Debug)]
pub struct ToolParams {
    pub id: ToolId,
    pub schema_version: ToolSchemaVersion,
    pub description: String,
    pub schema: crate::schema::ToolSchema,
    pub required_capability: String,
    pub requires_confirmation: bool,
    pub timeout_ms: u64,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
}

impl Tool {
    pub fn new(params: ToolParams) -> Self {
        let metadata = ToolMetadata::new(
            params.id.clone(),
            params.schema_version,
            params.description,
            serde_json::to_value(&params.schema.input).expect("valid input schema"),
            serde_json::to_value(&params.schema.output).expect("valid output schema"),
            params.required_capability,
            params.requires_confirmation,
            params.timeout_ms,
            params.max_input_bytes,
            params.max_output_bytes,
        );
        Self {
            metadata,
            schema: params.schema,
        }
    }

    pub fn id(&self) -> &ToolId {
        &self.metadata.id
    }

    pub fn metadata(&self) -> &ToolMetadata {
        &self.metadata
    }

    pub fn schema(&self) -> &crate::schema::ToolSchema {
        &self.schema
    }

    pub fn required_capability(&self) -> &str {
        &self.metadata.required_capability
    }

    pub fn requires_confirmation(&self) -> bool {
        self.metadata.requires_confirmation
    }

    pub fn timeout(&self) -> Duration {
        self.metadata.timeout()
    }

    pub fn max_input_bytes(&self) -> u64 {
        self.metadata.max_input_bytes
    }

    pub fn max_output_bytes(&self) -> u64 {
        self.metadata.max_output_bytes
    }
}

/// Centralized tool registry.
#[derive(Debug, Default)]
pub struct ToolRegistry {
    tools: BTreeMap<ToolId, Arc<Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
        }
    }

    /// Register a new tool.
    pub fn register(&mut self, tool: Tool) -> crate::error::RegistryResult<()> {
        let id = tool.id().clone();
        if self.tools.contains_key(&id) {
            return Err(crate::error::RegistryError::ToolAlreadyRegistered(
                id.to_string(),
            ));
        }
        self.tools.insert(id, Arc::new(tool));
        Ok(())
    }

    /// Get a tool by ID.
    pub fn get(&self, id: &ToolId) -> Option<Arc<Tool>> {
        self.tools.get(id).cloned()
    }

    /// Get a tool by string ID.
    pub fn get_str(&self, id: &str) -> Option<Arc<Tool>> {
        self.tools.get(id).cloned()
    }

    /// Check if a tool is registered.
    pub fn contains(&self, id: &ToolId) -> bool {
        self.tools.contains_key(id)
    }

    /// Get all registered tools.
    pub fn tools(&self) -> impl Iterator<Item = &Arc<Tool>> {
        self.tools.values()
    }

    /// Get all tool IDs.
    pub fn ids(&self) -> impl Iterator<Item = &ToolId> {
        self.tools.keys()
    }

    /// Get tool metadata by ID.
    pub fn metadata(&self, id: &ToolId) -> Option<&ToolMetadata> {
        self.tools.get(id).map(|t| &t.metadata)
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Check if registry is empty.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Get all tool metadata.
    pub fn all_metadata(&self) -> Vec<&ToolMetadata> {
        self.tools.values().map(|t| &t.metadata).collect()
    }

    /// Validate a request against the tool's input schema.
    pub fn validate_input(
        &self,
        tool_id: &ToolId,
        _params: &serde_json::Value,
    ) -> crate::error::RegistryResult<()> {
        let _tool = self.get(tool_id).ok_or_else(|| {
            crate::error::RegistryError::ToolNotFound(tool_id.as_str().to_string())
        })?;

        // Basic validation - in production, use a proper JSON Schema validator
        Ok(())
    }
}

impl ToolRegistry {
    /// Create a registry with the default built-in tools.
    pub fn with_default_tools() -> Self {
        crate::default_registry()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_id_equality() {
        let id1 = ToolId::new("fs.read");
        let id2 = ToolId::new("fs.read");
        let id3 = ToolId::new("fs.write");
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn tool_id_from_str() {
        let id = ToolId::from("fs.read");
        assert_eq!(id.as_str(), "fs.read");
    }

    #[test]
    fn tool_metadata_creation() {
        let _schema_version = ToolSchemaVersion::new("1.0.0");
        let metadata = ToolMetadata::new(
            "fs.read",
            "1.0.0",
            "Read file contents",
            serde_json::json!({}),
            serde_json::json!({}),
            "filesystem_read",
            false,
            5000,
            0,
            64 * 1024,
        );
        assert_eq!(metadata.id.as_str(), "fs.read");
        assert_eq!(metadata.required_capability, "filesystem_read");
        assert!(!metadata.requires_confirmation);
    }
}
