//! JSON Schema definitions for tool inputs and outputs.
//!
//! This module provides a simplified wrapper using serde_json::Value for
//! defining tool input and output schemas.

use serde::{Deserialize, Serialize};

/// JSON Schema for tool input validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InputSchema(pub serde_json::Value);

/// JSON Schema for tool output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OutputSchema(pub serde_json::Value);

/// Combined tool schema (input + output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub input: InputSchema,
    pub output: OutputSchema,
}

impl ToolSchema {
    pub fn new(input: InputSchema, output: OutputSchema) -> Self {
        Self { input, output }
    }
}

/// Helper functions for building common schemas.
pub mod helpers {
    use serde_json::json;
    use std::collections::BTreeMap;

    // String schemas
    pub fn string() -> serde_json::Value {
        json!({"type": "string"})
    }

    pub fn string_with_desc(desc: impl Into<String>) -> serde_json::Value {
        json!({"type": "string", "description": desc.into()})
    }

    pub fn string_const(value: &str) -> serde_json::Value {
        json!({"type": "string", "const": value})
    }

    pub fn string_enum(values: Vec<String>) -> serde_json::Value {
        json!({"type": "string", "enum": values})
    }

    // Integer schemas
    pub fn integer() -> serde_json::Value {
        json!({"type": "integer"})
    }

    pub fn integer_with_bounds(min: i64, max: i64) -> serde_json::Value {
        json!({"type": "integer", "minimum": min, "maximum": max})
    }

    // Use minimum=maximum to simulate const for integers
    pub fn integer_const(value: i64) -> serde_json::Value {
        json!({"type": "integer", "minimum": value, "maximum": value})
    }

    pub fn integer_optional() -> serde_json::Value {
        json!({"type": "integer"})
    }

    // Number (float) schemas
    pub fn number() -> serde_json::Value {
        json!({"type": "number"})
    }

    // Boolean schemas
    pub fn boolean() -> serde_json::Value {
        json!({"type": "boolean"})
    }

    pub fn boolean_const(value: bool) -> serde_json::Value {
        json!({"type": "boolean", "const": value})
    }

    // Array schemas
    pub fn array(items: serde_json::Value) -> serde_json::Value {
        json!({"type": "array", "items": items})
    }

    // Object schemas
    pub fn object() -> serde_json::Value {
        json!({"type": "object", "additionalProperties": false})
    }

    pub fn object_with_properties(props: BTreeMap<String, serde_json::Value>) -> serde_json::Value {
        let mut obj = json!({"type": "object", "additionalProperties": false, "properties": {}});
        if let Some(props_val) = obj.get_mut("properties") {
            *props_val = json!(props);
        }
        obj
    }

    pub fn object_with_properties_and_required(
        props: BTreeMap<String, serde_json::Value>,
        required: Vec<String>,
    ) -> serde_json::Value {
        let mut obj = json!({"type": "object", "additionalProperties": false, "properties": {}, "required": required});
        if let Some(props_val) = obj.get_mut("properties") {
            *props_val = json!(props);
        }
        obj
    }

    pub fn integer_optional_with_bounds(min: i64, max: i64) -> serde_json::Value {
        json!({"type": "integer", "minimum": min, "maximum": max})
    }
}
