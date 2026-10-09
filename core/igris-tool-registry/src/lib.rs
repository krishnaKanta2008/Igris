//! Igris tool registry.
//!
//! This crate defines the centralized registry of all tools an AI agent may
//! invoke. Every tool has an explicit schema, metadata, and capability
//! requirements. The registry is immutable at runtime; new tools require a
//! new registry version and an ADR.

use std::collections::BTreeMap;

pub mod error;
pub mod schema;
pub mod tool;

pub use error::{RegistryError, RegistryResult};
pub use schema::{helpers, InputSchema, OutputSchema, ToolSchema};
pub use tool::{Tool, ToolId, ToolMetadata, ToolParams, ToolRegistry, ToolSchemaVersion};

/// Current registry version. Increment when tools are added/removed/changed.
pub const REGISTRY_VERSION: &str = "1.0.0";

/// Initialize the default tool registry with all built-in tools.
pub fn default_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();

    // system.info
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("system.info"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Returns live kernel/system information (hostname, kernel version, CPU, memory, uptime).".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object()),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("hostname".to_string(), helpers::string());
                    props.insert("kernel_release".to_string(), helpers::string());
                    props.insert("kernel_version".to_string(), helpers::string());
                    props.insert("architecture".to_string(), helpers::string());
                    props.insert(
                        "cpu".to_string(),
                        helpers::object_with_properties({
                            let mut cpu_props = BTreeMap::new();
                            cpu_props.insert("model".to_string(), helpers::integer_optional());
                            cpu_props.insert("logical_cores".to_string(), helpers::integer());
                            cpu_props
                        }),
                    );
                    props.insert(
                        "memory".to_string(),
                        helpers::object_with_properties({
                            let mut mem_props = BTreeMap::new();
                            mem_props.insert("total_kb".to_string(), helpers::integer());
                            mem_props.insert("free_kb".to_string(), helpers::integer());
                            mem_props.insert("available_kb".to_string(), helpers::integer());
                            mem_props
                        }),
                    );
                    props.insert("uptime_seconds".to_string(), helpers::number());
                    props
                },
                vec![
                    "hostname".to_string(),
                    "kernel_release".to_string(),
                    "kernel_version".to_string(),
                    "architecture".to_string(),
                    "cpu".to_string(),
                    "memory".to_string(),
                    "uptime_seconds".to_string(),
                ],
            )),
        ),
        required_capability: "system_info".to_string(),
        requires_confirmation: false,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 1024,
    }));

    // fs.list
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("fs.list"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Lists directory entries within the configured filesystem root.".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "path".to_string(),
                        helpers::string_with_desc("Absolute path within IGRIS_FS_ROOT"),
                    );
                    props.insert(
                        "max_entries".to_string(),
                        helpers::integer_with_bounds(1, 1024),
                    );
                    props
                },
                vec!["path".to_string()],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("path".to_string(), helpers::string());
                    props.insert(
                        "entries".to_string(),
                        helpers::array(helpers::object_with_properties({
                            let mut entry_props = BTreeMap::new();
                            entry_props.insert("name".to_string(), helpers::string());
                            entry_props.insert(
                                "kind".to_string(),
                                helpers::string_enum(vec![
                                    "directory".to_string(),
                                    "file".to_string(),
                                    "symlink".to_string(),
                                    "other".to_string(),
                                ]),
                            );
                            entry_props
                                .insert("size_bytes".to_string(), helpers::integer_optional());
                            entry_props
                        })),
                    );
                    props.insert("truncated".to_string(), helpers::boolean());
                    props
                },
                vec![
                    "path".to_string(),
                    "entries".to_string(),
                    "truncated".to_string(),
                ],
            )),
        ),
        required_capability: "filesystem_read".to_string(),
        requires_confirmation: false,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 64 * 1024,
    }));

    // fs.stat
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("fs.stat"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Returns metadata for a single filesystem entry.".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "path".to_string(),
                        helpers::string_with_desc("Absolute path within IGRIS_FS_ROOT"),
                    );
                    props
                },
                vec!["path".to_string()],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("path".to_string(), helpers::string());
                    props.insert(
                        "kind".to_string(),
                        helpers::string_enum(vec![
                            "directory".to_string(),
                            "file".to_string(),
                            "symlink".to_string(),
                            "other".to_string(),
                        ]),
                    );
                    props.insert("size_bytes".to_string(), helpers::integer());
                    props.insert("mode".to_string(), helpers::integer());
                    props.insert("uid".to_string(), helpers::integer());
                    props.insert("gid".to_string(), helpers::integer());
                    props.insert("modified_unix".to_string(), helpers::integer_optional());
                    props.insert("accessed_unix".to_string(), helpers::integer_optional());
                    props
                },
                vec![
                    "path".to_string(),
                    "kind".to_string(),
                    "size_bytes".to_string(),
                    "mode".to_string(),
                    "uid".to_string(),
                    "gid".to_string(),
                ],
            )),
        ),
        required_capability: "filesystem_read".to_string(),
        requires_confirmation: false,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 1024,
    }));

    // fs.read
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("fs.read"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Reads file contents as base64-encoded data.".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "path".to_string(),
                        helpers::string_with_desc("Absolute path within IGRIS_FS_ROOT"),
                    );
                    props.insert(
                        "max_bytes".to_string(),
                        helpers::integer_with_bounds(1, 1024 * 1024),
                    );
                    props
                },
                vec!["path".to_string()],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("path".to_string(), helpers::string());
                    props.insert("size_bytes".to_string(), helpers::integer());
                    props.insert("encoding".to_string(), helpers::string_const("base64"));
                    props.insert("data".to_string(), helpers::string());
                    props.insert("truncated".to_string(), helpers::boolean());
                    props
                },
                vec![
                    "path".to_string(),
                    "size_bytes".to_string(),
                    "encoding".to_string(),
                    "data".to_string(),
                    "truncated".to_string(),
                ],
            )),
        ),
        required_capability: "filesystem_read".to_string(),
        requires_confirmation: false,
        timeout_ms: 10000,
        max_input_bytes: 0,
        max_output_bytes: 1024 * 1024,
    }));

    // fs.write
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("fs.write"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Creates or replaces a regular file with base64-encoded content.".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "path".to_string(),
                        helpers::string_with_desc("Absolute path within IGRIS_FS_ROOT"),
                    );
                    props.insert(
                        "content_base64".to_string(),
                        helpers::string_with_desc("Base64-encoded file content"),
                    );
                    props.insert(
                        "max_bytes".to_string(),
                        helpers::integer_with_bounds(1, 1024 * 1024),
                    );
                    props.insert("confirm".to_string(), helpers::boolean_const(true));
                    props
                },
                vec![
                    "path".to_string(),
                    "content_base64".to_string(),
                    "confirm".to_string(),
                ],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("path".to_string(), helpers::string());
                    props.insert("size_bytes".to_string(), helpers::integer());
                    props.insert("overwritten".to_string(), helpers::boolean());
                    props
                },
                vec![
                    "path".to_string(),
                    "size_bytes".to_string(),
                    "overwritten".to_string(),
                ],
            )),
        ),
        required_capability: "filesystem_write".to_string(),
        requires_confirmation: true,
        timeout_ms: 10000,
        max_input_bytes: 0,
        max_output_bytes: 1024 * 1024,
    }));

    // fs.delete
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("fs.delete"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Deletes a regular file or symlink. Directories are never deleted."
            .to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "path".to_string(),
                        helpers::string_with_desc("Absolute path within IGRIS_FS_ROOT"),
                    );
                    props.insert("confirm".to_string(), helpers::boolean_const(true));
                    props
                },
                vec!["path".to_string(), "confirm".to_string()],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("path".to_string(), helpers::string());
                    props.insert("deleted".to_string(), helpers::boolean_const(true));
                    props
                },
                vec!["path".to_string(), "deleted".to_string()],
            )),
        ),
        required_capability: "filesystem_write".to_string(),
        requires_confirmation: true,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 1024,
    }));

    // process.list
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("process.list"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Returns a bounded, PID-sorted snapshot of all visible processes.".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties({
                let mut props = BTreeMap::new();
                props.insert("max".to_string(), helpers::integer_with_bounds(1, 512));
                props
            })),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "entries".to_string(),
                        helpers::array(helpers::object_with_properties({
                            let mut entry_props = BTreeMap::new();
                            entry_props.insert("pid".to_string(), helpers::integer());
                            entry_props.insert("ppid".to_string(), helpers::integer());
                            entry_props.insert("name".to_string(), helpers::string());
                            entry_props.insert("state".to_string(), helpers::string());
                            entry_props.insert("uid".to_string(), helpers::integer());
                            entry_props.insert("gid".to_string(), helpers::integer());
                            entry_props.insert("rss_kb".to_string(), helpers::integer_optional());
                            entry_props
                        })),
                    );
                    props.insert("truncated".to_string(), helpers::boolean());
                    props
                },
                vec!["entries".to_string(), "truncated".to_string()],
            )),
        ),
        required_capability: "process_read".to_string(),
        requires_confirmation: false,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 64 * 1024,
    }));

    // process.stat
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("process.stat"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Returns metadata for a single process by PID.".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "pid".to_string(),
                        helpers::integer_with_bounds(1, 4_000_000),
                    );
                    props
                },
                vec!["pid".to_string()],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("pid".to_string(), helpers::integer());
                    props.insert("ppid".to_string(), helpers::integer());
                    props.insert("name".to_string(), helpers::string());
                    props.insert("state".to_string(), helpers::string());
                    props.insert("uid".to_string(), helpers::integer());
                    props.insert("gid".to_string(), helpers::integer());
                    props.insert("rss_kb".to_string(), helpers::integer_optional());
                    props
                },
                vec![
                    "pid".to_string(),
                    "ppid".to_string(),
                    "name".to_string(),
                    "state".to_string(),
                    "uid".to_string(),
                    "gid".to_string(),
                ],
            )),
        ),
        required_capability: "process_read".to_string(),
        requires_confirmation: false,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 1024,
    }));

    // process.children
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("process.children"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Returns direct children of a process (not recursive descendants)."
            .to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "pid".to_string(),
                        helpers::integer_with_bounds(1, 4_000_000),
                    );
                    props.insert("max".to_string(), helpers::integer_with_bounds(1, 512));
                    props
                },
                vec!["pid".to_string()],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("parent_pid".to_string(), helpers::integer());
                    props.insert(
                        "entries".to_string(),
                        helpers::array(helpers::object_with_properties({
                            let mut entry_props = BTreeMap::new();
                            entry_props.insert("pid".to_string(), helpers::integer());
                            entry_props.insert("ppid".to_string(), helpers::integer());
                            entry_props.insert("name".to_string(), helpers::string());
                            entry_props.insert("state".to_string(), helpers::string());
                            entry_props.insert("uid".to_string(), helpers::integer());
                            entry_props.insert("gid".to_string(), helpers::integer());
                            entry_props.insert("rss_kb".to_string(), helpers::integer_optional());
                            entry_props
                        })),
                    );
                    props.insert("truncated".to_string(), helpers::boolean());
                    props
                },
                vec![
                    "parent_pid".to_string(),
                    "entries".to_string(),
                    "truncated".to_string(),
                ],
            )),
        ),
        required_capability: "process_read".to_string(),
        requires_confirmation: false,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 1024,
    }));

    // proc.signal
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("proc.signal"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Sends SIGTERM (15) to a process. Requires confirmation.".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "pid".to_string(),
                        helpers::integer_with_bounds(1, 4_000_000),
                    );
                    props.insert("signal".to_string(), helpers::integer_const(15));
                    props.insert("confirm".to_string(), helpers::boolean_const(true));
                    props
                },
                vec![
                    "pid".to_string(),
                    "signal".to_string(),
                    "confirm".to_string(),
                ],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("sent".to_string(), helpers::boolean_const(true));
                    props
                },
                vec!["sent".to_string()],
            )),
        ),
        required_capability: "process_control".to_string(),
        requires_confirmation: true,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 1024,
    }));

    // events.watch
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("events.watch"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Registers a filesystem event watch on a path within IGRIS_FS_ROOT."
            .to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "path".to_string(),
                        helpers::string_with_desc("Absolute path within IGRIS_FS_ROOT to watch"),
                    );
                    props
                },
                vec!["path".to_string()],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("watch_id".to_string(), helpers::integer_with_bounds(1, 16));
                    props
                },
                vec!["watch_id".to_string()],
            )),
        ),
        required_capability: "event_observation".to_string(),
        requires_confirmation: false,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 1024,
    }));

    // events.poll
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("events.poll"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Drains queued events from a watch.".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("watch_id".to_string(), helpers::integer_with_bounds(1, 16));
                    props.insert("max".to_string(), helpers::integer_with_bounds(1, 128));
                    props
                },
                vec!["watch_id".to_string()],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert(
                        "events".to_string(),
                        helpers::array(helpers::object_with_properties({
                            let mut event_props = BTreeMap::new();
                            event_props.insert("name".to_string(), helpers::string());
                            event_props.insert("path".to_string(), helpers::string());
                            event_props.insert("timestamp_unix".to_string(), helpers::integer());
                            event_props.insert("kind".to_string(), helpers::integer_optional());
                            event_props
                        })),
                    );
                    props
                },
                vec!["events".to_string()],
            )),
        ),
        required_capability: "event_observation".to_string(),
        requires_confirmation: false,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 1024,
    }));

    // events.unwatch
    let _ = registry.register(Tool::new(ToolParams {
        id: ToolId::new("events.unwatch"),
        schema_version: ToolSchemaVersion::new("1.0.0"),
        description: "Removes a filesystem event watch by its ID.".to_string(),
        schema: ToolSchema::new(
            InputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("watch_id".to_string(), helpers::integer_with_bounds(1, 16));
                    props
                },
                vec!["watch_id".to_string()],
            )),
            OutputSchema(helpers::object_with_properties_and_required(
                {
                    let mut props = BTreeMap::new();
                    props.insert("success".to_string(), helpers::boolean_const(true));
                    props
                },
                vec!["success".to_string()],
            )),
        ),
        required_capability: "event_observation".to_string(),
        requires_confirmation: false,
        timeout_ms: 5000,
        max_input_bytes: 0,
        max_output_bytes: 1024,
    }));

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_all_tools() {
        let registry = default_registry();
        assert!(registry.get_str("system.info").is_some());
        assert!(registry.get_str("fs.list").is_some());
        assert!(registry.get_str("fs.stat").is_some());
        assert!(registry.get_str("fs.read").is_some());
        assert!(registry.get_str("fs.write").is_some());
        assert!(registry.get_str("fs.delete").is_some());
        assert!(registry.get_str("process.list").is_some());
        assert!(registry.get_str("process.stat").is_some());
        assert!(registry.get_str("process.children").is_some());
        assert!(registry.get_str("proc.signal").is_some());
        assert!(registry.get_str("events.watch").is_some());
        assert!(registry.get_str("events.poll").is_some());
        assert!(registry.get_str("events.unwatch").is_some());
        assert_eq!(registry.tools().count(), 13);
    }

    #[test]
    fn fs_write_requires_confirmation() {
        let registry = default_registry();
        let tool = registry.get_str("fs.write").unwrap();
        assert!(tool.requires_confirmation());
        assert_eq!(tool.required_capability(), "filesystem_write");
    }

    #[test]
    fn proc_signal_requires_confirmation() {
        let registry = default_registry();
        let tool = registry.get_str("proc.signal").unwrap();
        assert!(tool.requires_confirmation());
        assert_eq!(tool.required_capability(), "process_control");
    }

    #[test]
    fn fs_delete_requires_confirmation() {
        let registry = default_registry();
        let tool = registry.get_str("fs.delete").unwrap();
        assert!(tool.requires_confirmation());
        assert_eq!(tool.required_capability(), "filesystem_write");
    }

    #[test]
    fn unknown_tool_rejected() {
        let registry = default_registry();
        assert!(registry.get_str("unknown.tool").is_none());
    }

    #[test]
    fn tool_schemas_are_valid() {
        let registry = default_registry();
        for tool in registry.tools() {
            // Input schema should be valid JSON Schema
            let input_schema =
                serde_json::to_value(&tool.schema.input).expect("valid input schema");
            assert!(input_schema.is_object());

            // Output schema should be valid JSON Schema
            let output_schema =
                serde_json::to_value(&tool.schema.output).expect("valid output schema");
            assert!(output_schema.is_object());
        }
    }
}
