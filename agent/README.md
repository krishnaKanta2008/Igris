# igris-agent

The Python AI agent layer for Igris OS.

Phase 0 scaffold only. This package defines structure and contains no
planning, no model/LLM integration, and no tool orchestration yet.

The agent is intentionally kept separate from the privileged Rust core
(`core/`). It will communicate with the core only through a structured IPC
boundary, never by executing raw shell commands.
