# Architecture Decision Records (ADRs)

This directory records significant architectural decisions for Igris OS. Each
record is short, dated, and immutable once accepted; superseding a decision
means adding a new ADR that references the old one.

Format: lightweight [MADR](https://adr.github.io/madr/).

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-use-rust-for-core-services.md) | Use Rust for the privileged core services | Accepted |
| [0003](0003-use-python-for-agent-layer.md) | Use Python for the AI agent layer | Accepted |
| [0004](0004-wsl2-as-development-environment.md) | Use WSL2 Ubuntu 22.04 as the development environment | Accepted |
| [0005](0005-privilege-separation-and-default-deny.md) | Privilege separation and default-deny policy | Accepted |
| [0006](0006-unix-socket-ipc-boundary.md) | Unix-socket IPC boundary, versioned bounded protocol, audit | Accepted |
| [0007](0007-filesystem-boundary-and-read-only-tools.md) | Filesystem boundary and read-only filesystem tools | Accepted |
| [0008](0008-process-observation-and-proc-boundary.md) | Process observation and /proc boundary | Accepted |
| [0009](0009-agent-tool-calling-and-sandboxing.md) | AI Agent tool calling with sandboxed providers, session capabilities, and confirmation gate | Proposed |
