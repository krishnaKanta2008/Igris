# Igris OS

Igris OS is a Linux-based, AI-native operating system environment. The Linux
kernel is the foundation; the project builds a progressively integrated AI
system layer on top of it, connected through structured tools and APIs and
governed by a least-privilege permission model.

> **Status: Milestone 6 (event observation) implemented.**
> The `igrisd` daemon, `igrisctl` client, default-deny permission engine,
> structured Unix-socket IPC with append-only audit logging, and the following
> tool families are functional:
>
> - **Core**: `system.info`
> - **Filesystem**: `fs.list`, `fs.stat`, `fs.read`, `fs.write`, `fs.delete`
> - **Process**: `process.list`, `process.stat`, `process.children`, `proc.signal`
> - **Event observation**: `events.watch`, `events.poll`, `events.unwatch`
>
> The event-observation protocol, stateful provider, and real filesystem event
> production via Linux inotify are implemented.
> Process event observation is not implemented.
> Streaming IPC is not implemented.
> The AI agent layer remains a Phase 0 scaffold.
> Process event observation is not implemented.
> Streaming IPC is not implemented.
> The AI agent layer remains a Phase 0 scaffold.

## Architecture

```
User
  ↓
Igris AI Agent                (Python — agent/)
  ↓
Permission / Security Layer   (Rust — core/igris-permd)
  ↓
Igris Core Services           (Rust — core/igrisd)
  ↓
Linux System Services         (procfs/sysfs, inotify/fanotify, cgroups, seccomp, D-Bus)
  ↓
Linux Kernel
  ↓
Hardware
```

### Design Principles

- The AI is never allowed to execute raw, generated shell commands directly.
- All system access happens through structured, individually permissioned tools.
- Default deny: an operation must be explicitly granted by policy.
- Dangerous operations require explicit user confirmation.
- Components are modular, and every important component is tested.

## What Works

### Core

- `igrisd` daemon and `igrisctl` client over a versioned Unix-socket protocol
- Default-deny permission broker (`igris-permd`)
- Append-only JSON Lines audit logging
- `system.info` — live kernel/system data from `/proc` and `/sys`

### Filesystem (confined to `IGRIS_FS_ROOT`)

- `fs.list` — list directory entries (bounded, sorted)
- `fs.stat` — file metadata (type, size, mode, uid/gid, timestamps)
- `fs.read` — read file contents (base64-encoded, bounded, truncation flag)
- `fs.write` — create or replace regular files (base64 content, confirmation required, path allow-list)
- `fs.delete` — remove regular files or symlinks (confirmation required, path allow-list, no directory deletion)
- Symlink containment: resolved targets must remain inside the canonical filesystem root

### Process Observation and Control

- `process.list` — bounded, PID-sorted snapshot of all processes
- `process.stat` — metadata for a single process (pid, ppid, name/comm, state, uid, gid, rss_kb)
- `process.children` — direct children of a process (not recursive descendants)
- `proc.signal` — deliver SIGTERM to a process (confirmation required, self-signaling rejected, OS permission enforced)
- All process data sourced from `/proc` only; no `cmdline`, `environ`, `exe`, `cwd`, `root`, fd lists, cgroups, or wchan exposed

### Event Observation (Infrastructure)

- `events.watch` — register a filesystem event watch on an absolute path within `IGRIS_FS_ROOT`; returns a `watch_id`
- `events.poll` — drain queued events from a watch (non-blocking, bounded by `max` and `MAX_POLL_EVENTS`)
- `events.unwatch` — remove a watch by `watch_id` (ownership enforced)
- Stateful event provider with connection-owned watches
- Bounded watch count (`MAX_EVENT_WATCHES = 16`)
- Bounded event queues (`MAX_QUEUED_EVENTS = 256` total, `MAX_EVENTS_PER_WATCH = 16` per watch)
- Permission gating via `IGRIS_EVENTS` environment variable
- Automatic cleanup of watches on connection disconnect

> **Not yet implemented:**
> - Process event observation
> - Streaming IPC / WebSocket-style event delivery
> - Event filtering, regex matching, or field projections
> - `igrisctl` commands for event operations

## Security Model

- **Default deny**: every operation must be explicitly granted by policy
- **Structured operations**: no raw shell execution, no generic file/process interfaces
- **Least privilege**: each tool family is a separate capability
- **Path confinement**: filesystem operations canonicalize and verify containment within `IGRIS_FS_ROOT`
- **Explicit confirmation**: `fs.write`, `fs.delete`, `proc.signal` require `confirm: true`
- **Explicit capabilities**:
  - Filesystem mutation: `IGRIS_WRITABLE_PATHS` + policy
  - Process control: `IGRIS_PROCESS_CONTROL` + policy
  - Event observation: `IGRIS_EVENTS` + policy
- **Audit logging**: one append-only JSON Lines record per request (timestamp, request id, operation, decision, coarse result, peer); no payloads or secrets logged

## Repository Layout

| Path | Language | Purpose |
| --- | --- | --- |
| `core/igrisd` | Rust | Core service daemon and privileged IPC/tool-routing boundary |
| `core/igris-permd` | Rust | Permission/policy broker implementing default-deny |
| `core/igrisctl` | Rust | Command-line client for the core service daemon |
| `agent/` | Python | AI agent layer: orchestration, planning, memory, model abstraction |
| `docs/` | Markdown | Architecture documentation and decision records (ADRs) |
| `scripts/` | Shell | Development and verification helper scripts |

## Development Environment

- Linux / WSL2 (development environment only)
- Rust (stable, pinned via `rust-toolchain.toml`), Cargo
- Python 3.10+
- GCC/CMake/pkg-config for native integration

WSL2 is a **development environment**, not the final Igris OS runtime. The
long-term goal is an installable Igris OS environment eventually delivered via
a VM, bootable image, or suitable hardware.

## Build and Test

```bash
# Rust workspace
cargo build --workspace
cargo test  --workspace
cargo fmt   --all -- --check
cargo clippy --workspace -- -D warnings

# Python agent package
python3 -m venv .venv && . .venv/bin/activate
pip install -e ./agent
python3 -m unittest discover -s agent/tests
```

## Quick Start

```bash
# Terminal 1: start the daemon (user-owned socket, no root)
./target/debug/igrisd

# Terminal 2: query it
./target/debug/igrisctl system.info
./target/debug/igrisctl system.info --json

# Filesystem tools (confined to IGRIS_FS_ROOT, default ~/.igris/share)
./target/debug/igrisctl fs.list --path ~/.igris/share
./target/debug/igrisctl fs.stat --path ~/.igris/share/some-file
./target/debug/igrisctl fs.read --path ~/.igris/share/some-file [--max-bytes N]

# Process observation
./target/debug/igrisctl process.list [--max N]
./target/debug/igrisctl process.stat --pid 1
./target/debug/igrisctl process.children --pid 1

# Process control (requires IGRIS_PROCESS_CONTROL=true at daemon start)
./target/debug/igrisctl proc.signal --pid 123 --confirm
```

> **Note:** `igrisctl` does not yet provide commands for `events.watch`,
> `events.poll`, or `events.unwatch`. These operations are available at the
> daemon protocol level and can be exercised via raw JSON requests.

Socket and audit paths default to the shared locations documented in
`docs/architecture/ipc-protocol.md` and can be overridden with
`IGRIS_SOCKET_PATH` and `IGRIS_AUDIT_LOG`.

## Configuration

The following environment variables control daemon behavior. All are optional
and have secure defaults (disabled unless explicitly enabled).

| Variable | Purpose | Default | Security Notes |
| --- | --- | --- | --- |
| `IGRIS_SOCKET_PATH` | Unix domain socket path | `$XDG_RUNTIME_DIR/igris/igrisd.sock` or `~/.igris/igrisd.sock` | Socket created `0600` in `0700` directory |
| `IGRIS_AUDIT_LOG` | Append-only audit log path | `$XDG_STATE_HOME/igris/audit.log` or `~/.local/state/igris/audit.log` | JSON Lines; no payloads or secrets |
| `IGRIS_FS_ROOT` | Canonical filesystem root for `fs.*` | `~/.igris/share` | All `fs.*` paths confined to this root |
| `IGRIS_WRITABLE_PATHS` | Colon-separated paths allowed for `fs.write`/`fs.delete` | (empty) | Must be subdirectories of `IGRIS_FS_ROOT`; enables mutation capability when non-empty |
| `IGRIS_PROCESS_CONTROL` | Enable `proc.signal` (truthy: not "0" or "false") | `false` | Requires policy grant (`milestone_five`/`milestone_six`) |
| `IGRIS_EVENTS` | Enable event observation `events.*` (truthy: not "0" or "false") | `false` | Requires policy grant (`milestone_six`) |

## Documentation

- Architecture overview: `docs/architecture/overview.md`
- IPC protocol specification: `docs/architecture/ipc-protocol.md`
- Development roadmap: `docs/roadmap.md`
- Decision records (ADRs): `docs/adr/`

## Roadmap Summary

The project follows an incremental, test-driven roadmap:

- **Phase 0** — Project foundation (complete)
- **Phase 1** — Trusted core IPC (Milestone 1, complete)
- **Phase 2** — Filesystem tools (Milestones 2–4, complete)
- **Phase 3** — Process observation (Milestone 3, complete) and control (Milestone 5, complete)
- **Phase 3 continued** — Event observation infrastructure (Milestone 6 skeleton, complete); real event production (in progress)
- **Phase 4** — AI agent layer (scaffold only)
- **Phase 5** — OS-level integration (systemd, D-Bus, seccomp, packaging)
- **Phase 6** — Installable Igris OS environment (VM, bootable image)

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

Copyright 2024-2025 Igris OS Contributors.