# Igris OS

Igris OS is a Linux-based, AI-native operating system environment. The Linux
kernel is the foundation; the project builds a progressively integrated AI
system layer on top of it, connected through structured tools and APIs and
governed by a least-privilege permission model.

> **Status: Milestone 3 implemented.** The `igrisd` daemon, `igrisctl` client,
> default-deny permission engine, live `system.info`, read-only filesystem
> tools (`fs.list`, `fs.stat`, `fs.read`) confined to `IGRIS_FS_ROOT`, and
> read-only process observation (`process.list`, `process.stat`,
> `process.children`) over `/proc` are functional over a versioned
> Unix-socket protocol with append-only audit logging. The AI agent layer
> remains a Phase 0 scaffold.

## Canonical repository location

The canonical source tree lives **inside the WSL2 Linux filesystem** at:

```
~/projects/igris
```

A copy under `D:\projects krishna\igris` on Windows is a **non-canonical
convenience location** and must not be used as the primary build repository.
Rust builds are developed and run under WSL2 Ubuntu 22.04.

## Architecture (target)

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

Design principles:

- The AI is never allowed to execute raw, generated shell commands directly.
- All system access happens through structured, individually permissioned tools.
- Default deny: an operation must be explicitly granted by policy.
- Dangerous operations require explicit user confirmation.
- Components are modular, and every important component is tested.

## Repository layout

| Path | Language | Purpose |
| --- | --- | --- |
| `core/igrisd` | Rust | Core service daemon and privileged IPC/tool-routing boundary. |
| `core/igris-permd` | Rust | Permission/policy broker implementing default-deny. |
| `core/igrisctl` | Rust | Command-line client for the core service daemon. |
| `agent/` | Python | AI agent layer: orchestration, planning, memory, model abstraction. |
| `docs/` | Markdown | Architecture documentation and decision records (ADRs). |
| `scripts/` | Shell | Development and verification helper scripts. |

## Development environment

- WSL2 Ubuntu 22.04.3 LTS, x86_64 (development environment only).
- Rust (stable, pinned via `rust-toolchain.toml`), Cargo.
- Python 3.10+.
- GCC/CMake/pkg-config for native integration.

WSL2 is a **development environment**, not the final Igris OS runtime. The
long-term goal is an installable Igris OS environment eventually delivered via
a VM, bootable image, or suitable hardware.

## Build and test

```bash
# Rust workspace
cargo build --workspace
cargo test  --workspace
cargo fmt   --all -- --check
cargo clippy --workspace -- -D warnings

# Python agent package
python3 -m venv .venv && . .venv/bin/activate
pip install -e ./agent
python -m unittest discover -s agent/tests
```

## Milestone 1 quick start

```bash
# Terminal 1: start the daemon (user-owned socket, no root)
./target/debug/igrisd

# Terminal 2: query it
./target/debug/igrisctl system.info
./target/debug/igrisctl system.info --json

# Read-only filesystem tools (confined to IGRIS_FS_ROOT, default ~/.igris/share)
./target/debug/igrisctl fs.list --path ~/.igris/share
./target/debug/igrisctl fs.stat --path ~/.igris/share/some-file
./target/debug/igrisctl fs.read --path ~/.igris/share/some-file [--max-bytes N]

# Read-only process observation
./target/debug/igrisctl process.list [--max N]
./target/debug/igrisctl process.stat --pid 1
./target/debug/igrisctl process.children --pid 1
```

Socket and audit paths default to the shared locations documented in
`docs/architecture/ipc-protocol.md` and can be overridden with
`IGRIS_SOCKET_PATH` and `IGRIS_AUDIT_LOG`.

## Documentation

- Architecture: `docs/architecture/overview.md`
- IPC protocol: `docs/architecture/ipc-protocol.md`
- Roadmap: `docs/roadmap.md`
- Decision records: `docs/adr/`

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

Copyright 2024-2025 Igris OS Contributors.
