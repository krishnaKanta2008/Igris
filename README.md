# Igris OS

Igris OS is a Linux-based, AI-native operating system environment. The Linux
kernel is the foundation; the project builds a progressively integrated AI
system layer on top of it, connected through structured tools and APIs and
governed by a least-privilege permission model.

> **Status: Phase 0 (project foundation).** No system functionality is
> implemented yet. This repository currently contains only scaffolding,
> documentation, and build configuration.

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

## Build and test (Phase 0 scaffold)

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

## Documentation

- Architecture: `docs/architecture/overview.md`
- Roadmap: `docs/roadmap.md`
- Decision records: `docs/adr/`

## License

Not yet decided. No license file is included at this stage.
