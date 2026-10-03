# Architecture Overview

This document describes the target architecture of Igris OS and the current
implementation status. It is intentionally high level; concrete interfaces and
protocols are specified in later phases and recorded as ADRs.

## Layered model

```
User
 ↓
Igris AI Agent                (Python)     [scaffold, not wired to core]
 ↓
Permission / Security Layer   (Rust)       [Milestone 1: default-deny engine]
 ↓
Igris Core Services           (Rust)       [Milestones 1-2: IPC daemon, fs tools]
 ↓
Linux System Services                       [available, unused]
 ↓
Linux Kernel                                [stock kernel]
 ↓
Hardware
```

## Component responsibilities

### Igris AI Agent (`agent/`, Python)
High-level orchestration, planning, memory, and model/provider abstraction. The
agent's only route to the system is structured tool calls submitted to the core
service boundary. It does not run shell commands and does not hold privileges.

### Permission / Security Layer (`core/igris-permd`, Rust)
Evaluates every requested operation against a default-deny policy. Grants are
explicit and least-privilege. Dangerous operations additionally require an
out-of-band, explicit user confirmation. All decisions (allow and deny) are
written to an append-only audit log.

### Igris Core Services (`core/igrisd`, Rust)
The privileged IPC hub. It exposes a versioned, structured protocol over a Unix
domain socket, routes tool calls to providers, and enforces timeouts and quotas.
It never exposes an arbitrary shell.

### Tool providers (Rust, introduced in later phases)
Each provider is a separate, minimally privileged process exposing one narrow
capability (for example filesystem read, process inspection, system
information). Providers are individually permissioned and independently tested.

### Linux System Services and Kernel
Igris builds on real, existing Linux facilities (procfs, sysfs, inotify and
fanotify, cgroups, seccomp, netlink, D-Bus, systemd). The WSL2 kernel is used
unchanged during development; kernel modifications are not in scope for
Phases 0–4.

## Trust boundaries

1. **Agent → Core:** untrusted input crossing an IPC boundary. Structured,
   validated, versioned messages only.
2. **Core → Permission layer:** every privileged operation is mediated.
3. **Permission layer → Providers:** providers receive only the minimum
   authority required for a single granted operation.

## Current status

Phase 0 established the repository foundation. Milestone 1 implements the
trusted core: `igrisd` serves a versioned, length-framed JSON protocol over a
user-owned Unix socket (see `docs/architecture/ipc-protocol.md`), `igris-permd`
applies a default-deny policy, `system.info` reads live kernel/system data from
`/proc` and `/sys`, and every request produces one append-only audit record.
Milestone 2 adds read-only filesystem tools (`fs.list`, `fs.stat`, `fs.read`)
confined to a canonical `IGRIS_FS_ROOT` boundary (see ADR 0007). The Python
agent remains a Phase 0 scaffold and is not yet wired to the core.
