# Development Roadmap

This roadmap is incremental. Each phase is tested before the next begins, and
working code is not rewritten without reason.

## Phase 0 — Project foundation (complete)
Repository, build configuration, component scaffolding, documentation, and
decision records. No functionality.

## Phase 1 — Trusted core (complete, Milestone 1)
`igrisd` daemon and `igrisctl` client over a versioned Unix-socket protocol; a
default-deny policy broker; and one real tool (`system.info`) reading live
kernel/system data from `/proc` and `/sys`. End-to-end tests.

## Phase 2 — Filesystem tools
Milestone 2 (complete): read-only `fs.list`, `fs.stat`, `fs.read` confined to a
canonical `IGRIS_FS_ROOT` boundary with symlink containment, bounded output,
sanitized errors, and audit. Remaining: `fs.write`/`fs.delete` as separate
privilege-separated providers with path allow-lists, a dangerous-operation
confirmation flow, and append-only audit logging.

## Phase 3 — Process and event monitoring
Milestone 3 (complete): read-only `process.list`, `process.stat`, and
`process.children` over `/proc` with bounded, sanitized output and full audit.
Remaining: guarded process control (`proc.signal`), an event provider via
inotify/fanotify (separate milestone with a stateful IPC model), and provider
sandboxing via cgroups/namespaces/seccomp.

## Phase 4 — AI agent layer
Agent orchestration restricted to structured tool calls, per-session capability
tokens, a confirmation channel, and reasoning traces linked to audit records.

## Phase 5 — OS-level integration
systemd units, D-Bus interface, seccomp profiles, packaging, and an optional
QEMU-based VM image. Kernel-module work is evaluated here on evidence only.

## Phase 6 — Installable Igris OS environment
A deliverable environment via VM, bootable image, or suitable hardware.
