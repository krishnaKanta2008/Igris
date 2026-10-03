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
`fs.read`, then `fs.write` and `fs.delete` as separate privilege-separated
providers, with path allow-lists, a dangerous-operation confirmation flow, and
an append-only audit log.

## Phase 3 — Process and event monitoring
`proc.list`, `proc.inspect`, guarded `proc.signal`, and an event provider using
inotify (later fanotify). Provider sandboxing via cgroups/namespaces/seccomp.

## Phase 4 — AI agent layer
Agent orchestration restricted to structured tool calls, per-session capability
tokens, a confirmation channel, and reasoning traces linked to audit records.

## Phase 5 — OS-level integration
systemd units, D-Bus interface, seccomp profiles, packaging, and an optional
QEMU-based VM image. Kernel-module work is evaluated here on evidence only.

## Phase 6 — Installable Igris OS environment
A deliverable environment via VM, bootable image, or suitable hardware.
