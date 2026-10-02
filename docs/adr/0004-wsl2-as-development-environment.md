# 4. Use WSL2 Ubuntu 22.04 as the development environment

- Status: Accepted
- Date: 2026-10-03
- Deciders: Igris OS Project

## Context

Development currently happens on a Windows 11 host. Igris OS targets Linux and
requires real Linux facilities (procfs, sysfs, inotify/fanotify, cgroups,
seccomp, D-Bus). A native Linux environment is therefore required for correct
development and testing.

## Decision

Use WSL2 Ubuntu 22.04.3 LTS on x86_64 as the canonical development environment,
with the canonical repository at `~/projects/igris`. WSL2 is a **development
environment only**; the WSL2 kernel is used unchanged and is not customised for
Phases 0–4.

## Consequences

- Real Linux APIs are available for development and testing.
- The final deliverable (VM, bootable image, or hardware) is separate and later.
- Kernel-module work is deferred to Phase 5 and evaluated on evidence.
