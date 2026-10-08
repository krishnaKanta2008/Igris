# 2. Use Rust for the privileged core services

- Status: Accepted
- Date: 2026-10-03
- Deciders: Igris OS Project

## Context

The privileged system layer (`igrisd`, `igris-permd`, tool providers) sits on a
security boundary and handles untrusted input from the AI agent. Memory-safety
defects here are especially costly because of the authority these components
hold.

## Decision

Implement the privileged core and the IPC/security boundary in Rust. Rust
provides memory safety without a garbage collector and yields single static
binaries suitable for a hardened system component.

## Consequences

- Memory-safety and data-race classes of bugs are largely eliminated.
- A single Rust toolchain is required and pinned via `rust-toolchain.toml`.
- C/C++ remains available where native or kernel integration requires it.
