# 5. Privilege separation and default-deny policy

- Status: Accepted
- Date: 2026-10-03
- Deciders: Igris OS Project

## Context

An AI-native OS must let an AI interact with files, processes, and system
services. Giving a model direct privilege or shell access is unacceptable: a
single bad decision could be destructive, and the failure is not reliably
predictable.

## Decision

Separate privileges by component and enforce a default-deny policy:

- The agent holds no system privileges and never executes raw shell commands.
- Every operation is a structured tool call mediated by `igris-permd`.
- Default deny: an operation succeeds only if an explicit policy rule grants it,
  with the least privilege needed.
- Dangerous operations require explicit, out-of-band user confirmation.
- All allow and deny decisions are written to an append-only audit log.

## Consequences

- A clear, auditable security boundary exists between the agent and the system.
- New capabilities require deliberate policy, not incidental permission.
- More explicit plumbing is required for each capability, by design.
