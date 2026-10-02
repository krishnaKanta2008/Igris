# 3. Use Python for the AI agent layer

- Status: Accepted
- Date: 2026-10-03
- Deciders: Igris OS Project

## Context

The agent layer needs fast experimentation with planning, memory, and
model/provider integration. That work changes rapidly and is not on the
privileged security boundary.

## Decision

Implement the AI agent layer in Python. It is kept strictly separate from the
privileged Rust core and reaches the system only through structured tool calls
over the IPC boundary.

## Consequences

- Faster iteration on agent behaviour and model integration.
- Python carries no system privileges; the security guarantee lives in Rust.
- An explicit IPC contract is required between the two languages.
