# 6. Unix-socket IPC boundary with versioned, bounded protocol and append-only audit

- Status: Accepted
- Date: 2026-10-03
- Deciders: Igris OS Project

## Context

ADR 0005 established privilege separation and default-deny policy, but left the
client↔daemon boundary unspecified. The trusted core still had to decide how
untrusted bytes from IPC clients are framed, validated, authorized, executed,
and accounted for, without ever becoming a general-purpose command execution
surface.

## Decision

- `igrisctl` clients and `igrisd` communicate over a user-owned Unix domain
  socket (`0600` socket, `0700` directory). No network listener, no root.
- Wire format: 4-byte big-endian length prefix + UTF-8 JSON payload, versioned
  (`version: 1`), with request ids, an explicit operation name, and a `params`
  object. Requests are capped at 64 KiB and responses at 1 MiB; oversized
  frames are rejected before the body is read.
- The daemon's pipeline is fixed and narrow: frame/size check → JSON parse →
  schema validation → default-deny policy evaluation (`igris-permd`) →
  dispatch to a narrowly scoped provider → one audit record per request.
- Providers accept no caller-supplied paths and expose exactly one capability
  (`system.info` in Milestone 1). There is no shell execution and no generic
  file-read or process interface.
- Every accepted and rejected request is appended to a JSON Lines audit log
  that stores decisions and coarse outcomes, never payloads or secrets.

## Consequences

- The IPC boundary is auditable, testable, and safe by default: malformed and
  oversized input is rejected deterministically.
- New capabilities require a new provider plus an explicit policy grant and
  audit coverage, not ad-hoc endpoints.
- Clients must carry the protocol version; incompatible clients fail with a
  structured error rather than undefined behavior.
