# 7. Filesystem boundary and read-only filesystem tools

- Status: Accepted
- Date: 2026-10-03
- Deciders: Igris OS Project

## Context

Milestone 1 deliberately exposed no filesystem capability: all system access
flowed through `system.info`, whose sources were fixed `/proc` and `/sys`
paths. Milestone 2 needs real filesystem introspection (`fs.list`, `fs.stat`,
`fs.read`) without turning `igrisd` into a general-purpose file server or a
privilege boundary escape hatch.

## Decision

- A single, configured filesystem root confines all `fs.*` operations:
  `IGRIS_FS_ROOT`, default `~/.igris/share` for the daemon's current user.
- Requests carry absolute paths. Before any filesystem access, the daemon
  canonicalizes the requested path (this follows symlinks and resolves `..`)
  and requires the resolved target to remain inside the canonical root.
  `.`/`..` are not rejected outright; only escapes of the boundary are.
  NUL-containing paths are rejected.
- Symlinks are followed. After resolution, the final target must still be
  inside the root; an escaping symlink is rejected. No no-follow parameter is
  exposed in this milestone.
- The tools are read-only. `fs.read` returns base64-encoded contents with a
  default cap of 64 KiB and a hard cap of 1 MiB, further clamped so the framed
  response stays within `MAX_RESPONSE_SIZE`. `fs.list` returns a bounded,
  name-sorted entry set: default 256, hard maximum 1024, with a `truncated`
  marker. `fs.stat` returns structured metadata (kind, size, mode, uid/gid,
  timestamps).
- Errors are sanitized: `path not found`, `permission denied`,
  `not a directory`, `invalid path`, `path escapes filesystem boundary`. Raw
  `std::io::Error` text and resolved host paths are never exposed in response
  payloads or audit records. Client-requested paths are echoed where a path
  field is required.
- The permission policy stays default-deny: `Policy::milestone_two()` grants
  exactly `system.info`, `fs.list`, `fs.stat`, `fs.read`. Permission checking
  remains separate from filesystem execution, and every request (accepted,
  denied, or rejected) is audited.
- TOCTOU: canonicalization and the subsequent `open`/`stat`/`read_dir` are
  separate syscalls, so a symlink swapped between them is a residual race.
  This is accepted for an unprivileged local daemon and documented rather than
  hidden; hardened resolution (`openat2`-style) is not introduced because the
  existing architecture does not need it for this threat level.

## Consequences

- All filesystem reads are confined to one audited, user-configured boundary.
- New filesystem capabilities require explicit policy grants and provider
  changes, never endpoint sprawl.
- Clients never learn the daemon's resolved host paths.
