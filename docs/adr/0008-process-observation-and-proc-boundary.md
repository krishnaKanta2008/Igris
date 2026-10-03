# 8. Process observation over /proc with a same-user, unprivileged boundary

- Status: Accepted
- Date: 2026-10-03
- Deciders: Igris OS Project

## Context

Milestone 1 exposed `system.info`; Milestone 2 added read-only filesystem
tools under a canonical root. Milestone 3 needs equivalent *process*
observation (`process.list`, `process.stat`, `process.children`) without
process control capabilities and without leaking host details. Milestone 4
(agent layer) is not part of this decision.

## Decision

- The only data source is `/proc`: `/proc/<pid>/stat` for pid, comm, state,
  and ppid; `/proc/<pid>/status` for Uid, Gid, and VmRSS. `comm` is parsed
  after the last `)` to tolerate spaces and parentheses. Directory
  enumeration skips numeric entries that vanish or fail to parse.
- The exposed `ProcessEntry` is exactly: `pid`, `ppid`, `name` (kernel
  `comm`), `state`, `uid`, `gid`, `rss_kb` (nullable). Nothing else:
  `/proc/<pid>/cmdline`, `environ`, `exe`, `cwd`, `root`, fd lists, cgroups,
  wchan, and scheduler/syscall internals are never read or exposed.
- `pid` parameters are integers in `1..=4,000,000`; `max` parameters are
  positive integers up to 512 (default 128). A missing/exited process yields
  a sanitized `NOT_FOUND` ("process not found"); unreadable processes are
  skipped in enumerations and reported only as a sanitized provider error
  for `process.stat`.
- `process.children` returns direct children only (entries whose ppid equals
  the requested pid), pid-sorted, bounded, and marked `truncated`; it never
  returns recursive descendants.
- The tools are read-only and run in the daemon's own (unprivileged) user
  context: visibility is exactly what the invoking user can see in `/proc`
  (subject to `hidepid`, other-user processes, etc.). No killing, starting,
  stopping, or executing processes is added.
- Every `/proc` scan is O(number of processes); result bounds cap output,
  not scan cost. This is accepted for a single-user local daemon and is not
  claimed as bounded work.
- Authorization stays default-deny via `Policy::milestone_three()` covering
  exactly the seven operations in scope. Audit behavior is unchanged: one
  JSON-Lines record per request, with no command lines, environments,
  filesystem paths, or process payloads recorded.
- `events.subscribe` (inotify/fanotify-style streaming) is intentionally out
  of scope for this milestone because subscriptions are long-lived stateful
  streams, whereas the current request/response framing handles one response
  per request. A future milestone will define that IPC model separately.

## Consequences

- Process introspection rides the same validated, default-deny, audited
  pipeline as the rest of the core.
- Privacy posture is explicit and testable: integration tests assert that no
  sensitive fields appear in payloads, and audit rows never contain process
  data.
- A future event milestone must add a subscription-aware framing model and
  its own ADR rather than overloading this one.
