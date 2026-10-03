# Igris IPC Protocol (Milestone 1)

This document is the specification for the client/daemon boundary between
`igrisctl` (and future clients) and `igrisd`. The wire behavior is implemented
in `core/igris-proto` and exercised by the unit and integration tests.

## Transport

- Unix domain socket, stream semantics.
- Socket path resolution: `$IGRIS_SOCKET_PATH`, otherwise
  `$XDG_RUNTIME_DIR/igris/igrisd.sock` when set, otherwise
  `~/.igris/igrisd.sock`. Client and daemon share `igris_proto::default_socket_path()`.
- The socket file is created `0600` inside a `0700` directory: only the owning
  user may connect. The daemon runs with the privileges of its invoking user;
  no root is required or used.
- One client may send a sequence of requests on a single connection; each
  request receives exactly one response, in order.

## Framing

Each message is:

```
+-------------------------------+---------------------------+
| length: u32 (big-endian, 4 B) | JSON payload (length B)   |
+-------------------------------+---------------------------+
```

- The payload is UTF-8 JSON.
- Requests are limited to 64 KiB (`MAX_REQUEST_SIZE`). A frame whose declared
  length exceeds this is rejected deterministically *before* the body is read,
  with an error response; the connection is then closed because the stream
  cannot be resynchronised.
- Responses are limited to 1 MiB (`MAX_RESPONSE_SIZE`).

## Request schema

```json
{
  "version": 1,
  "id": "req-123",
  "op": "system.info",
  "params": {}
}
```

- `version` (u16): must equal the daemon's protocol version (`1`). Any other
  value is rejected with `UNSUPPORTED_VERSION`.
- `id` (string): non-empty, at most 128 bytes, no control characters. The id
  is echoed in the response and recorded in the audit log.
- `op` (string): one of the supported operations: `system.info`,
  `fs.list`, `fs.stat`, `fs.read`, `process.list`, `process.stat`,
  `process.children`. Unknown operations are rejected with
  `UNKNOWN_OPERATION`.
- `params` (object): must be a JSON object. `system.info` takes no required
  fields; the `fs.*` operations require their own parameters (below), which
  are validated per operation (`validate_operation_params`).

## Response schema

Success:

```json
{
  "version": 1,
  "id": "req-123",
  "ok": true,
  "result": { "hostname": "...", "...": "..." }
}
```

Error:

```json
{
  "version": 1,
  "id": "req-123",
  "ok": false,
  "error": { "code": "DENIED", "message": "operation \"fs.write\" denied by policy" }
}
```

`id` is `null` when the request id could not be used (parse failure, oversize).

### Error codes

| Code | Meaning |
| --- | --- |
| `BAD_REQUEST` | Malformed JSON, schema violation, bad id, non-object params |
| `UNSUPPORTED_VERSION` | Protocol version mismatch |
| `UNKNOWN_OPERATION` | Operation not in the supported list |
| `DENIED` | Operation rejected by the default-deny policy |
| `TOO_LARGE` | Declared frame length exceeds the limit |
| `NOT_FOUND` | The requested filesystem path does not exist |
| `FS_ERROR` | Filesystem failure with a sanitized message |
| `INTERNAL` | Provider failed to execute an allowed operation |

## Filesystem boundary

All `fs.*` operations are confined to a single canonical filesystem root:
`IGRIS_FS_ROOT`, default `~/.igris/share`. For every request the daemon
canonicalizes the requested absolute path (following symlinks) and requires
the resolved target to remain inside the canonical root. Paths that escape —
via `..`, an outside absolute path, or a symlink — are rejected with
`BAD_REQUEST` (`path escapes filesystem boundary`) and audited as denied.
Result payloads and audit records echo the client-requested path; the resolved
host path is never exposed.

## `fs.list`

Params: `{ "path": string, "max_entries"?: number }` — `max_entries`
defaults to 256, hard maximum 1024.

```json
{ "path": "...", "entries": [{ "name": "...", "kind": "file", "size_bytes": 12 }], "truncated": false }
```

`entries` is sorted by name; `kind` is `directory`/`file`/`symlink`/`other`;
`size_bytes` may be `null` when unavailable; `truncated` reports that a limit
cut the listing short.

## `fs.stat`

Params: `{ "path": string }`.

```json
{ "path": "...", "kind": "file", "size_bytes": 12, "mode": 420, "uid": 1000, "gid": 1000, "modified_unix": 1696000000, "accessed_unix": 1696000000 }
```

Symlinks are followed; the result describes the final target.

## `fs.read`

Params: `{ "path": string, "max_bytes"?: number }` — `max_bytes` defaults to
64 KiB, hard maximum 1 MiB. The effective cap also ensures the base64-encoded
result fits the 1 MiB `MAX_RESPONSE_SIZE` frame limit.

```json
{ "path": "...", "size_bytes": 12, "encoding": "base64", "data": "...", "truncated": false }
```

Binary-safe: contents are base64-encoded.

## Process observation

All `process.*` operations are read-only. Data comes from
`/proc/<pid>/stat` (pid, comm, state, ppid) and `/proc/<pid>/status`
(Uid, Gid, VmRSS). Scanning `/proc` is O(number of processes) per request;
result sizes are bounded. Processes that disappear mid-scan are skipped.
`name` is the kernel `comm` only; `cmdline`, `environ`, `exe`, `cwd`, `root`,
fds, cgroups, and wchan are never read or exposed.

`ProcessEntry`:

```json
{ "pid": 123, "ppid": 456, "name": "igrisd", "state": "S", "uid": 1000, "gid": 1000, "rss_kb": 2048 }
```

`rss_kb` is `null` when unavailable.

### `process.list`

Params: `{ "max"?: number }` — default 128, hard maximum 512. Result:
`{ "entries": [ProcessEntry], "truncated": bool }`, sorted by pid.

### `process.stat`

Params: `{ "pid": number }` — integer, `1 <= pid <= 4000000`. Result:
`ProcessEntry`. A missing/exited process yields `NOT_FOUND`
(`process not found`).

### `process.children`

Params: `{ "pid": number, "max"?: number }` — same defaults/bounds as
`process.list`. Result: `{ "parent_pid": number, "entries": [ProcessEntry],
"truncated": bool }`. Only direct children are returned (entries whose
ppid equals the requested pid), never recursive descendants.

## `system.info` result

```json
{
  "hostname": "...",
  "kernel_release": "...",
  "kernel_version": "...",
  "architecture": "...",
  "cpu": { "model": "...", "logical_cores": 16 },
  "memory": { "total_kb": 0, "free_kb": 0, "available_kb": 0 },
  "uptime_seconds": 0.0
}
```

The provider reads only fixed, well-known paths (`/proc/sys/kernel/hostname`,
`/proc/sys/kernel/osrelease`, `/proc/sys/kernel/version`,
`/proc/sys/kernel/arch`, `/proc/uptime`, `/proc/meminfo`, `/proc/cpuinfo`,
`/sys/devices/system/cpu/online`). It never accepts a caller-supplied path and
cannot be turned into a generic file-read primitive.

## Request pipeline (daemon)

1. Frame + size check (oversized rejected before body read).
2. JSON parse.
3. Protocol validation (version, id, params, supported operation).
4. Permission decision via `igris_permd::Policy` (default deny; Milestone 3
   allows `system.info`, `fs.list`, `fs.stat`, `fs.read`, `process.list`,
   `process.stat`, `process.children`).
5. Provider dispatch.
6. Exactly one append-only audit record per request: timestamp, request id,
   operation, decision (`allow`/`deny`), coarse result
   (`success`/`denied`/`error`), peer. Audit lines are JSON Lines; records
   never contain response payloads or secrets.

Timeouts: connections time out after 30 s idle; each connection is loosely
isolated on its own thread so a misbehaving client cannot block others.
