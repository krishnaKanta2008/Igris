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
- `op` (string): one of the supported operations. `system.info` is the only
  operation in Milestone 1. Unknown operations are rejected with
  `UNKNOWN_OPERATION`.
- `params` (object): must be a JSON object; empty `{}` accepted for
  `system.info`.

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
| `INTERNAL` | Provider failed to execute an allowed operation |

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
4. Permission decision via `igris_permd::Policy` (default deny; Milestone 1
   allows exactly `system.info`).
5. Provider dispatch.
6. Exactly one append-only audit record per request: timestamp, request id,
   operation, decision (`allow`/`deny`), coarse result
   (`success`/`denied`/`error`), peer. Audit lines are JSON Lines; records
   never contain response payloads or secrets.

Timeouts: connections time out after 30 s idle; each connection is loosely
isolated on its own thread so a misbehaving client cannot block others.
