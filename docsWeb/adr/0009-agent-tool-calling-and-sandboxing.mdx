# 9. AI Agent tool calling with sandboxed providers, session capabilities, and confirmation gate

- Status: Proposed
- Date: 2026-10-09
- Deciders: Igris OS Project

## Context

Milestone 7 implemented sandboxed provider processes (filesystem, process, system, events) that run in isolated environments with Linux namespaces, cgroups, and seccomp. The `igrisd` daemon routes client requests to these sandboxed providers over Unix domain sockets, after consulting the default-deny permission broker (`igris-permd`).

The next step is to enable an AI agent to interact with the system through structured tool calls. The agent must never hold ambient authority; every operation must be explicitly authorized, confirmed when sensitive, and audited. The agent itself must never bypass the permission broker or directly invoke provider binaries.

## Decision

### Trust boundaries

```
User / AI Agent
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  Igris Core (trusted)                                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  igrisctl   │  │ igris-permd │  │    igrisd (router)  │  │
│  │  (client)   │  │  (policy)   │  │  ┌───────────────┐  │  │
│  └──────┬──────┘  └──────┬──────┘  │  │ ProviderManager │  │  │
│         │                │          │  │  ┌─────────┐   │  │  │
│         ▼                ▼          │  │  │ fs      │   │  │  │
│  ┌─────────────────────────────────┐  │  │  │ process │   │  │  │
│  │     Sandbox Boundary            │  │  │  │ system  │   │  │  │
│  │  ┌─────────┐ ┌─────────┐        │  │  │  │ events  │   │  │  │
│  │  │ fs      │ │ process │        │  │  │  └─────────┘   │  │  │
│  │  │ provider│ │ provider│        │  │  └───────────────┘  │  │
│  │  └────┬────┘ └────┬────┘        │  └─────────────────────┘  │
│  └───────┼───────────┼──────────────┘                             │
│          ▼           ▼                                            │
└──────────┼───────────┼────────────────────────────────────────────┘
           ▼           ▼
    ┌─────────────┐ ┌─────────────┐
    │ fs-provider │ │proc-provider│  (sandboxed: namespaces, cgroups, seccomp)
    └─────────────┘ └─────────────┘
```

### Tool Registry

A centralized `ToolRegistry` defines every tool the agent may invoke. Each tool entry contains:

- `ToolId`: stable identifier (e.g., `fs.read`, `proc.signal`)
- `SchemaVersion`: semantic version of the tool's contract
- `Description`: human-readable purpose
- `InputSchema`: JSON Schema for validation
- `OutputSchema`: JSON Schema for the result
- `RequiredCapability`: capability name (e.g., `filesystem_read`, `process_control`)
* `RequiresConfirmation`: boolean
* `TimeoutMs`: execution timeout
* `MaxInputBytes` / `MaxOutputBytes`: size bounds

The registry is immutable at runtime. New tools require a new registry version and an ADR.

### Session-Scoped Capabilities

Each agent session receives a `SessionContext` containing:

* `SessionId`: cryptographically random, unguessable
* `Capabilities`: set of `Capability` granted for this session
* `ExpiresAt`: timestamp after which capabilities are invalid
* `RevokedAt`: optional revocation timestamp

Capabilities are fine-grained (e.g., `filesystem_read`, `filesystem_write`, `process_control`, `event_observation`). They are issued by the trusted core at session creation and validated on every tool invocation. Capabilities cannot be escalated or transferred between sessions.

Capabilities expire automatically at `ExpiresAt`. They can be explicitly revoked by the trusted core. Expired or revoked capabilities are rejected with a distinct error code.

A session cannot use another session's capabilities. Capability tokens are cryptographically random, generated via `getrandom` (or `getrandom` crate). No timestamps, counters, or predictable values are used as security tokens.

### Confirmation Gate

Sensitive operations (`fs.write`, `fs.delete`, `proc.signal`) require explicit user confirmation. The confirmation flow:

1. Agent requests tool invocation with validated arguments
2. `igrisd` checks policy and capability → if allowed, creates a `ConfirmationRequest`
3. `ConfirmationRequest` contains: `ConfirmationId`, `ToolId`, validated arguments, `SessionId`, `ExpiresAt`
4. User reviews and explicitly approves or denies
5. On approval: `ConfirmationToken` (cryptographically random, one-time) is issued
6. Agent re-submits tool request with `ConfirmationToken`
7. `igrisd` validates token (one-time, bound to session and tool/args), then forwards to provider

A confirmation is bound to the exact tool ID and validated arguments. It is single-use and expires. The agent cannot approve its own confirmations.

### Audit Correlation

Every tool invocation generates an `AuditCorrelationId` (UUIDv7 or similar) linking:

- Session ID
- Tool ID and validated arguments (redacted for sensitive fields)
- Policy decision (`allow`/`deny`)
- Confirmation request/result (when applicable)
* Provider execution outcome
* Final result or error

Audit records follow the existing JSON Lines format. No secrets or full sensitive payloads are logged. The correlation ID enables end-to-end tracing from agent request to provider result.

### Mock Agent

A deterministic mock agent exercises the full request path without an LLM. It demonstrates:

1. Permitted read-only operation succeeds
2. Unknown tool rejected
3. Invalid arguments rejected
3. Missing capability denied
4. Expired/revoked capability denied
5. Sensitive action without confirmation denied
6. Confirmed, authorized action succeeds
7. Denied confirmation never executes
9. Session isolation enforced
10. Provider error produces structured error and audit correlation
10. Untrusted provider output treated as data, not instructions
12. Duplicate/replayed confirmations rejected

### Threat model additions

* Agent cannot bypass `igris-permd` — all requests go through policy evaluation
* Agent cannot directly invoke providers — all traffic routes through `igrisd`
* Provider output is treated as untrusted data, never as instructions
* Sandboxed providers cannot escape their namespace/cgroup/seccomp boundaries
* Confirmation tokens are single-use, cryptographically random, bound to session and tool/args
* Capability tokens are unguessable, expire, and are revocable

## Consequences

- The agent has no ambient authority; every operation is explicitly authorized
- Confirmation gate provides human-in-the-loop for destructive operations
- Audit trail enables full traceability from agent request to provider result
- Mock agent enables deterministic testing without LLM dependency
- Existing M1–M7 behavior is preserved; M8 adds new layers without weakening existing guarantees
- New tools require explicit registry entry and ADR, preventing accidental capability expansion

## Implementation Phases

1. **Phase 1**: ADR and design document (this ADR)
2. **Phase 2**: Tool registry with explicit schemas (`igris-tool-registry` crate)
3. **Phase 3**: Session-scoped capabilities (`igris-session` crate)
3. **Phase 4**: Confirmation gate (`igris-confirmation` crate)
4. **Phase 5**: Audit correlation integration in `igrisd`
4. **Phase 6**: Deterministic mock agent (`igris-mock-agent` binary)
5. **Phase 7**: Security tests (unit, integration, adversarial)
5. **Phase 8**: Documentation updates in `docsWeb/`
4. **Phase 9**: Review, finalize, push

## Consequences

- New crates increase compilation time slightly but improve modularity and auditability
- Session management adds runtime state to `igrisd` but is bounded and auditable
* Confirmation gate adds latency for sensitive operations but is required for safety
* Mock agent enables CI testing without LLM dependency
- New tools require ADR + registry entry, preventing capability creep
- Existing M1–M7 behavior is preserved; M8 adds layers without weakening guarantees