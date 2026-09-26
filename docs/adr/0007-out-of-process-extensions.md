# 0007. Out-of-process extension host

- Status: accepted
- Date: 2026-09-26

## Decision
Extensions run as subprocesses speaking length-prefixed canonical CBOR frames over stdin/stdout.
The host verifies the executable's SHA-256 against both the manifest and the digest pinned by the
registering caller, negotiates protocol/contract ranges, grants host capabilities per invocation,
enforces deadlines and frame-size limits, and kills misbehaving processes. Extensions never
receive storage paths or database handles. Each invocation spawns a fresh process.

## Consequences
No third-party code is loaded into the runtime process. The reference host does not sandbox the
OS process itself; host capabilities govern only the structured host calls. Per-invocation spawn
costs latency; a pooled host is a future optimization that the contract already permits.
