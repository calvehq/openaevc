# 0006. Typed command/query/event API behind one admission path

- Status: accepted
- Date: 2026-09-26

## Decision

The runtime API is a closed set of tagged-union Commands (may mutate), Queries (read-only) and journal Events. Every request travels in a signed envelope (`request` domain) and passes through one admission function: version check, replay window, signature, principal resolution, then per-command authorization. Embedded Rust callers use the identical envelope; there is no privileged in-process path.

## Consequences

Daemon and embedded semantics cannot diverge; the conformance suite runs the same cases against both. Embedded callers pay for signing each request.
