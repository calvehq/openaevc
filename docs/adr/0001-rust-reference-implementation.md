# 0001. Rust for the reference implementation

- Status: accepted
- Date: 2026-09-26

## Context

The reference runtime holds authority-sensitive state, must embed in other processes and run as a daemon, and must be statically distributable on Linux, macOS and Windows.

## Decision

Implement protocol types, core, runtime, storage, daemon, Rust SDK, extension host and conformance runner in Rust. Every project-owned crate uses `#![forbid(unsafe_code)]`. Tokio is used only in the runtime-facing async layers (transport, daemon, SDK); protocol, canonical, crypto, core, authority, policy, store, execution, verification and composition are synchronous. The runtime itself is synchronous behind a single lock and is driven from async code via blocking tasks.

## Consequences

The protocol stays language-neutral: TypeScript, Python and Go SDKs consume the same schemas and fixtures. A global runtime lock bounds write throughput; per-namespace locking is the upgrade path.
