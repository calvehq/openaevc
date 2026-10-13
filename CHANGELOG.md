# Changelog

All notable changes are documented here. Protocol, extension-contract and conformance versions are listed separately from package versions.

## [Unreleased]

## [0.1.0] - 2026-10-12

Protocol 0.1.0, extension contract 0.1.0, conformance suite 0.1.0, data root schema 1.

### Added

- Initial OpenAEVC implementation: protocol 0.1.0, extension contract 0.1.0, conformance 0.1.0.
- Protocol specification (`spec/`), JSON Schema, CDDL and OpenAPI 3.1.
- Reference runtime with SQLite + filesystem CAS store, signed receipts and journal checkpoints.
- `openaevcd` daemon (Unix socket, loopback TCP, TLS), `openaevc-inspect`, `openaevc-conformance`.
- Extension Contract host and SDK; reference extensions `reference-kv` and `reference-null`.
- SDKs for Rust, TypeScript, Python and Go.
- Conformance suite: CORE, AUTHORITY, RUNTIME, EXTENSION_HOST and FULL profiles; in-process, remote and extension targets; JSON and JUnit reports.
- `openaevcd gc` for offline removal of unindexed bytes.
- One public Rust crate, `openaevc`, with modules `protocol`, `canonical`, `crypto`, `core`, `authority`, `policy`, `extension`, `execution`, `verification`, `composition`, `store`, `runtime` and `transport`. The default build is the protocol layer; features `store`, `runtime`, `transport` and `full` add the heavy stacks. The Rust SDK (`openaevc-sdk`), conformance suite, binaries and reference extensions are not published to crates.io.
- Release workflow publishes `openaevc` to crates.io, npm (with provenance) and PyPI (trusted publishing) on a `v*` tag.

### Release-candidate audit

- Digest model frozen (ADR 0011): object digest over the full envelope is the only identity and reference; signatures cover the signing digest (32 raw bytes, `object` domain); one signature per key, sorted (AEVC-OBJ-0006); unused `checkpoint`/`receipt` signature domains removed.
- Extension trust boundary stated (ADR 0012): host capabilities are protocol authorization, not OS confinement; `resource.write`, `network.connect` and `secret.read` are reported as unsupported and never granted (AEVC-EXT-0009).
- Imported objects are inert: they never act as grant parents, Baseline members, verification inputs or policy gates (AEVC-XCH-0003).
- Authority: resource-scoped grants no longer confer non-resource actions (AEVC-CAP-0007); grants carrying constraints are refused (AEVC-CAP-0006); provider registrations belong to their principal (AEVC-EXE-0009); every denial of an authenticated request is audited, including `act_as` and reads; unknown Namespaces answer `UNAUTHORIZED`.
- Executions: completion requires the admitted pack generation; a lease past its grace period is never renewed; one timestamp per command.
- Storage/recovery: CAS bytes are fsynced in every durability mode; GC unlinks after commit; checkpoints are written by every commit path, must be signed by the runtime key, and the checkpointed event is re-hashed.
- Extension host: an extension can no longer block the runtime through unread pipes or descendants holding its output; `process.execute` is bounded by the invocation deadline; `entropy.random` uses the OS CSPRNG.
- Conformance: real daemon restart/tamper recovery through a harness lifecycle (Scenario K); `NOT_EXERCISED` status; profiles are conformant only when every case passed; AEVC-EXT-0003 split (EXT-0010); targeted mutation-sensitivity tests.
- SDKs: strict Ed25519 verification and base64url, ASCII-only identifier case folding, Python error codes decoded from CBOR, invalid text rejected by encoders; transport query values are percent-decoded; timeouts report an unknown, non-retryable outcome.
