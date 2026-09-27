# Changelog

All notable changes are documented here. Protocol, extension-contract and conformance versions are listed separately from package versions.

## [Unreleased]

### Added

- Initial OpenAEVC implementation: protocol 0.1.0, extension contract 0.1.0, conformance 0.1.0.
- Protocol specification (`spec/`, 120 requirement IDs), JSON Schema, CDDL and OpenAPI 3.1.
- Reference runtime with SQLite + filesystem CAS store, signed receipts and journal checkpoints.
- `openaevcd` daemon (Unix socket, loopback TCP, TLS), `openaevc-inspect`, `openaevc-conformance`.
- Extension Contract host and SDK; reference extensions `reference-kv` and `reference-null`.
- SDKs for Rust, TypeScript, Python and Go.
- Conformance suite: CORE, AUTHORITY, RUNTIME, EXTENSION_HOST and FULL profiles; in-process,
  remote and extension targets; JSON and JUnit reports.
- `openaevcd gc` for offline removal of unindexed bytes.
