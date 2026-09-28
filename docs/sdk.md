# SDKs

All SDKs speak the same protocol: they build envelopes, encode them as deterministic CBOR, sign
them with Ed25519 under the `request` domain, and send them over the v1 HTTP transport
(`spec/transport.md`). They pass the same golden fixtures (`fixtures/canonical/`).

| Language   | Location          | Dependencies            | Transport                     |
| ---------- | ----------------- | ----------------------- | ----------------------------- |
| Rust       | `crates/openaevc-sdk` | tokio               | embedded or HTTP (TCP, TLS, Unix) |
| TypeScript | `sdk/typescript`  | none (Node ≥ 22.6)      | HTTP (TCP, Unix)              |
| Python     | `sdk/python`      | standard library (≥ 3.10) | HTTP (TCP, Unix)            |
| Go         | `sdk/go`          | standard library (≥ 1.22) | HTTP (TCP, Unix)            |

## Rust

```rust
use openaevc_sdk::{EmbeddedClient, RemoteClient, Session, OpenAevcClient, TypedClient};

let session = Session::new(key, principal, Some(namespace));
let c = RemoteClient::connect(Endpoint::Unix("data/openaevcd.sock".into()), session).await?;
// or: EmbeddedClient::new(runtime, session) — same trait, same admission path.
let pack = c.create_change_pack(PackSpec::default()).await?;
let mut events = c.subscribe(EventFilter { namespace, after: 0, kinds: vec![], subjects: vec![] }).await?;
```

`OpenAevcClient` has four primitives (`command`, `query`, `subscribe`, `get_object`);
`TypedClient` adds typed helpers for every common flow. `get_object` verifies digests and
signatures before returning.

## Other languages

See `sdk/typescript/README.md`, `sdk/python/README.md` and `sdk/go/README.md`. The TypeScript
types, and the protocol constants of all three SDKs (command and query names, error codes, object
kinds, ID prefixes, versions), are generated from the protocol schema (`cargo run -p
generate-sdks`); Python and Go values are plain dicts/maps. The canonical encoder, identifiers and
signing are hand-written and tested against the golden fixtures. `verify` is strict Ed25519
(canonical base64url, no small-order keys, canonical S) like the runtime's. Scenario J
(`bins/openaevcd/tests/interop.rs`) drives one daemon from all four SDKs.

## Writing a client in a new language

1. Implement deterministic CBOR per `spec/canonical-encoding.md` and pass
   `fixtures/canonical/values.json`.
2. Implement Ed25519 with domain separation (`"OPENAEVC/1 request\n" || bytes`) and pass
   `fixtures/canonical/signatures.json`, including its `invalid` cases. Object signatures cover
   the 32 raw bytes of the object's signing digest, not its `sha256:` text
   (`spec/identity-and-digests.md`).
3. Build envelopes per `spec/transport.md`; timestamps use 9 fraction digits; send the value
   you signed.
4. Run `openaevc-conformance --target remote` against a daemon that your client talks to, and use
   `openaevc-inspect` to decode and verify what you produce.
