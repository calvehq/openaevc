# openaevc-sdk (Rust)

Client SDK for OpenAEVC protocol 0.1.0: one API over the embedded runtime (`EmbeddedClient`) and the `openaevcd` daemon (`RemoteClient`). Both sign every request with the session's key and go through the same admission path; linking the runtime in-process confers no extra authority.

```rust
use openaevc_sdk::{EmbeddedClient, RemoteClient, RemoteEndpoint, Session, OpenAevcClient, TypedClient};

let session = Session::new(key, principal, Some(namespace));
let c = RemoteClient::connect(RemoteEndpoint::Unix("data/openaevcd.sock".into()), session).await?;
// or: EmbeddedClient::new(runtime, session)
let pack = c.create_change_pack(PackSpec::default()).await?;
let candidate = c.seal(pack, 1).await?;
```

`OpenAevcClient` has four primitives (`command`, `query`, `subscribe`, `get_object`); `TypedClient` adds typed helpers for common flows. `get_object` verifies digests and signatures before returning. Endpoints: TCP (`RemoteEndpoint::Tcp("127.0.0.1:7878".into())`), TLS and Unix sockets.

See `docs/sdk/README.md` and `examples/`. Tests: `cargo test -p openaevc-sdk`.
