# openaevc

OpenAEVC protocol types, canonical encoding, cryptography, authority, policy, execution, verification, composition, the Extension Contract, and the reference store, runtime and HTTP transport — one crate, one module per layer.

```toml
[dependencies]
openaevc = "0.1"                                        # protocol layer only
openaevc = { version = "0.1", features = ["full"] }     # + store, runtime, transport
```

| Feature | Adds | Pulls in |
| --- | --- | --- |
| _(default)_ | `protocol`, `canonical`, `crypto`, `core`, `authority`, `policy`, `extension`, `execution`, `verification`, `composition` | serde, sha2, ed25519-dalek |
| `store` | `openaevc::store` | rusqlite (bundled SQLite) |
| `runtime` | `openaevc::runtime` (implies `store`) | tokio |
| `transport` | `openaevc::transport` (implies `runtime`) | axum, hyper, rustls |
| `full` | everything above |  |

Features only add modules; they never change protocol behaviour. The normative specification, schemas and conformance suite live in the [repository](https://github.com/calvehq/openaevc).

License: Apache-2.0.
