# Examples

| Example | Run |
|---------|-----|
| Embedded runtime | `cargo run -p openaevc-examples --example embedded-runtime` |
| Daemon client | `OPENAEVC_ENDPOINT=127.0.0.1:7878 OPENAEVC_ADMIN_KEY=admin.json cargo run -p openaevc-examples --example daemon-client` |
| Authority flow | `cargo run -p openaevc-examples --example authority-flow` |
| Execute → verify → promote | `cargo build -p openaevc-ext-reference-kv && cargo run -p openaevc-examples --example execute-verify-promote` |
| Baseline composition | `cargo build -p openaevc-ext-reference-kv && cargo run -p openaevc-examples --example baseline-composition` |
| Custom extension (Rust) | `custom-extension-rust/` — a counter domain in ~100 lines |
| Custom extension (Python) | `custom-extension-python/extension.py` — a tally domain on `sdk/python` |

`cargo test -p openaevc-examples` runs every flow, including registering both custom extensions
into an unmodified runtime.
