# Writing an extension

An extension adds a domain — resource kinds, effect kinds, verifiers, evaluators, composition validators — without changing the runtime. It is an executable that speaks the Extension Contract (`spec/extensions.md`) over stdin/stdout. Complete examples: `examples/custom-extension-rust/main.rs` (Rust, ~100 lines) and `examples/custom-extension-python/extension.py` (Python).

## 1. Declare a manifest

```rust
ExtensionManifest {
    id: "org.example.counter".into(),            // reverse-DNS, unique per Namespace
    version: "1.0.0".into(),
    protocol: SUPPORTED_PROTOCOL,
    contract: SUPPORTED_CONTRACT,
    artifact_digest: self_artifact_digest(),     // sha256 of this executable
    resource_kinds: vec![ResourceKindDecl { kind: "counter.value".into(), description: None }],
    effect_kinds: vec![EffectKindDecl {
        kind: "counter.increment".into(),
        resource_kind: "counter.value".into(),
        required_actions: vec!["counter.write".into()], // authority callers need to use it
    }],
    verifier_kinds: vec!["counter.at-least".into()],
    host_capabilities: vec![],                   // request only what you use
    ..
}
```

## 2. Handle operations

| Operation         | Must                                                       | Host calls allowed             |
| ----------------- | ---------------------------------------------------------- | ------------------------------ |
| `validate_effect` | Accept or reject a proposal (payload shape, preconditions) | resource.read, clock.read      |
| `apply_effect`    | Return the applied result (outputs, new resource version)  | all granted                    |
| `verify`          | Return `PASS`/`FAIL`/`ERROR` with findings and facts       | all granted but resource.write |
| `evaluate`        | Return a verdict and integer metrics                       | resource.read, clock.read      |
| `compose`         | Validate a Baseline's members for this domain              | none                           |

Answer operations for kinds you did not declare with an error. Be deterministic: the same inputs must produce the same outputs, since results are recorded as evidence.

## 3. Build, install, register

```sh
cargo build --release -p my-extension
cp target/release/my-extension /var/lib/openaevc/extensions/   # a configured extension directory
sha256sum /var/lib/openaevc/extensions/my-extension
```

Register with `RegisterExtension { entrypoint: "my-extension", artifact_digest: <sha256>, approved_host_capabilities: [...] }`. The runtime re-hashes the executable before every invocation; replacing the file requires registering the new digest.

## 4. Check it

```sh
openaevc-conformance --target extension --extension ./target/release/my-extension
```

The check runs the handshake, confirms the manifest pins the executable's digest and a v1 contract range, that identifiers are namespaced, and that undeclared kinds get an error.

## What the host enforces, and what it does not

The process starts with only `PATH` in its environment and the extension directory as working directory, and is never given runtime storage paths, database handles or keys. Output frames are limited in size, the whole exchange has a deadline, and a host-call budget applies. Anything the extension wants to change goes through its outputs, which the runtime validates and records.

Host capabilities control the host calls you may make, not what your process can do: the reference host is **not** an OS sandbox. Your executable runs with the privileges of the OS user that runs the runtime (or whatever identity the operator arranges), so operators treat registering it as trusting that code. `resource.write`, `network.connect` and `secret.read` can be declared, but the reference host implements no host call for them: they are reported as `unsupported_host_capabilities` and never granted (spec/extensions.md, AEVC-EXT-0009).
