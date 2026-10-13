# Getting started

In about ten minutes you will run the reference daemon, create a Namespace, and take a first change from creation to an immutable, signed Baseline, using the SDK for your language.

| You need                                             | For                                             |
| ---------------------------------------------------- | ----------------------------------------------- |
| Linux x86_64, macOS arm64 or Windows x86_64          | the prebuilt daemon (or Rust 1.89+ to build it) |
| Python ≥ 3.10, Node ≥ 22.6, Go ≥ 1.22 or Rust ≥ 1.89 | one SDK                                         |

## 1. Install the tools

Download the binaries for your platform from the [v0.1.0 release](https://github.com/calvehq/openaevc/releases/tag/v0.1.0): `openaevcd` (the daemon), `openaevc-inspect` (decode, digest and verify) and `openaevc-conformance` (the conformance suite).

```sh
base=https://github.com/calvehq/openaevc/releases/download/v0.1.0
target=x86_64-unknown-linux-gnu          # or aarch64-apple-darwin; on Windows use the .exe files
for b in openaevcd openaevc-inspect; do curl -fLO "$base/$b-$target"; done
curl -fLO "$base/SHA256SUMS" && sha256sum -c --ignore-missing SHA256SUMS
for b in openaevcd openaevc-inspect; do chmod +x "$b-$target" && mv "$b-$target" "$b"; done
```

Each file also has a Sigstore signature and a build-provenance attestation; see [RELEASES.md → Verifying artifacts](../../RELEASES.md#verifying-artifacts). To build from source instead: `cargo build --release -p openaevcd -p openaevc-inspect` in a clone of this repository.

## 2. Start the daemon

```sh
./openaevcd init --data-root ./data --config-out openaevcd.toml --admin-key-out admin.json
```

`init` creates the data root and the runtime's signing key, and writes `admin.json`: the **administrator key**, the only credential that can create Namespaces. Keep it private.

The daemon always listens on a Unix socket (`./data/openaevcd.sock`). For this guide, also listen on loopback TCP: edit `openaevcd.toml` so the `[listen]` section reads

```toml
[listen]
tcp = "127.0.0.1:7878"
```

then start it and check that it answers:

```sh
./openaevcd run --config openaevcd.toml
./openaevc-inspect compatibility 127.0.0.1:7878     # in another terminal
# daemon protocol 0.1.0..=0.1.0, contract 0.1.0..=0.1.0
```

## 3. Your first change

Every program below does the same thing, from the directory that holds `admin.json`:

1. As the **administrator**, create a Namespace with one root principal: a new Ed25519 key that you own.
2. As that **root principal**, create a ChangePack, seal generation 1, refresh its qualification, promote it, and compose the promoted pack into a Baseline.

### Python

```sh
pip install openaevc
```

```python
import json
from openaevc import Client, Session, SigningKey

ENDPOINT = "127.0.0.1:7878"
admin = json.load(open("admin.json"))

# 1. The administrator creates a Namespace with one root principal (a new key you keep).
admin_client = Client(ENDPOINT, Session(SigningKey.from_hex(admin["seed"]), admin["id"]))
admin_client.negotiate()
root_key = SigningKey.generate()
ns, roots = admin_client.create_namespace([{"kind": "KEY", "public_key": root_key.public_key}])

# 2. Work in the Namespace as its root principal.
c = Client(ENDPOINT, Session(root_key, roots[0], ns))
pack = c.create_change_pack()
candidate = c.seal(pack, 1)                      # freeze generation 1 as a candidate
state = c.refresh_qualification(pack, 1)["result"]["state"]
promoted = c.promote(pack, 1)                    # immutable, signed record
_, baseline = c.create_baseline([promoted])
valid = c.query({"type": "ValidateBaseline", "digest": baseline})["valid"]

print("namespace", ns)
print("pack", pack, "->", state)
print("promoted", promoted)
print("baseline", baseline, "valid:", valid)
```

### TypeScript (Node ≥ 22.6)

```sh
npm i @openaevc/sdk
```

```js
// quickstart.mjs
import { readFileSync } from 'node:fs';
import { Client, Session, SigningKey } from '@openaevc/sdk';

const endpoint = { host: '127.0.0.1', port: 7878 };
const admin = JSON.parse(readFileSync('admin.json', 'utf8'));

// 1. The administrator creates a Namespace with one root principal.
const adminClient = new Client(endpoint, new Session(SigningKey.fromHex(admin.seed), admin.id));
await adminClient.negotiate();
const rootKey = SigningKey.generate();
const { namespace, roots } = await adminClient.createNamespace([{ kind: 'KEY', public_key: rootKey.publicKey }]);

// 2. Work in the Namespace as its root principal.
const c = new Client(endpoint, new Session(rootKey, roots[0], namespace));
const pack = await c.createChangePack();
await c.seal(pack, 1);
const { result } = await c.refreshQualification(pack, 1);
const promoted = await c.promote(pack, 1);
const { digest: baseline } = await c.createBaseline([promoted]);
const { valid } = await c.query({ type: 'ValidateBaseline', digest: baseline });
console.log({ namespace, pack, state: result.state, promoted, baseline, valid });
```

### Go

```sh
go get github.com/calvehq/openaevc/sdk/go@v0.1.0
```

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	openaevc "github.com/calvehq/openaevc/sdk/go"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	const endpoint = "127.0.0.1:7878"
	raw, err := os.ReadFile("admin.json")
	check(err)
	var admin struct{ ID, Seed string }
	check(json.Unmarshal(raw, &admin))

	// 1. The administrator creates a Namespace with one root principal.
	adminKey, err := openaevc.KeyFromHex(admin.Seed)
	check(err)
	ac := openaevc.NewClient(endpoint, openaevc.Session{Key: adminKey, Principal: admin.ID})
	_, err = ac.Negotiate()
	check(err)
	rootKey, err := openaevc.GenerateKey()
	check(err)
	ns, roots, err := ac.CreateNamespace([]map[string]any{{"kind": "KEY", "public_key": rootKey.PublicKey}})
	check(err)

	// 2. Work in the Namespace as its root principal. Commands return {"result": {...}}.
	c := openaevc.NewClient(endpoint, openaevc.Session{Key: rootKey, Principal: roots[0], Namespace: ns})
	result := func(body map[string]any) map[string]any {
		r, err := c.Command(body)
		check(err)
		return r["result"].(map[string]any)
	}
	pack := result(map[string]any{"type": "CreateChangePack", "spec": map[string]any{}})["id"]
	result(map[string]any{"type": "SealChangePack", "pack": pack, "expected_generation": 1})
	state := result(map[string]any{"type": "RefreshQualification", "pack": pack, "generation": 1})["state"]
	promoted := result(map[string]any{"type": "PromoteChangePack", "pack": pack, "generation": 1})["digest"]
	baseline := result(map[string]any{"type": "CreateBaseline", "members": []any{promoted}, "edges": []any{}})["digest"]
	v, err := c.Query(map[string]any{"type": "ValidateBaseline", "digest": baseline})
	check(err)
	fmt.Println("namespace", ns, "\npack", pack, "->", state, "\npromoted", promoted,
		"\nbaseline", baseline, "valid:", v.(map[string]any)["valid"])
}
```

### Rust

The Rust client SDK (`openaevc-sdk`) is not on crates.io yet; take it and the `openaevc` crate from the same release tag so their types match:

```toml
[dependencies]
openaevc = { git = "https://github.com/calvehq/openaevc", tag = "v0.1.0", features = ["full"] }
openaevc-sdk = { git = "https://github.com/calvehq/openaevc", tag = "v0.1.0" }
serde_json = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use std::sync::Arc;

use openaevc::crypto::{Signer, SigningKey};
use openaevc::protocol::{NewPrincipal, PackSpec, PrincipalKind, Query};
use openaevc_sdk::{OpenAevcClient, RemoteClient, RemoteEndpoint, Session, TypedClient};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    // The administrator key written by `openaevcd init --admin-key-out admin.json`.
    let admin: serde_json::Value = serde_json::from_str(&std::fs::read_to_string("admin.json")?)?;
    let seed = admin["seed"].as_str().ok_or("seed")?;
    let seed: [u8; 32] = (0..32)
        .map(|i| u8::from_str_radix(&seed[2 * i..2 * i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "seed length")?;
    let admin_id = admin["id"].as_str().ok_or("id")?.parse()?;
    let endpoint = RemoteEndpoint::Tcp("127.0.0.1:7878".into());

    // 1. The administrator creates a Namespace with one root principal.
    let admin_client = RemoteClient::connect(
        endpoint.clone(),
        Session::new(Arc::new(SigningKey::from_seed(seed)), admin_id, None),
    )
    .await?;
    let root_key = Arc::new(SigningKey::generate());
    let (ns, roots) = admin_client
        .create_namespace(vec![NewPrincipal {
            kind: PrincipalKind::Key,
            public_key: Some(root_key.public_key()),
            linked_to: None,
            attributes: Default::default(),
        }])
        .await?;

    // 2. Work in the Namespace as its root principal.
    let c = RemoteClient::connect(endpoint, Session::new(root_key, roots[0], Some(ns))).await?;
    let pack = c.create_change_pack(PackSpec::default()).await?;
    c.seal(pack, 1).await?;
    c.refresh_qualification(pack, 1).await?;
    let promoted = c.promote(pack, 1).await?;
    let (_, baseline) = c.create_baseline(vec![promoted], vec![]).await?;
    let valid = c.query(Query::ValidateBaseline { digest: baseline }).await?["valid"] == true;
    println!("namespace {ns}\npack {pack}\npromoted {promoted}\nbaseline {baseline} valid: {valid}");
    Ok(())
}
```

Rust can also skip the daemon and embed the runtime in-process (`EmbeddedClient`, same API and the same admission path): see [`examples/embedded-runtime`](../../examples/embedded-runtime/main.rs) and [`examples/src/common.rs`](../../examples/src/common.rs).

### Expected output

Python shown; the other SDKs print the same values in their own formats.

```text
namespace ns_…
pack cpk_… -> QUALIFIED
promoted sha256:…
baseline sha256:… valid: True
```

## What just happened

| Term | Meaning |
| --- | --- |
| **Namespace** | An isolated authority domain. Only the administrator key can create one; its root principals hold full authority inside it. |
| **Principal** | An identity that signs requests: here an Ed25519 key. Every request is signed and checked (version → signature → freshness → replay → capability). |
| **ChangePack** | The unit of proposed change. Each mutation bumps its **generation**; sealing freezes one generation as a candidate. |
| **Qualification** | Policy gates evaluated against evidence bound to that exact generation. With no policy attached, the sealed pack qualifies. |
| **Promotion** | Turns a qualified generation into an immutable, signed, content-addressed record (`sha256:…`). |
| **Baseline** | An immutable composition of promoted packs: the accepted state. |

## Next steps

- **Delegate authority instead of using the root key**: register principals and issue scoped, expiring capability grants: [`examples/authority-flow`](../../examples/src/authority_flow.rs).
- **Make real changes**: domains (key-value, documents, infrastructure, …) come from extensions. Run [`examples/execute-verify-promote`](../../examples/src/execute_verify_promote.rs) with the reference key-value extension, then [write your own](../extension-authoring/README.md).
- **Watch events**: every SDK can stream the hash-chained journal (`events` / `subscribe`).
- **Run it for real**: TLS listeners, configuration, backups, upgrades: [operations guide](../operations/README.md).
- **Check the daemon you just started**: `openaevc-conformance --profile CORE --target remote --endpoint 127.0.0.1:7878 --admin-key admin.json`. The `FULL` profile also needs the conformance extensions installed and control of the daemon's process for restart checks (`--daemon`); see [conformance](../../spec/conformance.md).
