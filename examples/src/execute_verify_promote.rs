//! A full trusted change in the key-value reference domain: execute → verify → evaluate →
//! qualify (under a mandatory policy) → promote.

use std::path::Path;

use openaevc_protocol::*;
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::json;

use crate::common::{
    kv_set, new_namespace, open_embedded, provider, register_extension, run_effects,
};
use crate::Result;

pub const KV: &str = "openaevc-ext-reference-kv";

#[derive(Debug)]
pub struct Outcome {
    pub verification: String,
    pub qualification: String,
    pub promoted: Digest,
}

pub async fn run(data_root: &Path, extension_dir: &Path) -> Result<Outcome> {
    let e = open_embedded(data_root, vec![extension_dir.to_path_buf()])?;
    let (c, _) = new_namespace(&e).await?;
    register_extension(
        &c,
        extension_dir,
        &format!("{KV}{}", std::env::consts::EXE_SUFFIX),
    )
    .await?;
    c.command(Command::RegisterProvider {
        provider: provider(c.session().principal()),
    })
    .await?;
    let gate: PolicyDocument = serde_json::from_value(json!({
        "name": "org.example.release-gate",
        "rules": [
            {"id": "expected-value", "expr": {"verifier": {"kind": "kv.expect", "status": "PASS"}}},
            {"id": "small-change", "expr": {"not": {"evaluator": {"kind": "kv.size", "verdict": "DENY"}}}}
        ]
    }))?;
    c.command(Command::RegisterPolicy {
        document: gate,
        mandatory: true,
    })
    .await?;
    let pack = c.create_change_pack(PackSpec::default()).await?;
    let generation =
        run_effects(&c, pack, vec![kv_set("service/timeout", "30s")], "kv.entry").await?;
    c.seal(pack, generation).await?;
    let v = c
        .run_verification(
            pack,
            generation,
            "kv.expect",
            json!({"key": "service/timeout", "value": "30s"}),
        )
        .await?;
    c.run_evaluation(pack, generation, "kv.size", json!({"max_keys": 5}))
        .await?;
    let q = c.refresh_qualification(pack, generation).await?;
    let promoted = c.promote(pack, generation).await?;
    Ok(Outcome {
        verification: v.result.state.unwrap_or_default(),
        qualification: q.result.state.unwrap_or_default(),
        promoted,
    })
}
