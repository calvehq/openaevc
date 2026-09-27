//! Registers custom-domain extensions (Rust counter, Python tally) and runs a verified change
//! through each — proving new domains need only the Extension Contract (AEVC-INV-030).

use std::path::Path;

use openaevc_protocol::*;
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::json;

use crate::common::{new_namespace, open_embedded, provider, register_extension, run_effects};
use crate::Result;

fn effect(
    kind: &str,
    resource: &str,
    extension: &str,
    locator: &str,
    payload: serde_json::Value,
) -> EffectProposal {
    EffectProposal {
        kind: kind.into(),
        target: ResourceRef {
            kind: resource.into(),
            locator: locator.into(),
            version: None,
            extension: extension.into(),
        },
        payload,
        preconditions: vec![],
        outputs: vec![],
    }
}

/// Runs a counter change; returns the verification status.
pub async fn run_counter(
    data_root: &Path,
    extension_dir: &Path,
    entrypoint: &str,
) -> Result<String> {
    let e = open_embedded(data_root, vec![extension_dir.to_path_buf()])?;
    let (c, _) = new_namespace(&e).await?;
    register_extension(&c, extension_dir, entrypoint).await?;
    c.command(Command::RegisterProvider {
        provider: provider(c.session().principal()),
    })
    .await?;
    let pack = c.create_change_pack(PackSpec::default()).await?;
    let inc = |n: i64| {
        effect(
            "counter.increment",
            "counter.value",
            "org.example.counter",
            "visits",
            json!({"by": n}),
        )
    };
    let generation = run_effects(&c, pack, vec![inc(2), inc(3)], "counter.value").await?;
    c.seal(pack, generation).await?;
    let v = c
        .run_verification(
            pack,
            generation,
            "counter.at-least",
            json!({"name": "visits", "min": 5}),
        )
        .await?;
    Ok(v.result.state.unwrap_or_default())
}

/// Runs a tally change through the Python extension; returns the verification status.
pub async fn run_python_tally(data_root: &Path, extension_dir: &Path) -> Result<String> {
    let e = open_embedded(data_root, vec![extension_dir.to_path_buf()])?;
    let (c, _) = new_namespace(&e).await?;
    register_extension(&c, extension_dir, "extension.py").await?;
    c.command(Command::RegisterProvider {
        provider: provider(c.session().principal()),
    })
    .await?;
    let pack = c.create_change_pack(PackSpec::default()).await?;
    let add = effect(
        "tally.add",
        "tally.mark",
        "org.example.tally",
        "inventory",
        json!({"item": "apples"}),
    );
    let generation = run_effects(&c, pack, vec![add], "tally.mark").await?;
    c.seal(pack, generation).await?;
    let v = c
        .run_verification(
            pack,
            generation,
            "tally.contains",
            json!({"item": "apples"}),
        )
        .await?;
    Ok(v.result.state.unwrap_or_default())
}
