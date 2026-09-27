//! Independent Baselines over shared promoted packs, and a domain composition conflict resolved
//! by an explicit ordering edge.

use std::path::Path;

use openaevc_protocol::*;
use openaevc_sdk::{OpenAevcClient, TypedClient};

use crate::common::{
    kv_set, new_namespace, open_embedded, provider, register_extension, run_effects,
};
use crate::execute_verify_promote::KV;
use crate::Result;

#[derive(Debug)]
pub struct Outcome {
    pub unordered_conflict: ErrorCode,
    pub ordered: Digest,
    pub independent: Vec<Digest>,
}

async fn promote_one<C: OpenAevcClient>(c: &C, key: &str, value: &str) -> Result<Digest> {
    let pack = c.create_change_pack(PackSpec::default()).await?;
    let generation = run_effects(c, pack, vec![kv_set(key, value)], "kv.entry").await?;
    c.seal(pack, generation).await?;
    c.refresh_qualification(pack, generation).await?;
    Ok(c.promote(pack, generation).await?)
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
    let fast = promote_one(&c, "mode", "fast").await?;
    let safe = promote_one(&c, "mode", "safe").await?;
    let other = promote_one(&c, "region", "eu").await?;
    let unordered_conflict = c
        .create_baseline(vec![fast, safe], vec![])
        .await
        .map(|_| ErrorCode::Internal)
        .unwrap_or_else(|e| e.code);
    let order = CompositionEdge {
        from: safe,
        to: fast,
        kind: CompositionEdgeKind::OrdersAfter,
        relation: None,
    };
    let (_, ordered) = c.create_baseline(vec![fast, safe], vec![order]).await?;
    let (_, b1) = c.create_baseline(vec![fast, other], vec![]).await?;
    let (_, b2) = c.create_baseline(vec![safe, other], vec![]).await?;
    Ok(Outcome {
        unordered_conflict,
        ordered,
        independent: vec![b1, b2],
    })
}
