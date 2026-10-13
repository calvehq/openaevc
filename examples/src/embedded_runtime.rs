//! Embedding the runtime in-process: create → seal → qualify → promote → Baseline.

use std::path::Path;

use openaevc::protocol::{Digest, PackSpec, Query};
use openaevc_sdk::{OpenAevcClient, TypedClient};

use crate::common::{new_namespace, open_embedded};
use crate::Result;

#[derive(Debug)]
pub struct Summary {
    pub promoted: Digest,
    pub baseline: Digest,
    pub valid: bool,
}

pub async fn run(data_root: &Path) -> Result<Summary> {
    let e = open_embedded(data_root, vec![])?;
    let (c, _) = new_namespace(&e).await?;
    let pack = c.create_change_pack(PackSpec::default()).await?;
    c.seal(pack, 1).await?;
    c.refresh_qualification(pack, 1).await?;
    let promoted = c.promote(pack, 1).await?;
    let (_, baseline) = c.create_baseline(vec![promoted], vec![]).await?;
    let valid = c
        .query(Query::ValidateBaseline { digest: baseline })
        .await?["valid"]
        == true;
    Ok(Summary {
        promoted,
        baseline,
        valid,
    })
}
