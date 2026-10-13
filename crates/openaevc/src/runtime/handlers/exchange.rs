//! Object exchange (spec/object-exchange.md): verified import of immutable objects by digest.

use crate::core::ImmutableObject;
use crate::protocol::{CommandResult, Digest};
use serde_json::json;

use crate::runtime::tx::Tx;
use crate::runtime::{authz, Ctx, Result};

/// Imports canonical object bytes. The digest is checked first, then canonical form, envelope
/// schema, body schema and signatures; only then is the object indexed. Importing never
/// registers principals, grants or extensions: imported authority is inert data.
pub(crate) fn put(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    digest: Digest,
    bytes: Vec<u8>,
) -> Result<CommandResult> {
    authz(tx, ctx, "object.exchange", None)?;
    let obj = ImmutableObject::from_bytes(&bytes, Some(digest))?;
    let already = tx.rt.store.is_indexed(&tx.ns, &digest)?;
    let kind = obj.kind();
    if !already {
        tx.add_object(obj);
    }
    tx.emit(
        "object.imported",
        json!({"digest": digest, "kind": kind, "already_present": already}),
        vec![digest.to_string()],
    );
    Ok(CommandResult {
        digest: Some(digest),
        ..Default::default()
    })
}
