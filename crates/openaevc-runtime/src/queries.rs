//! Read-only queries. Every query is authorized (`namespace.read`, or `object.read` for object
//! access) through the same admission path as commands.

use openaevc_core::ImmutableObject;
use openaevc_protocol::{b64, err, JournalCheckpoint, Namespace, Principal, Query};
use serde_json::{json, Value};

use crate::records::{self, CheckpointRecord, GrantRecord};
use crate::tx::Tx;
use crate::view::NsView;
use crate::{authz, Ctx, Result};

fn to_json<T: serde::Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| err::internal(format!("encode: {e}")))
}

/// JSON form of an immutable object as returned by queries.
pub(crate) fn object_json(o: &ImmutableObject) -> Result<Value> {
    Ok(
        json!({"digest": o.digest(), "envelope": to_json(o.envelope())?, "canonical": b64::encode(o.bytes())}),
    )
}

pub(crate) fn dispatch(tx: &Tx<'_>, ctx: &Ctx, q: Query) -> Result<Value> {
    use Query::*;
    let read = |tx: &Tx<'_>| authz(tx, ctx, "namespace.read", None).map(drop);
    let object_read = |tx: &Tx<'_>| authz(tx, ctx, "object.read", None).map(drop);
    match q {
        GetRuntimeInfo {} => {
            read(tx)?;
            Ok(json!({
                "runtime_instance": tx.rt.instance,
                "protocol": openaevc_protocol::SUPPORTED_PROTOCOL,
                "contract": openaevc_protocol::SUPPORTED_CONTRACT,
                "implementation": {"name": "openaevc-runtime", "version": env!("CARGO_PKG_VERSION")},
                "runtime_key": tx.rt.signer.public_key(),
                "replay_window_ms": tx.rt.config.replay_window_ms,
            }))
        }
        GetNamespace {} => {
            read(tx)?;
            let n: Namespace = tx
                .peek(records::NAMESPACE, &tx.ns.to_string())?
                .ok_or_else(|| err::not_found("namespace"))?;
            to_json(&n)
        }
        GetPrincipal { principal } => {
            read(tx)?;
            let p: Principal = tx
                .peek(records::PRINCIPAL, &records::key(&tx.ns, principal))?
                .ok_or_else(|| err::not_found(format!("principal {principal} not found")))?;
            to_json(&p)
        }
        GetGrant { grant } => {
            read(tx)?;
            let g: GrantRecord = tx
                .peek(records::GRANT, &records::key(&tx.ns, grant))?
                .ok_or_else(|| err::not_found(format!("grant {grant} not found")))?;
            Ok(json!({"digest": g.digest, "grant": g.grant, "revoked": g.revoked}))
        }
        Authorize {
            principal,
            action,
            resource,
        } => {
            read(tx)?;
            let view = NsView {
                tx,
                roots: ctx.roots.clone(),
            };
            let req = openaevc_authority::Request {
                principal,
                action: &action,
                resource: resource.as_ref(),
            };
            Ok(match openaevc_authority::authorize(&view, tx.now, &req) {
                Ok(a) => json!({"allowed": true, "root": a.root, "grants": a.grants}),
                Err(e) => json!({"allowed": false, "error": to_json(&e)?}),
            })
        }
        ListEvents {
            after,
            limit,
            kinds,
        } => {
            read(tx)?;
            let limit = limit
                .unwrap_or(tx.rt.config.max_page)
                .min(tx.rt.config.max_page) as usize;
            let mut out = Vec::new();
            let mut cursor = after;
            while out.len() < limit {
                let batch = tx.rt.store.read_events(&tx.ns, cursor, limit)?;
                let Some(last) = batch.last() else { break };
                cursor = last.sequence;
                out.extend(
                    batch
                        .into_iter()
                        .filter(|e| kinds.is_empty() || kinds.contains(&e.kind)),
                );
            }
            out.truncate(limit);
            to_json(&out)
        }
        GetObject { digest } => {
            object_read(tx)?;
            let o = tx.load_object(&digest)?.ok_or_else(|| {
                err::not_found(format!("object {digest} not found")).with_object(digest)
            })?;
            object_json(&o)
        }
        HasObject { digests } => {
            object_read(tx)?;
            let mut m = serde_json::Map::new();
            for d in digests {
                m.insert(
                    d.to_string(),
                    Value::Bool(tx.rt.store.is_indexed(&tx.ns, &d)?),
                );
            }
            Ok(Value::Object(m))
        }
        GetJournalCheckpoint {} => {
            read(tx)?;
            let rec: CheckpointRecord = tx
                .peek(records::CHECKPOINT, &tx.ns.to_string())?
                .ok_or_else(|| err::not_found("no journal checkpoint has been written yet"))?;
            let o = tx
                .load_object(&rec.digest)?
                .ok_or_else(|| err::integrity("checkpoint object missing"))?;
            let _: JournalCheckpoint = o.body()?;
            object_json(&o)
        }
        other => Err(err::invalid(format!(
            "{} is not supported by this runtime build",
            other.name()
        ))),
    }
}
