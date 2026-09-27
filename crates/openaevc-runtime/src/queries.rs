//! Read-only queries. Every query is authorized (`namespace.read`, or `object.read` for object
//! access) through the same admission path as commands.

use openaevc_core::ImmutableObject;
use openaevc_protocol::{b64, err, JournalCheckpoint, Namespace, Principal, Query};
use serde_json::{json, Value};

use openaevc_protocol::{AnyId, ChangePack, NodeRef, PackId};

use crate::handlers;
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
        GetChangePack { pack, generation } | GetRevisionPack { pack, generation } => {
            read(tx)?;
            let p: Option<ChangePack> = match generation {
                Some(g) => tx.peek(
                    records::PACK_GENERATION,
                    &records::generation_key(&tx.ns, pack, g),
                )?,
                None => tx.peek(records::PACK, &records::key(&tx.ns, pack))?,
            };
            to_json(&p.ok_or_else(|| {
                err::not_found(format!("pack {pack} not found")).with_object(pack)
            })?)
        }
        GetActiveChangeGraph { pack } => {
            read(tx)?;
            graph_json(tx, pack)
        }
        GetNode { node } => {
            read(tx)?;
            node_json(tx, &node)
        }
        GetDependencyClosure { node, reverse } => {
            read(tx)?;
            let waits = handlers::wait_edges(&handlers::edges(tx)?);
            to_json(&openaevc_core::graph::closure(&waits, &node, reverse))
        }
        GetAffectedNodes { node } => {
            read(tx)?;
            let waits = handlers::wait_edges(&handlers::edges(tx)?);
            let mut out = openaevc_core::graph::closure(&waits, &node, true);
            // Downstream of a pack also includes everything waiting on its work units.
            if let Some(pack) = pack_of_node(&node) {
                if let Some(p) =
                    tx.peek::<ChangePack>(records::PACK, &records::key(&tx.ns, pack))?
                {
                    for w in &p.work_units {
                        out.extend(openaevc_core::graph::closure(
                            &waits,
                            &NodeRef::from(w.id),
                            true,
                        ));
                    }
                }
            }
            out.sort();
            out.dedup();
            to_json(&out)
        }
        GetReadyWork { pack } => {
            read(tx)?;
            to_json(&handlers::work_status(tx, pack, true)?)
        }
        GetBlockedWork { pack } => {
            read(tx)?;
            to_json(&handlers::work_status(tx, pack, false)?)
        }
        ListExtensions {} => {
            read(tx)?;
            let recs = tx.peek_list::<records::ExtensionRecord>(
                records::EXTENSION,
                &records::prefix(&tx.ns),
            )?;
            Ok(Value::Array(
                recs.into_iter()
                    .map(|(_, r)| json!({"id": r.manifest.id, "version": r.manifest.version, "manifest": r.manifest_digest, "active": r.active, "granted_host_capabilities": r.approved}))
                    .collect(),
            ))
        }
        GetExecution { execution } => {
            read(tx)?;
            let e: Option<openaevc_protocol::Execution> =
                tx.peek(records::EXECUTION, &records::key(&tx.ns, execution))?;
            to_json(&e.ok_or_else(|| {
                err::not_found(format!("execution {execution} not found")).with_object(execution)
            })?)
        }
        ListExecutions { pack, state } => {
            read(tx)?;
            let all = tx.peek_list::<openaevc_protocol::Execution>(
                records::EXECUTION,
                &records::prefix(&tx.ns),
            )?;
            let out: Vec<_> = all
                .into_iter()
                .map(|(_, e)| e)
                .filter(|e| pack.is_none_or(|p| p == e.pack) && state.is_none_or(|s| s == e.state))
                .collect();
            to_json(&out)
        }
        GetEvidence { digest } => {
            typed_object(tx, ctx, digest, openaevc_protocol::ObjectKind::Evidence)
        }
        GetVerification { digest } => typed_object(
            tx,
            ctx,
            digest,
            openaevc_protocol::ObjectKind::VerificationResult,
        ),
        GetEvaluation { digest } => typed_object(
            tx,
            ctx,
            digest,
            openaevc_protocol::ObjectKind::EvaluationResult,
        ),
        GetPolicyDecision { digest } => typed_object(
            tx,
            ctx,
            digest,
            openaevc_protocol::ObjectKind::PolicyDecision,
        ),
        GetPromotedPack { pack, digest } => {
            let d = match (pack, digest) {
                (_, Some(d)) => d,
                (Some(pack), None) => {
                    read(tx)?;
                    let p: ChangePack = tx
                        .peek(records::PACK, &records::key(&tx.ns, pack))?
                        .ok_or_else(|| err::not_found(format!("pack {pack} not found")))?;
                    p.promotion
                        .ok_or_else(|| err::not_found(format!("pack {pack} is not promoted")))?
                        .promoted_pack
                }
                (None, None) => {
                    return Err(err::invalid("GetPromotedPack needs a pack or a digest"))
                }
            };
            typed_object(tx, ctx, d, openaevc_protocol::ObjectKind::PromotedPack)
        }
        other => Err(err::invalid(format!(
            "{} is not supported by this runtime build",
            other.name()
        ))),
    }
}

fn pack_of_node(n: &NodeRef) -> Option<PackId> {
    match n {
        NodeRef::Id(AnyId::ChangePackId(id)) => Some(PackId::Change(*id)),
        NodeRef::Id(AnyId::RevisionPackId(id)) => Some(PackId::Revision(*id)),
        _ => None,
    }
}

fn pack_node(p: &ChangePack) -> Value {
    json!({"node": p.id, "type": "pack", "state": p.state, "generation": p.generation})
}

fn graph_json(tx: &Tx<'_>, only: Option<PackId>) -> Result<Value> {
    let packs = handlers::all_packs(tx)?;
    let mut nodes = Vec::new();
    let mut members: Vec<String> = Vec::new();
    for p in packs.values().filter(|p| only.is_none_or(|o| o == p.id)) {
        nodes.push(pack_node(p));
        members.push(p.id.to_string());
        for w in &p.work_units {
            nodes.push(json!({"node": w.id, "type": "work_unit", "pack": p.id, "state": w.state, "kind": w.kind}));
            members.push(w.id.to_string());
        }
    }
    let edges: Vec<_> = handlers::edges(tx)?
        .into_iter()
        .filter(|e| {
            only.is_none()
                || members.contains(&e.from.to_string())
                || members.contains(&e.to.to_string())
        })
        .collect();
    Ok(json!({"nodes": nodes, "edges": to_json(&edges)?}))
}

fn node_json(tx: &Tx<'_>, n: &NodeRef) -> Result<Value> {
    let missing = || err::not_found(format!("node {n} not found")).with_object(n);
    if let Some(pack) = pack_of_node(n) {
        let p: ChangePack = tx
            .peek(records::PACK, &records::key(&tx.ns, pack))?
            .ok_or_else(missing)?;
        return Ok(pack_node(&p));
    }
    if let NodeRef::Id(AnyId::WorkUnitId(w)) = n {
        let pack = handlers::owner(tx, n)?.ok_or_else(missing)?;
        let p: ChangePack = tx
            .peek(records::PACK, &records::key(&tx.ns, pack))?
            .ok_or_else(missing)?;
        let unit = p
            .work_units
            .iter()
            .find(|u| &u.id == w)
            .ok_or_else(missing)?;
        return Ok(
            json!({"node": w, "type": "work_unit", "pack": pack, "state": unit.state, "kind": unit.kind, "spec": unit.spec}),
        );
    }
    if let NodeRef::Digest(d) = n {
        let o = tx.load_object(d)?.ok_or_else(missing)?;
        return Ok(json!({"node": d, "type": o.kind()}));
    }
    Err(missing())
}

fn typed_object(
    tx: &Tx<'_>,
    ctx: &Ctx,
    digest: openaevc_protocol::Digest,
    kind: openaevc_protocol::ObjectKind,
) -> Result<Value> {
    authz(tx, ctx, "namespace.read", None)?;
    let o = tx
        .load_object(&digest)?
        .ok_or_else(|| err::not_found(format!("object {digest} not found")).with_object(digest))?;
    if o.kind() != kind {
        return Err(
            err::not_found(format!("{digest} is not a {}", kind.as_str())).with_object(digest),
        );
    }
    object_json(&o)
}
