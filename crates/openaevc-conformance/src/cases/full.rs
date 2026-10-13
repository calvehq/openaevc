//! FULL profile: restart recovery and object exchange.

use std::collections::BTreeSet;
use std::sync::Arc;

use openaevc::protocol::*;
use openaevc::store::{SqliteOptions, SqliteStore};
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::json;

use crate::ctx::{ensure, expect_code, Check, Ctx, Ns};
use crate::lifecycle::Lifecycle;
use crate::target::{Identity, Target};
use crate::CaseResult;

/// Promotion, journal and checkpoint consistency any target must show (REC-0003/0004).
async fn observable(cx: &Ctx, ns: &Ns) -> Result<Digest, String> {
    let pack = ns
        .root
        .create_change_pack(PackSpec {
            intent: Some(json!({"org.openaevc.conformance.notes": "x".repeat(20_000)})),
            ..Default::default()
        })
        .await
        .c()?;
    let promoted = cx.finish(&ns.root, pack, 1).await?;
    let p = ns.root.get_change_pack(pack).await.c()?;
    let info = p.promotion.ok_or("promoted pack without promotion info")?;
    ns.root.get_object(info.promotion_record).await.c()?;
    ns.root.get_object(promoted).await.c()?;
    let events = cx.events(&ns.root).await?;
    ensure(
        events.iter().any(|e| e.kind == "changepack.promoted"),
        "promotion without its audit event",
    )?;
    openaevc::core::events::verify_chain(&events, 0, Digest::ZERO)
        .map_err(|e| format!("journal: {}", e.message))?;
    Ok(promoted)
}

/// Runs a blocking lifecycle operation off the async runtime.
async fn lifecycle_op(
    l: &Arc<dyn Lifecycle>,
    f: fn(&dyn Lifecycle) -> Result<(), String>,
) -> Result<(), String> {
    let l = l.clone();
    tokio::task::spawn_blocking(move || f(l.as_ref()))
        .await
        .map_err(|e| e.to_string())?
}

/// Recovery through the transport: the harness really crashes and restarts the implementation on
/// the same data root (AEVC-REC-0001 to AEVC-REC-0004).
async fn remote_recovery(cx: &Ctx, l: Arc<dyn Lifecycle>) -> CaseResult {
    let ns = cx.namespace().await?;
    // 1. Persistent protocol state: a promoted pack (object stored in the CAS), a Baseline, a
    //    running execution holding a lease.
    let promoted = observable(cx, &ns).await?;
    let (_, baseline) = ns.root.create_baseline(vec![promoted], vec![]).await.c()?;
    ns.root
        .command(Command::RegisterProvider {
            provider: crate::ctx::provider(ns.root_id, false),
        })
        .await
        .c()?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let wu = ns.root.add_work_unit(pack, 1, "org.x.t").await.c()?;
    let (exe, lease) = ns
        .root
        .start_execution(cx.execution_request(pack, 2, wu, &[]))
        .await
        .c()?;
    ns.root.heartbeat(&lease).await.c()?;
    let before = cx.events(&ns.root).await?;
    let promoted_bytes = ns.root.get_object(promoted).await.c()?;

    // 2. Crash; leave a staged write behind; let the lease expire while the daemon is down.
    lifecycle_op(&l, |l| l.stop()).await?;
    let stray = l.data_root().join("tmp").join("conformance-stray");
    std::fs::write(&stray, b"partial").map_err(|e| e.to_string())?;
    let wait = cx.target.now().millis_until(lease.expires_at).max(0) as u64 + 1_000;
    tokio::time::sleep(std::time::Duration::from_millis(wait)).await;

    // 3. Restart on the same data root.
    lifecycle_op(&l, |l| l.start()).await?;
    ensure(
        !stray.exists(),
        "startup must discard staged temporary writes",
    )?;
    // 4. Namespace and runtime state survive.
    ns.root.query(Query::GetNamespace {}).await.c()?;
    ensure(
        ns.root.get_change_pack(pack).await.c()?.state == PackState::Open,
        "pack state survives restart",
    )?;
    // 5. Immutable objects survive byte for byte and validate.
    ensure(
        ns.root.get_object(promoted).await.c()? == promoted_bytes,
        "promoted object bytes changed across restart",
    )?;
    // 6. The journal is preserved as a prefix and still hash-chains.
    let after = cx.events(&ns.root).await?;
    ensure(
        after.len() >= before.len() && after[..before.len()] == before[..],
        "restart must preserve the journal",
    )?;
    openaevc::core::events::verify_chain(&after, 0, Digest::ZERO)
        .map_err(|e| format!("journal after restart: {}", e.message))?;
    // 7. Promoted objects and Baselines remain valid.
    let v = ns
        .root
        .query(Query::ValidateBaseline { digest: baseline })
        .await
        .c()?;
    ensure(
        v["valid"] == true,
        format!("Baseline invalid after restart: {v}"),
    )?;
    // 8. Lease recovery: the lease expired while down, so the execution is LOST and its late
    //    effects are refused.
    let e: Execution = serde_json::from_value(
        ns.root
            .query(Query::GetExecution { execution: exe })
            .await
            .c()?,
    )
    .map_err(|e| e.to_string())?;
    ensure(
        e.state == ExecutionState::Lost,
        format!(
            "expired lease must be LOST after restart, found {:?}",
            e.state
        ),
    )?;
    expect_code(
        ns.root
            .command(Command::SubmitEffectProposal {
                execution: exe,
                lease: lease.id,
                effect: crate::ctx::kv_set("late", "1"),
            })
            .await,
        ErrorCode::ExecutionLost,
    )?;
    // 10. No half-promoted state: every PROMOTED pack has its snapshot, record and event.
    for ev in after.iter().filter(|e| e.kind == "changepack.promoted") {
        for k in ["promoted_pack", "promotion_record"] {
            let d: Digest =
                serde_json::from_value(ev.body[k].clone()).map_err(|e| format!("{k}: {e}"))?;
            ns.root.get_object(d).await.c()?;
        }
    }
    // 9. Tampered authoritative state fails closed and is never repaired.
    lifecycle_op(&l, |l| l.stop()).await?;
    let hex = promoted
        .to_string()
        .trim_start_matches("sha256:")
        .to_owned();
    let cas = l
        .data_root()
        .join("objects/sha256")
        .join(&hex[..2])
        .join(&hex);
    let bytes = std::fs::read(&cas).map_err(|e| format!("promoted object not in the CAS: {e}"))?;
    std::fs::remove_file(&cas).map_err(|e| e.to_string())?;
    ensure(
        lifecycle_op(&l, |l| l.start()).await.is_err(),
        "a data root missing committed bytes must not start",
    )?;
    ensure(!cas.exists(), "corrupt state must not be silently repaired")?;
    std::fs::write(&cas, &bytes).map_err(|e| e.to_string())?;
    lifecycle_op(&l, |l| l.start()).await?;
    ns.root.get_object(promoted).await.c().map(drop)
}

pub async fn recovery(cx: &Ctx) -> CaseResult {
    if cx.target.is_remote() {
        return match cx.target.lifecycle() {
            Some(l) => remote_recovery(cx, l).await,
            None => {
                // The consistency a restart must preserve is still checked, but a restart was not.
                let ns = cx.namespace().await?;
                observable(cx, &ns).await?;
                Err(format!(
                    "{}restart, lease recovery and tamper checks need control of the target's process and data root (no lifecycle controller)",
                    crate::NOT_EXERCISED
                ))
            }
        };
    }
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let id = Identity::generate();
    let open = || -> Result<Ctx, ProtocolError> {
        let store = SqliteStore::open(dir.path(), SqliteOptions::create())?;
        Ok(Ctx::new(Target::with_store(Arc::new(store), &id, None)?))
    };
    let (ns_id, key, root_id, pack, exe, promoted, events) = {
        let cx1 = open().c()?;
        let ns = cx1.namespace().await?;
        let promoted = observable(&cx1, &ns).await?;
        ns.root
            .command(Command::RegisterProvider {
                provider: crate::ctx::provider(ns.root_id, false),
            })
            .await
            .c()?;
        let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
        let wu = ns.root.add_work_unit(pack, 1, "org.x.t").await.c()?;
        let (exe, lease) = ns
            .root
            .start_execution(cx1.execution_request(pack, 2, wu, &[]))
            .await
            .c()?;
        ns.root.heartbeat(&lease).await.c()?;
        id.clock
            .set(lease.expires_at.unix_nanos() as i64 + 1_000_000);
        let events = cx1.events(&ns.root).await?;
        (
            ns.id,
            ns.root_key.clone(),
            ns.root_id,
            pack,
            exe,
            promoted,
            events,
        )
    };
    // A staged write left by a crash.
    let stray = dir.path().join("tmp").join("conformance-stray");
    std::fs::write(&stray, b"partial").map_err(|e| e.to_string())?;
    {
        let cx2 = open().c()?;
        ensure(
            !stray.exists(),
            "startup must discard staged temporary writes",
        )?;
        let root = cx2.client_for(ns_id, key.clone(), root_id);
        let after = cx2.events(&root).await?;
        ensure(
            after.len() > events.len() && after[..events.len()] == events[..],
            "restart preserves the journal",
        )?;
        ensure(
            after[events.len()..]
                .iter()
                .any(|e| e.kind == "execution.lost"),
            "startup marks expired leases LOST",
        )?;
        let e: Execution = serde_json::from_value(
            root.query(Query::GetExecution { execution: exe })
                .await
                .c()?,
        )
        .map_err(|e| e.to_string())?;
        ensure(
            e.state == ExecutionState::Lost,
            "expired lease must be LOST after restart",
        )?;
        ensure(
            root.get_change_pack(pack).await.c()?.state == PackState::Open,
            "state survives restart",
        )?;
        root.get_object(promoted).await.c()?;
    }
    // Missing committed bytes: fail closed, never repair.
    let hex = promoted
        .to_string()
        .trim_start_matches("sha256:")
        .to_owned();
    let cas = dir.path().join("objects/sha256").join(&hex[..2]).join(&hex);
    let bytes = std::fs::read(&cas).map_err(|e| format!("promoted object not in the CAS: {e}"))?;
    std::fs::remove_file(&cas).map_err(|e| e.to_string())?;
    expect_code(open(), ErrorCode::StorageIntegrityError)?;
    ensure(!cas.exists(), "corrupt state must not be silently repaired")?;
    std::fs::write(&cas, &bytes).map_err(|e| e.to_string())?;
    let cx3 = open().c()?;
    cx3.client_for(ns_id, key, root_id)
        .get_object(promoted)
        .await
        .c()
        .map(drop)
}

fn digests(v: &serde_json::Value) -> Result<Vec<Digest>, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

pub async fn exchange(cx: &Ctx) -> CaseResult {
    let a = cx.namespace().await?;
    let alice = cx.member(&a).await?;
    cx.grant(&a, alice.id, &["*"]).await?;
    let (_, p0) = cx.promote_empty(&alice.client).await?;
    let (_, p1) = cx.promote_empty(&alice.client).await?;
    let (_, unrelated) = cx.promote_empty(&alice.client).await?;
    let (baseline, bd) = a.root.create_baseline(vec![p0, p1], vec![]).await.c()?;
    let closure = digests(
        &a.root
            .query(Query::GetBaselineClosure { baseline })
            .await
            .c()?["objects"],
    )?;
    let set: BTreeSet<_> = closure.iter().collect();
    ensure(
        set.contains(&bd) && set.contains(&p0) && set.contains(&p1),
        "closure contains the root and its members",
    )?;
    ensure(
        !set.contains(&unrelated),
        "closure contains nothing unreachable from the root",
    )?;

    let b = cx.namespace().await?;
    let missing = digests(
        &b.root
            .query(Query::ComputeMissingObjects {
                digests: closure.clone(),
            })
            .await
            .c()?,
    )?;
    ensure(
        missing.len() == closure.len(),
        "a fresh Namespace sees none of another Namespace's objects",
    )?;
    // Import everything but one non-root object: the root is present, its closure is not.
    let withheld = *missing
        .iter()
        .find(|d| **d != bd)
        .ok_or("closure has only its root")?;
    let put = |d: Digest| {
        let (a, b) = (a.root.clone(), b.root.clone());
        async move {
            let bytes = a.get_object(d).await.c()?.bytes().to_vec();
            b.command(Command::PutImmutableObject { digest: d, bytes })
                .await
                .c()
        }
    };
    for d in missing.iter().filter(|d| **d != withheld) {
        put(*d).await?;
    }
    let partial = b
        .root
        .query(Query::GetObjectClosure { digest: bd })
        .await
        .c()?;
    ensure(
        partial["missing"] == json!([withheld]),
        format!("closure must report the withheld object: {partial}"),
    )?;
    let v = b
        .root
        .query(Query::ValidateBaseline { digest: bd })
        .await
        .c()?;
    ensure(
        v["valid"] == false,
        format!("a Baseline with an incomplete closure must not validate: {v}"),
    )?;
    put(withheld).await?;
    let v = b
        .root
        .query(Query::ValidateBaseline { digest: bd })
        .await
        .c()?;
    ensure(
        v["valid"] == true,
        format!("imported closure validates independently: {v}"),
    )?;
    let obj = b
        .root
        .query(Query::GetObjectClosure { digest: bd })
        .await
        .c()?;
    ensure(obj["missing"] == json!([]), "complete closure")?;

    // Imported grants, principals and manifests confer nothing.
    expect_code(
        b.root
            .query(Query::GetPrincipal {
                principal: alice.id,
            })
            .await,
        ErrorCode::NotFound,
    )?;
    let alice_on_b = cx.client_for(b.id, alice.key.clone(), alice.id);
    expect_code(
        alice_on_b.query(Query::GetNamespace {}).await,
        ErrorCode::Unauthorized,
    )?;
    ensure(
        b.root.query(Query::ListExtensions {}).await.c()? == json!([]),
        "imported manifests register nothing",
    )?;

    // Accepted objects never change: re-import is a no-op, altered bytes are refused.
    let before = b.root.get_object(p0).await.c()?;
    put(p0).await?;
    let mut altered = before.bytes().to_vec();
    if let Some(x) = altered.last_mut() {
        *x ^= 1;
    }
    expect_code(
        b.root
            .command(Command::PutImmutableObject {
                digest: p0,
                bytes: altered,
            })
            .await,
        ErrorCode::DigestMismatch,
    )?;
    ensure(
        b.root.get_object(p0).await.c()? == before,
        "stored objects are immutable",
    )
}

/// AEVC-XCH-0003: imported objects are inert — they never authorize, gate, or become accepted
/// state in the importing Namespace.
pub async fn inert_imports(cx: &Ctx) -> CaseResult {
    let a = cx.namespace().await?;
    let b = cx.namespace().await?;
    let copy = |d: Digest| {
        let (a, b) = (a.root.clone(), b.root.clone());
        async move {
            let bytes = a.get_object(d).await.c()?.bytes().to_vec();
            b.command(Command::PutImmutableObject { digest: d, bytes })
                .await
                .c()
        }
    };
    // A promoted pack (with its whole closure) imported from A is not a member B may accept.
    let (_, promoted) = cx.promote_empty(&a.root).await?;
    let closure = a
        .root
        .query(Query::GetPackClosure { digest: promoted })
        .await
        .c()?;
    for d in serde_json::from_value::<Vec<Digest>>(closure["objects"].clone())
        .map_err(|e| e.to_string())?
    {
        copy(d).await?;
    }
    expect_code(
        b.root.create_baseline(vec![promoted], vec![]).await,
        ErrorCode::InvalidArgument,
    )
    .map_err(|e| format!("imported promoted pack as Baseline member: {e}"))?;

    // A policy registered in A is imported into B; it cannot gate a pack in B.
    let doc: PolicyDocument = serde_json::from_value(json!({"name": "org.openaevc.conformance.inert", "rules": [{"id": "pass", "expr": {"verifier": {"kind": "kv.expect", "status": "PASS"}}}]}))
        .map_err(|e| e.to_string())?;
    let policy = a
        .root
        .command(Command::RegisterPolicy {
            document: doc,
            mandatory: false,
        })
        .await
        .c()?
        .result
        .digest
        .ok_or("policy digest")?;
    copy(policy).await?;
    let spec = PackSpec {
        required_policies: vec![policy],
        ..Default::default()
    };
    expect_code(
        b.root.create_change_pack(spec).await,
        ErrorCode::InvalidArgument,
    )
    .map_err(|e| format!("imported policy as a gate: {e}"))?;

    // A grant signed by B's root but never issued in B, imported as an object, can neither
    // authorize its subject nor serve as a delegation parent.
    let m = cx.member(&b).await?;
    cx.grant(&b, m.id, &["grant.issue"]).await?;
    let body = cx.grant_body(b.id, b.root_id, m.id, &["*"], None, 1);
    let signed = openaevc::authority::sign_grant(body, b.root_key.as_ref()).c()?;
    let env = ObjectEnvelope {
        kind: ObjectKind::CapabilityGrant,
        protocol_version: PROTOCOL_VERSION,
        namespace: b.id,
        id: Some(signed.body.id.to_string()),
        created_seq: 1,
        creator: b.root_id,
        body: serde_json::to_value(&signed).map_err(|e| e.to_string())?,
        signatures: vec![],
    };
    let obj = openaevc::core::ImmutableObject::build(env).c()?;
    b.root
        .command(Command::PutImmutableObject {
            digest: obj.digest(),
            bytes: obj.bytes().to_vec(),
        })
        .await
        .c()?;
    expect_code(
        m.client.create_change_pack(PackSpec::default()).await,
        ErrorCode::Forbidden,
    )
    .map_err(|e| format!("imported grant authorized its subject: {e}"))?;
    let child = cx.grant_body(
        b.id,
        m.id,
        m.id,
        &["changepack.create"],
        Some(obj.digest()),
        0,
    );
    expect_code(m.client.issue_grant(child).await, ErrorCode::Forbidden)
        .map_err(|e| format!("imported grant accepted as a parent: {e}"))?;
    expect_code(
        m.client.create_change_pack(PackSpec::default()).await,
        ErrorCode::Forbidden,
    )
    .map(drop)
}
