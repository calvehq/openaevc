//! RUNTIME profile: lifecycle, Active Change Graph, execution, evidence, verification,
//! evaluation, policy, promotion, revisions, Baselines, composition, events, transport.

use std::collections::BTreeMap;
use std::time::Duration;

use openaevc::protocol::*;
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::json;

use crate::ctx::{ensure, expect_code, fresh, kv_set, Check, Ctx, Ns};
use crate::CaseResult;

fn gen_err(r: Result<CommandReceipt, ProtocolError>, expected: u64, actual: u64) -> CaseResult {
    let e = expect_code(r, ErrorCode::StaleGeneration)?;
    ensure(
        e.expected_generation == Some(expected) && e.actual_generation == Some(actual),
        "STALE_GENERATION must report both generations",
    )
}

pub async fn generations(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    ensure(
        ns.root.get_change_pack(pack).await.c()?.generation == 1,
        "creation yields generation 1",
    )?;
    ns.root
        .add_work_unit(pack, 1, "org.openaevc.conformance.task")
        .await
        .c()?;
    gen_err(
        ns.root
            .command(Command::AddWorkUnit {
                pack,
                expected_generation: 1,
                kind: "org.x.t".into(),
                spec: None,
                depends_on: vec![],
            })
            .await,
        1,
        2,
    )?;
    let g1: ChangePack = serde_json::from_value(
        ns.root
            .query(Query::GetChangePack {
                pack,
                generation: Some(1),
            })
            .await
            .c()?,
    )
    .map_err(|e| e.to_string())?;
    ensure(
        g1.work_units.is_empty() && g1.generation == 1,
        "historical generations stay queryable",
    )
}

pub async fn sealing(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let wu = ns.root.add_work_unit(pack, 1, "org.x.t").await.c()?;
    ns.root
        .command(Command::RegisterProvider {
            provider: crate::ctx::provider(ns.root_id, false),
        })
        .await
        .c()?;
    let (exe, _) = ns
        .root
        .start_execution(cx.execution_request(pack, 2, wu, &[]))
        .await
        .c()?;
    expect_code(ns.root.seal(pack, 2).await, ErrorCode::Conflict)?;
    ns.root
        .command(Command::CancelExecution {
            execution: exe,
            reason: None,
        })
        .await
        .c()?;
    let candidate = ns.root.seal(pack, 2).await.c()?;
    let obj = ns.root.get_object(candidate).await.c()?;
    ensure(
        obj.kind() == ObjectKind::Candidate,
        "seal must freeze a candidate object",
    )?;
    expect_code(
        ns.root
            .command(Command::AddWorkUnit {
                pack,
                expected_generation: 2,
                kind: "org.x.t".into(),
                spec: None,
                depends_on: vec![],
            })
            .await,
        ErrorCode::InvalidTransition,
    )
    .map(drop)
}

pub async fn reopen_invalidates(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    cx.setup_kv(&ns).await?;
    let gate: PolicyDocument = serde_json::from_value(json!({"name": "org.openaevc.conformance.gate", "rules": [{"id": "pass", "expr": {"verifier": {"kind": "kv.expect", "status": "PASS"}}}]})).map_err(|e| e.to_string())?;
    ns.root
        .command(Command::RegisterPolicy {
            document: gate,
            mandatory: true,
        })
        .await
        .c()?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let g = cx
        .run_effects(&ns.root, pack, vec![kv_set("a", "1")])
        .await?;
    let cand = ns.root.seal(pack, g).await.c()?;
    ns.root
        .run_verification(pack, g, "kv.expect", json!({"key": "a", "value": "1"}))
        .await
        .c()?;
    ensure(
        ns.root
            .refresh_qualification(pack, g)
            .await
            .c()?
            .result
            .state
            .as_deref()
            == Some("QUALIFIED"),
        "qualifies",
    )?;
    ns.root
        .command(Command::ReopenChangePack {
            pack,
            expected_generation: g,
        })
        .await
        .c()?;
    let p = ns.root.get_change_pack(pack).await.c()?;
    ensure(
        p.generation == g + 1 && p.state == PackState::Open && p.qualification.is_none(),
        "reopen increments the generation and clears qualification",
    )?;
    ns.root.seal(pack, g + 1).await.c()?;
    ensure(
        ns.root
            .refresh_qualification(pack, g + 1)
            .await
            .c()?
            .result
            .state
            .as_deref()
            == Some("SEALED"),
        "earlier-generation verification must not qualify",
    )?;
    let old = ns.root.command(Command::RegisterEvidence {
        pack,
        generation: g,
        candidate: cand,
        kind: "org.x.e".into(),
        payload: Blob {
            media_type: "text/plain".into(),
            data: b"old".to_vec(),
        },
        schema: None,
        sources: vec![],
        extension: None,
    });
    expect_code(old.await, ErrorCode::EvidenceInvalid).map(drop)
}

pub async fn terminal(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let (pack, _) = cx.promote_empty(&ns.root).await?;
    for c in [
        Command::ReopenChangePack {
            pack,
            expected_generation: 1,
        },
        Command::AddWorkUnit {
            pack,
            expected_generation: 1,
            kind: "org.x.t".into(),
            spec: None,
            depends_on: vec![],
        },
        Command::AbandonChangePack {
            pack,
            expected_generation: 1,
        },
        Command::PromoteChangePack {
            pack,
            generation: 1,
        },
    ] {
        let name = c.name();
        expect_code(ns.root.command(c).await, ErrorCode::ImmutableObject)
            .map_err(|e| format!("{name}: {e}"))?;
    }
    let abandoned = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    ns.root
        .command(Command::AbandonChangePack {
            pack: abandoned,
            expected_generation: 1,
        })
        .await
        .c()?;
    expect_code(
        ns.root
            .command(Command::SealChangePack {
                pack: abandoned,
                expected_generation: 1,
            })
            .await,
        ErrorCode::InvalidTransition,
    )?;
    expect_code(
        ns.root
            .command(Command::PromoteChangePack {
                pack: abandoned,
                generation: 1,
            })
            .await,
        ErrorCode::InvalidTransition,
    )
    .map(drop)
}

pub async fn quarantine(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    ns.root.seal(pack, 1).await.c()?;
    ns.root
        .command(Command::QuarantineChangePack {
            pack,
            reason: "conformance".into(),
        })
        .await
        .c()?;
    expect_code(
        ns.root
            .command(Command::ReopenChangePack {
                pack,
                expected_generation: 1,
            })
            .await,
        ErrorCode::Quarantined,
    )?;
    expect_code(
        ns.root
            .command(Command::PromoteChangePack {
                pack,
                generation: 1,
            })
            .await,
        ErrorCode::Quarantined,
    )?;
    ns.root
        .command(Command::ReleaseQuarantine { pack })
        .await
        .c()?;
    ensure(
        ns.root.get_change_pack(pack).await.c()?.state == PackState::Sealed,
        "release restores the previous state",
    )?;
    let m = cx.member(&ns).await?;
    cx.grant(&ns, m.id, &["changepack.*"]).await?;
    expect_code(
        m.client
            .command(Command::QuarantineChangePack {
                pack,
                reason: "x".into(),
            })
            .await,
        ErrorCode::Forbidden,
    )
    .map(drop)
}

pub async fn requires_qualification(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    expect_code(ns.root.promote(pack, 1).await, ErrorCode::NotQualified)?;
    ns.root.seal(pack, 1).await.c()?;
    expect_code(ns.root.promote(pack, 1).await, ErrorCode::NotQualified).map(drop)
}

pub async fn graph(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let a = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let b = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let wa = ns.root.add_work_unit(a, 1, "org.x.t").await.c()?;
    let wb: WorkUnitId = ns
        .root
        .command(Command::AddWorkUnit {
            pack: b,
            expected_generation: 1,
            kind: "org.x.t".into(),
            spec: None,
            depends_on: vec![NodeRef::from(wa)],
        })
        .await
        .c()?
        .result
        .id
        .and_then(|s| s.parse().ok())
        .ok_or("work unit id")?;
    // Runtime-owned edge kinds are refused; missing nodes and cycles are reported.
    expect_code(
        ns.root
            .command(Command::AddActiveDependency {
                pack: a,
                expected_generation: 2,
                from: wa.into(),
                to: wb.into(),
                kind: ActiveEdgeKind::Produces,
                annotations: BTreeMap::new(),
            })
            .await,
        ErrorCode::InvalidArgument,
    )?;
    expect_code(
        ns.root
            .command(Command::AddActiveDependency {
                pack: a,
                expected_generation: 2,
                from: wa.into(),
                to: NodeRef::from(fresh::<WorkUnitId>()),
                kind: ActiveEdgeKind::DependsOn,
                annotations: BTreeMap::new(),
            })
            .await,
        ErrorCode::DependencyMissing,
    )?;
    let e = expect_code(
        ns.root
            .command(Command::AddActiveDependency {
                pack: a,
                expected_generation: 2,
                from: wa.into(),
                to: wb.into(),
                kind: ActiveEdgeKind::DependsOn,
                annotations: BTreeMap::new(),
            })
            .await,
        ErrorCode::DependencyCycle,
    )?;
    ensure(
        e.cycle.first() == e.cycle.last() && e.cycle.len() >= 3,
        "cycle must be reported first-node-repeated",
    )?;
    // Readiness: wa ready, wb blocked on wa.
    let ready = ns
        .root
        .query(Query::GetReadyWork { pack: None })
        .await
        .c()?;
    ensure(
        ready.as_array().is_some_and(|r| {
            r.iter().any(|w| w["work_unit"] == wa.to_string())
                && !r.iter().any(|w| w["work_unit"] == wb.to_string())
        }),
        "readiness",
    )?;
    let blocked = ns
        .root
        .query(Query::GetBlockedWork { pack: None })
        .await
        .c()?;
    ensure(
        blocked
            .as_array()
            .is_some_and(|r| r.iter().any(|w| w["work_unit"] == wb.to_string())),
        "blocked work must be reported",
    )
}

pub async fn admission(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let wu = ns.root.add_work_unit(pack, 1, "org.x.t").await.c()?;
    // Unknown provider.
    expect_code(
        ns.root
            .start_execution(cx.execution_request(pack, 2, wu, &[]))
            .await,
        ErrorCode::NotFound,
    )?;
    ns.root
        .command(Command::RegisterProvider {
            provider: crate::ctx::provider(ns.root_id, false),
        })
        .await
        .c()?;
    // Stale generation; unknown effect kind.
    expect_code(
        ns.root
            .start_execution(cx.execution_request(pack, 1, wu, &[]))
            .await,
        ErrorCode::StaleGeneration,
    )?;
    expect_code(
        ns.root
            .start_execution(cx.execution_request(pack, 2, wu, &["org.nowhere.effect"]))
            .await,
        ErrorCode::ExtensionIncompatible,
    )?;
    // Idempotency key returns the same execution; a second active attempt conflicts.
    let req = cx.execution_request(pack, 2, wu, &[]);
    let (e1, _) = ns.root.start_execution(req.clone()).await.c()?;
    let (e2, _) = ns.root.start_execution(req).await.c()?;
    ensure(e1 == e2, "idempotency key must return the same execution")?;
    expect_code(
        ns.root
            .start_execution(cx.execution_request(pack, 2, wu, &[]))
            .await,
        ErrorCode::Conflict,
    )?;
    // Not ready.
    let g = ns.root.get_change_pack(pack).await.c()?.generation;
    let blocked: WorkUnitId = ns
        .root
        .command(Command::AddWorkUnit {
            pack,
            expected_generation: g,
            kind: "org.x.t".into(),
            spec: None,
            depends_on: vec![NodeRef::from(wu)],
        })
        .await
        .c()?
        .result
        .id
        .and_then(|s| s.parse().ok())
        .ok_or("id")?;
    ns.root
        .command(Command::CancelExecution {
            execution: e1,
            reason: None,
        })
        .await
        .c()?;
    expect_code(
        ns.root
            .start_execution(cx.execution_request(pack, g + 1, blocked, &[]))
            .await,
        ErrorCode::ExecutionNotReady,
    )
    .map(drop)
}

pub async fn scope_authority(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    cx.setup_kv(&ns).await?;
    let m = cx.member(&ns).await?;
    cx.grant(
        &ns,
        m.id,
        &["changepack.*", "execution.start", "namespace.read"],
    )
    .await?;
    let pack = m.client.create_change_pack(PackSpec::default()).await.c()?;
    let wu = m.client.add_work_unit(pack, 1, "org.x.t").await.c()?;
    let e = expect_code(
        m.client
            .start_execution(cx.execution_request(pack, 2, wu, &["kv.set"]))
            .await,
        ErrorCode::Forbidden,
    )?;
    ensure(
        e.missing_action.as_deref() == Some("kv.write"),
        "admission must require the effect's actions over the scope",
    )?;
    let mut body = cx.grant_body(ns.id, ns.root_id, m.id, &["kv.write"], None, 0);
    body.resources = vec![ResourceSelector {
        kind: "kv.entry".into(),
        locator_prefix: Some("app/".into()),
    }];
    ns.root.issue_grant(body).await.c()?;
    let mut req = cx.execution_request(pack, 2, wu, &["kv.set"]);
    req.allowed_resources = vec![ResourceSelector {
        kind: "kv.entry".into(),
        locator_prefix: Some("app/".into()),
    }];
    let (_, lease) = m.client.start_execution(req).await.c()?;
    ensure(
        m.client
            .submit_effect(&lease, kv_set("app/x", "1"))
            .await
            .c()?,
        "in-scope effect applies",
    )?;
    expect_code(
        m.client.submit_effect(&lease, kv_set("etc/x", "1")).await,
        ErrorCode::Forbidden,
    )?;
    let delete = EffectProposal {
        kind: "kv.delete".into(),
        payload: json!({}),
        ..kv_set("app/x", "")
    };
    expect_code(
        m.client.submit_effect(&lease, delete).await,
        ErrorCode::Forbidden,
    )
    .map(drop)
}

pub async fn worker_rules(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    ns.root
        .command(Command::RegisterProvider {
            provider: crate::ctx::provider(ns.root_id, false),
        })
        .await
        .c()?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let wu = ns.root.add_work_unit(pack, 1, "org.x.t").await.c()?;
    let (_, lease) = ns
        .root
        .start_execution(cx.execution_request(pack, 2, wu, &[]))
        .await
        .c()?;
    let mut wrong = lease.clone();
    wrong.id = fresh();
    expect_code(ns.root.heartbeat(&wrong).await, ErrorCode::Forbidden)?;
    let other = cx.member(&ns).await?;
    cx.grant(&ns, other.id, &["execution.start"]).await?;
    expect_code(other.client.heartbeat(&lease).await, ErrorCode::Forbidden)?;
    ns.root.heartbeat(&lease).await.c()?;
    let e: Execution = serde_json::from_value(
        ns.root
            .query(Query::GetExecution {
                execution: lease.execution,
            })
            .await
            .c()?,
    )
    .map_err(|e| e.to_string())?;
    ensure(
        e.state == ExecutionState::Running,
        "first worker command moves the execution to RUNNING",
    )
}

pub async fn lost(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
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
    cx.target.advance_past(lease.expires_at).await;
    // Any command in the Namespace sweeps expired leases.
    ns.root.query(Query::GetNamespace {}).await.c()?;
    let _ = ns
        .root
        .command(Command::CreateChangePack {
            spec: PackSpec::default(),
        })
        .await;
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
            "expired lease must make the execution LOST (state {:?})",
            e.state
        ),
    )?;
    expect_code(
        ns.root.complete_execution(&lease).await,
        ErrorCode::ExecutionLost,
    )?;
    expect_code(ns.root.heartbeat(&lease).await, ErrorCode::ExecutionLost)?;
    let mut retry = cx.execution_request(pack, 2, wu, &[]);
    retry.retry_of = Some(exe);
    let (next, _) = ns.root.start_execution(retry).await.c()?;
    let n: Execution = serde_json::from_value(
        ns.root
            .query(Query::GetExecution { execution: next })
            .await
            .c()?,
    )
    .map_err(|e| e.to_string())?;
    ensure(
        n.attempt == 2 && n.retry_of == Some(exe),
        "retry must increment the attempt and link the previous one",
    )?;
    let graph = ns
        .root
        .query(Query::GetActiveChangeGraph { pack: None })
        .await
        .c()?;
    ensure(
        graph["edges"].as_array().is_some_and(|es| {
            es.iter().any(|e| {
                e["kind"] == "DERIVED_FROM"
                    && e["from"] == next.to_string()
                    && e["to"] == exe.to_string()
            })
        }),
        "retry must record a DERIVED_FROM edge",
    )
}

pub async fn effects(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    cx.setup_kv(&ns).await?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let wu = ns.root.add_work_unit(pack, 1, "org.x.t").await.c()?;
    let (exe, lease) = ns
        .root
        .start_execution(cx.execution_request(pack, 2, wu, &["kv.set"]))
        .await
        .c()?;
    // Workers keep the lease alive; extension invocations can be slow on a loaded target.
    ns.root.heartbeat(&lease).await.c()?;
    let mut bad = kv_set("a", "1");
    bad.preconditions = vec![json!({"equals": "nope"})];
    ensure(
        !ns.root.submit_effect(&lease, bad).await.c()?,
        "a rejected proposal is reported as not applied",
    )?;
    ensure(
        cx.events(&ns.root)
            .await?
            .iter()
            .any(|e| e.kind == "effect.rejected"),
        "rejections are recorded",
    )?;
    ns.root.heartbeat(&lease).await.c()?;
    ensure(
        ns.root.submit_effect(&lease, kv_set("a", "1")).await.c()?,
        "valid effect applies",
    )?;
    ns.root.heartbeat(&lease).await.c()?;
    let obs = ns
        .root
        .command(Command::AppendObservation {
            execution: exe,
            lease: lease.id,
            kind: "org.x.obs".into(),
            payload: Some(json!({"n": 1})),
            blob: None,
            related_resources: vec![],
            related_effects: vec![],
        })
        .await
        .c()?;
    let p = ns.root.get_change_pack(pack).await.c()?;
    let prov = &p
        .candidate_effects
        .first()
        .ok_or("no applied effect")?
        .provenance;
    ensure(
        prov.execution == exe
            && prov.generation == 2
            && prov.pack == pack
            && prov.extension.is_some()
            && !prov.harness.is_empty()
            && !prov.provider.is_empty(),
        "applied effects carry complete provenance",
    )?;
    let o = ns
        .root
        .get_object(obs.result.digest.ok_or("observation digest")?)
        .await
        .c()?;
    let body: Observation = o.body().c()?;
    ensure(
        body.generation == 2 && body.execution == exe,
        "observations identify the exact generation",
    )?;
    // Structural change during execution invalidates further effects.
    ns.root.heartbeat(&lease).await.c()?;
    ns.root.add_work_unit(pack, 2, "org.x.t").await.c()?;
    expect_code(
        ns.root
            .command(Command::SubmitEffectProposal {
                execution: exe,
                lease: lease.id,
                effect: kv_set("b", "1"),
            })
            .await,
        ErrorCode::StaleGeneration,
    )
    .map(drop)
}

pub async fn evidence(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let blob = Blob {
        media_type: "text/plain".into(),
        data: b"conformance".to_vec(),
    };
    let bogus = openaevc::crypto::sha256(b"not-a-candidate");
    expect_code(
        ns.root
            .command(Command::RegisterEvidence {
                pack,
                generation: 1,
                candidate: bogus,
                kind: "org.x.e".into(),
                payload: blob.clone(),
                schema: None,
                sources: vec![],
                extension: None,
            })
            .await,
        ErrorCode::EvidenceInvalid,
    )?;
    let cand = ns.root.seal(pack, 1).await.c()?;
    expect_code(
        ns.root
            .command(Command::RegisterEvidence {
                pack,
                generation: 1,
                candidate: bogus,
                kind: "org.x.e".into(),
                payload: blob.clone(),
                schema: None,
                sources: vec![],
                extension: None,
            })
            .await,
        ErrorCode::EvidenceInvalid,
    )?;
    let r = ns
        .root
        .command(Command::RegisterEvidence {
            pack,
            generation: 1,
            candidate: cand,
            kind: "org.x.e".into(),
            payload: blob,
            schema: None,
            sources: vec![],
            extension: None,
        })
        .await
        .c()?;
    let e: Evidence = ns
        .root
        .get_object(r.result.digest.ok_or("digest")?)
        .await
        .c()?
        .body()
        .c()?;
    ensure(
        e.candidate == cand && e.generation == 1,
        "evidence binds to the sealed candidate",
    )
}

async fn kv_sealed(
    cx: &Ctx,
    ns: &Ns,
    effects: Vec<EffectProposal>,
) -> Result<(PackId, u64), String> {
    cx.setup_kv(ns).await?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let g = cx.run_effects(&ns.root, pack, effects).await?;
    ns.root.seal(pack, g).await.c()?;
    Ok((pack, g))
}

pub async fn verification(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let open = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    expect_code(
        ns.root
            .run_verification(open, 1, "kv.expect", json!({}))
            .await,
        ErrorCode::InvalidTransition,
    )?;
    let (pack, g) = kv_sealed(cx, &ns, vec![kv_set("a", "1")]).await?;
    expect_code(
        ns.root
            .run_verification(pack, g + 5, "kv.expect", json!({}))
            .await,
        ErrorCode::StaleGeneration,
    )?;
    let pass = ns
        .root
        .run_verification(pack, g, "kv.expect", json!({"key": "a", "value": "1"}))
        .await
        .c()?;
    let fail = ns
        .root
        .run_verification(pack, g, "kv.expect", json!({"key": "a", "value": "2"}))
        .await
        .c()?;
    ensure(
        pass.result.digest != fail.result.digest,
        "reruns create new result objects",
    )?;
    let v: VerificationResult = ns
        .root
        .get_object(pass.result.digest.ok_or("digest")?)
        .await
        .c()?
        .body()
        .c()?;
    ensure(
        v.status == VerificationStatus::Pass && v.generation == g,
        "result records status and subject",
    )?;
    let gate: PolicyDocument = serde_json::from_value(json!({"name": "org.openaevc.conformance.vgate", "rules": [{"id": "pass", "expr": {"verifier": {"kind": "kv.expect", "status": "PASS"}}}]})).map_err(|e| e.to_string())?;
    ns.root
        .command(Command::RegisterPolicy {
            document: gate,
            mandatory: true,
        })
        .await
        .c()?;
    ensure(
        ns.root
            .refresh_qualification(pack, g)
            .await
            .c()?
            .result
            .state
            .as_deref()
            == Some("SEALED"),
        "latest FAIL must deny",
    )?;
    ns.root
        .run_verification(pack, g, "kv.expect", json!({"key": "a", "value": "1"}))
        .await
        .c()?;
    ensure(
        ns.root
            .refresh_qualification(pack, g)
            .await
            .c()?
            .result
            .state
            .as_deref()
            == Some("QUALIFIED"),
        "latest PASS qualifies",
    )?;
    ns.root
        .run_verification(pack, g, "kv.expect", json!({"key": "a", "value": "1"}))
        .await
        .c()?;
    ensure(
        ns.root.get_change_pack(pack).await.c()?.state == PackState::Sealed,
        "new results disqualify until refreshed",
    )
}

pub async fn evaluation(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let (pack, g) = kv_sealed(cx, &ns, vec![kv_set("a", "1"), kv_set("b", "2")]).await?;
    let r = ns
        .root
        .run_evaluation(pack, g, "kv.size", json!({"max_keys": 1}))
        .await
        .c()?;
    let e: EvaluationResult = ns
        .root
        .get_object(r.result.digest.ok_or("digest")?)
        .await
        .c()?
        .body()
        .c()?;
    ensure(
        e.verdict == EvaluationVerdict::Deny && e.metrics.get("kv.keys") == Some(&2),
        "evaluation result records verdict and metrics",
    )?;
    let m = cx.member(&ns).await?;
    cx.grant(&ns, m.id, &["evaluation.run", "namespace.read"])
        .await?;
    m.client
        .run_evaluation(pack, g, "kv.size", json!({"max_keys": 9}))
        .await
        .c()?;
    expect_code(m.client.promote(pack, g).await, ErrorCode::Forbidden).map(drop)
}

pub async fn policy(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    for bad in [
        json!({"name": "nonamespace", "rules": [{"id": "r", "expr": {"all": []}}]}),
        json!({"name": "org.x.p", "rules": []}),
        json!({"name": "org.x.p", "rules": [{"id": "r", "expr": {"exists": {"fact": "bare"}}}]}),
    ] {
        let doc: PolicyDocument = serde_json::from_value(bad.clone()).map_err(|e| e.to_string())?;
        expect_code(
            ns.root
                .command(Command::RegisterPolicy {
                    document: doc,
                    mandatory: false,
                })
                .await,
            ErrorCode::InvalidArgument,
        )
        .map_err(|e| format!("{bad}: {e}"))?;
    }
    // Unknown operators do not decode.
    let v = cx.signed_value(&ns.root_key, ns.root_id, Some(ns.id), json!({"type": "RegisterPolicy", "document": {"name": "org.x.p", "rules": [{"id": "r", "expr": {"script": "true"}}]}}), |_| {});
    expect_code(cx.target.command_value(v).await, ErrorCode::InvalidArgument)?;
    // A pack's own policy cannot remove the mandatory gate.
    let never: PolicyDocument = serde_json::from_value(
        json!({"name": "org.x.never", "rules": [{"id": "no", "expr": {"any": []}}]}),
    )
    .map_err(|e| e.to_string())?;
    let always: PolicyDocument = serde_json::from_value(
        json!({"name": "org.x.always", "rules": [{"id": "yes", "expr": {"all": []}}]}),
    )
    .map_err(|e| e.to_string())?;
    ns.root
        .command(Command::RegisterPolicy {
            document: never,
            mandatory: true,
        })
        .await
        .c()?;
    let pd = ns
        .root
        .command(Command::RegisterPolicy {
            document: always,
            mandatory: false,
        })
        .await
        .c()?
        .result
        .digest
        .ok_or("digest")?;
    let pack = ns
        .root
        .create_change_pack(PackSpec {
            required_policies: vec![pd],
            ..Default::default()
        })
        .await
        .c()?;
    ns.root.seal(pack, 1).await.c()?;
    let first = ns.root.refresh_qualification(pack, 1).await.c()?;
    let second = ns.root.refresh_qualification(pack, 1).await.c()?;
    ensure(
        first.result.state.as_deref() == Some("SEALED"),
        "mandatory policies always apply",
    )?;
    let a: PolicyDecision = ns
        .root
        .get_object(first.result.digest.ok_or("digest")?)
        .await
        .c()?
        .body()
        .c()?;
    let b: PolicyDecision = ns
        .root
        .get_object(second.result.digest.ok_or("digest")?)
        .await
        .c()?
        .body()
        .c()?;
    ensure(
        a.outcome == DecisionOutcome::Deny
            && a.outcome == b.outcome
            && a.rules == b.rules
            && a.facts == b.facts,
        "same inputs must give the same decision",
    )?;
    ensure(
        a.policies.len() == 2,
        "decision records every evaluated policy",
    )?;
    // Policy never authorizes: an allowing decision still requires changepack.promote.
    let ns2 = cx.namespace().await?;
    let m = cx.member(&ns2).await?;
    cx.grant(
        &ns2,
        m.id,
        &[
            "changepack.create",
            "changepack.seal",
            "verification.run",
            "namespace.read",
        ],
    )
    .await?;
    let p2 = m.client.create_change_pack(PackSpec::default()).await.c()?;
    m.client.seal(p2, 1).await.c()?;
    ensure(
        m.client
            .refresh_qualification(p2, 1)
            .await
            .c()?
            .result
            .state
            .as_deref()
            == Some("QUALIFIED"),
        "qualifies without gates",
    )?;
    expect_code(m.client.promote(p2, 1).await, ErrorCode::Forbidden).map(drop)
}

pub async fn promotion(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    // Gates are re-checked at promotion.
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    ns.root.seal(pack, 1).await.c()?;
    ns.root.refresh_qualification(pack, 1).await.c()?;
    let dep = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    ns.root
        .command(Command::AddActiveDependency {
            pack: dep,
            expected_generation: 1,
            from: dep.into(),
            to: pack.into(),
            kind: ActiveEdgeKind::DependsOn,
            annotations: BTreeMap::new(),
        })
        .await
        .c()?;
    ns.root.seal(dep, 2).await.c()?;
    ns.root.refresh_qualification(dep, 2).await.c()?;
    expect_code(ns.root.promote(dep, 2).await, ErrorCode::DependencyMissing)?;
    let promoted = ns.root.promote(pack, 1).await.c()?;
    let dep_promoted = ns.root.promote(dep, 2).await.c()?;
    let body: PromotedPack = ns.root.get_object(dep_promoted).await.c()?.body().c()?;
    ensure(
        body.dependencies == vec![promoted],
        "dependencies are recorded by promoted digest",
    )?;
    let gated = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    ns.root.seal(gated, 1).await.c()?;
    ns.root.refresh_qualification(gated, 1).await.c()?;
    let never: PolicyDocument = serde_json::from_value(
        json!({"name": "org.x.late", "rules": [{"id": "no", "expr": {"any": []}}]}),
    )
    .map_err(|e| e.to_string())?;
    ns.root
        .command(Command::RegisterPolicy {
            document: never,
            mandatory: true,
        })
        .await
        .c()?;
    expect_code(ns.root.promote(gated, 1).await, ErrorCode::PolicyDenied)?;
    // Atomic visibility: state, objects and event agree.
    let p = ns.root.get_change_pack(pack).await.c()?;
    let info = p.promotion.ok_or("promotion info")?;
    let record = ns.root.get_object(info.promotion_record).await.c()?;
    ensure(
        record.kind() == ObjectKind::PromotionRecord && info.promoted_pack == promoted,
        "promotion writes record and snapshot together",
    )?;
    ensure(
        cx.events(&ns.root).await?.iter().any(|e| {
            e.kind == "changepack.promoted" && e.body["promoted_pack"] == promoted.to_string()
        }),
        "promotion event",
    )?;
    // The closure is complete.
    let closure = ns
        .root
        .query(Query::GetPackClosure { digest: promoted })
        .await
        .c()?;
    ensure(
        closure["missing"].as_array().is_some_and(Vec::is_empty),
        "promoted pack validates from present immutable objects",
    )
}

pub async fn revisions(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    cx.setup_kv(&ns).await?;
    expect_code(
        ns.root
            .command(Command::CreateRevisionPack {
                relation: RevisionRelation::Reverts,
                targets: vec![],
                spec: PackSpec::default(),
            })
            .await,
        ErrorCode::InvalidArgument,
    )?;
    expect_code(
        ns.root
            .command(Command::CreateRevisionPack {
                relation: RevisionRelation::Reverts,
                targets: vec![openaevc::crypto::sha256(b"x")],
                spec: PackSpec::default(),
            })
            .await,
        ErrorCode::NotFound,
    )?;
    let (_, p0) = cx.promote_kv(&ns.root, "feature", "on").await?;
    let before = ns.root.get_object(p0).await.c()?;
    let r = ns
        .root
        .command(Command::CreateRevisionPack {
            relation: RevisionRelation::Reverts,
            targets: vec![p0],
            spec: PackSpec::default(),
        })
        .await
        .c()?;
    let rpk: PackId = r
        .result
        .id
        .and_then(|s| s.parse().ok())
        .ok_or("revision id")?;
    let delete = EffectProposal {
        kind: "kv.delete".into(),
        payload: json!({}),
        ..kv_set("feature", "")
    };
    let g = cx.run_effects(&ns.root, rpk, vec![delete]).await?;
    let promoted = cx.finish(&ns.root, rpk, g).await?;
    let body: PromotedPack = ns.root.get_object(promoted).await.c()?.body().c()?;
    ensure(
        body.revision
            == Some(RevisionInfo {
                relation: RevisionRelation::Reverts,
                targets: vec![p0],
            }),
        "promoted revision records its relation",
    )?;
    ensure(
        ns.root.get_object(p0).await.c()? == before,
        "targets are never modified",
    )
}

pub async fn baselines(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let (_, a) = cx.promote_empty(&ns.root).await?;
    let (_, b) = cx.promote_empty(&ns.root).await?;
    let (b1, d1) = ns.root.create_baseline(vec![a], vec![]).await.c()?;
    let before = ns
        .root
        .query(Query::GetBaseline { baseline: b1 })
        .await
        .c()?;
    let (_, d2) = ns.root.create_baseline(vec![a, b], vec![]).await.c()?;
    ensure(
        ns.root
            .query(Query::GetBaseline { baseline: b1 })
            .await
            .c()?
            == before,
        "existing Baselines never change",
    )?;
    ensure(d1 != d2, "each Baseline is a new object")?;
    expect_code(
        ns.root
            .create_baseline(vec![openaevc::crypto::sha256(b"none")], vec![])
            .await,
        ErrorCode::NotFound,
    )?;
    let not_promoted = ns
        .root
        .command(Command::CreateChangePack {
            spec: PackSpec::default(),
        })
        .await
        .c()?
        .receipt;
    expect_code(
        ns.root.create_baseline(vec![not_promoted], vec![]).await,
        ErrorCode::InvalidArgument,
    )?;
    let limit: PolicyDocument = serde_json::from_value(json!({"name": "org.x.pair", "rules": [{"id": "two", "expr": {"ge": {"fact": "composition.members", "value": 2}}}]})).map_err(|e| e.to_string())?;
    let pd = ns
        .root
        .command(Command::RegisterPolicy {
            document: limit,
            mandatory: false,
        })
        .await
        .c()?
        .result
        .digest
        .ok_or("digest")?;
    expect_code(
        ns.root
            .command(Command::CreateBaseline {
                members: vec![a],
                edges: vec![],
                policies: vec![pd],
                metadata: BTreeMap::new(),
            })
            .await,
        ErrorCode::PolicyDenied,
    )?;
    let v = ns
        .root
        .query(Query::ValidateBaseline { digest: d2 })
        .await
        .c()?;
    ensure(
        v["valid"] == true,
        format!("ValidateBaseline must re-derive the graph: {v}"),
    )
}

pub async fn composition(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let (_, a) = cx.promote_empty(&ns.root).await?;
    let (_, b) = cx.promote_empty(&ns.root).await?;
    // Dependencies must be members.
    let dep = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let a_pack = ns
        .root
        .get_object(a)
        .await
        .c()?
        .body::<PromotedPack>()
        .c()?
        .pack;
    ns.root
        .command(Command::AddActiveDependency {
            pack: dep,
            expected_generation: 1,
            from: dep.into(),
            to: a_pack.into(),
            kind: ActiveEdgeKind::DependsOn,
            annotations: BTreeMap::new(),
        })
        .await
        .c()?;
    let d = cx.finish(&ns.root, dep, 2).await?;
    expect_code(
        ns.root.create_baseline(vec![d], vec![]).await,
        ErrorCode::DependencyMissing,
    )?;
    // Caller edges: only ordering between members.
    let order = |from, to| CompositionEdge {
        from,
        to,
        kind: CompositionEdgeKind::OrdersAfter,
        relation: None,
    };
    expect_code(
        ns.root.create_baseline(vec![a], vec![order(a, b)]).await,
        ErrorCode::CompositionInvalid,
    )?;
    expect_code(
        ns.root
            .create_baseline(
                vec![a, b],
                vec![CompositionEdge {
                    from: a,
                    to: b,
                    kind: CompositionEdgeKind::ConflictsWith,
                    relation: None,
                }],
            )
            .await,
        ErrorCode::CompositionInvalid,
    )?;
    // Cycles.
    let e = expect_code(
        ns.root
            .create_baseline(vec![a, b], vec![order(a, b), order(b, a)])
            .await,
        ErrorCode::DependencyCycle,
    )?;
    ensure(!e.cycle.is_empty(), "cycle reported")?;
    // Declared conflicts.
    let c = ns
        .root
        .create_change_pack(PackSpec {
            conflicts_with: vec![a],
            ..Default::default()
        })
        .await
        .c()?;
    let dc = cx.finish(&ns.root, c, 1).await?;
    expect_code(
        ns.root.create_baseline(vec![a, dc], vec![]).await,
        ErrorCode::CompositionInvalid,
    )?;
    // Lineage: REVERTS needs its target; two SUPERSEDES of one target are ambiguous.
    let revert = ns
        .root
        .command(Command::CreateRevisionPack {
            relation: RevisionRelation::Reverts,
            targets: vec![b],
            spec: PackSpec::default(),
        })
        .await
        .c()?;
    let rv = cx
        .finish(
            &ns.root,
            revert.result.id.and_then(|s| s.parse().ok()).ok_or("id")?,
            1,
        )
        .await?;
    expect_code(
        ns.root.create_baseline(vec![rv], vec![]).await,
        ErrorCode::CompositionInvalid,
    )?;
    let mut sup = Vec::new();
    for _ in 0..2 {
        let r = ns
            .root
            .command(Command::CreateRevisionPack {
                relation: RevisionRelation::Supersedes,
                targets: vec![b],
                spec: PackSpec::default(),
            })
            .await
            .c()?;
        sup.push(
            cx.finish(
                &ns.root,
                r.result.id.and_then(|s| s.parse().ok()).ok_or("id")?,
                1,
            )
            .await?,
        );
    }
    expect_code(
        ns.root
            .create_baseline(vec![b, sup[0], sup[1]], vec![])
            .await,
        ErrorCode::CompositionInvalid,
    )?;
    let (_, ok) = ns.root.create_baseline(vec![b, sup[0]], vec![]).await.c()?;
    let bl: Baseline = ns.root.get_object(ok).await.c()?.body().c()?;
    ensure(bl.heads == vec![sup[0]], "superseded members are not heads")?;
    // Determinism: same members in another order give the same graph.
    let (_, x) = ns.root.create_baseline(vec![a, b], vec![]).await.c()?;
    let (_, y) = ns.root.create_baseline(vec![b, a], vec![]).await.c()?;
    let (bx, by): (Baseline, Baseline) = (
        ns.root.get_object(x).await.c()?.body().c()?,
        ns.root.get_object(y).await.c()?.body().c()?,
    );
    ensure(
        bx.graph_digest == by.graph_digest && bx.members == by.members && bx.edges == by.edges,
        "canonicalization must be deterministic",
    )
}

pub async fn events(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let before = cx.events(&ns.root).await?.len();
    ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let events = cx.events(&ns.root).await?;
    ensure(events.len() > before, "commands append events")?;
    ensure(
        events
            .iter()
            .enumerate()
            .all(|(i, e)| e.sequence == i as u64 + 1),
        "sequences start at 1 without gaps",
    )?;
    openaevc::core::events::verify_chain(&events, 0, Digest::ZERO)
        .map_err(|e| format!("hash chain: {}", e.message))?;
    // Checkpoints.
    let interval = cx.target.checkpoint_interval();
    let mut n = events.len() as u64;
    while n < interval {
        ns.root.create_change_pack(PackSpec::default()).await.c()?;
        n = cx.events(&ns.root).await?.len() as u64;
    }
    let cp = ns.root.query(Query::GetJournalCheckpoint {}).await.c()?;
    let seq = cp["envelope"]["body"]["sequence"]
        .as_u64()
        .ok_or("checkpoint sequence")?;
    ensure(
        seq % interval == 0
            && !cp["envelope"]["signatures"]
                .as_array()
                .is_none_or(Vec::is_empty),
        "checkpoints are signed at interval multiples",
    )?;
    let all = cx.events(&ns.root).await?;
    let at = all
        .iter()
        .find(|e| e.sequence == seq)
        .ok_or("checkpointed event")?;
    ensure(
        cp["envelope"]["body"]["event_hash"] == at.hash.to_string(),
        "checkpoint commits to the journal hash",
    )?;
    // Subscription resume delivers exactly what follows the cursor.
    let cursor = all.last().map(|e| e.sequence).unwrap_or(0);
    let mut stream = ns
        .root
        .subscribe(EventFilter {
            namespace: ns.id,
            after: cursor,
            kinds: vec![],
            subjects: vec![],
        })
        .await
        .c()?;
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let next = tokio::time::timeout(Duration::from_secs(20), stream.next())
        .await
        .map_err(|_| "no event delivered")?
        .ok_or("stream ended")?
        .c()?;
    ensure(
        next.sequence == cursor + 1 && next.subjects.contains(&pack.to_string()),
        "resume must deliver the next event",
    )
}

pub async fn transport(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    // Explicit empty optional fields are accepted; the signature covers what was sent.
    let v = cx.signed_value(
        &ns.root_key,
        ns.root_id,
        Some(ns.id),
        json!({"type": "ListEvents", "after": 0, "kinds": []}),
        |_| {},
    );
    cx.target.query_value(v).await.c()?;
    // Payload bytes must match the signed digest.
    let (_, promoted) = cx.promote_empty(&ns.root).await?;
    let bytes = ns.root.get_object(promoted).await.c()?.bytes().to_vec();
    let wrong = openaevc::crypto::sha256(b"other");
    let env = cx.envelope_value(
        &ns.root_key,
        ns.root_id,
        Some(ns.id),
        Command::PutImmutableObject {
            digest: wrong,
            bytes: vec![],
        },
    )?;
    expect_code(
        cx.target.put_object_payload(env, wrong, bytes).await,
        ErrorCode::DigestMismatch,
    )?;
    // Subscriptions filtered by subject resume from the cursor.
    let pack = ns.root.create_change_pack(PackSpec::default()).await.c()?;
    let mut stream = ns
        .root
        .subscribe(EventFilter {
            namespace: ns.id,
            after: 0,
            kinds: vec![],
            subjects: vec![pack.to_string()],
        })
        .await
        .c()?;
    let e = tokio::time::timeout(Duration::from_secs(20), stream.next())
        .await
        .map_err(|_| "timeout")?
        .ok_or("ended")?
        .c()?;
    ensure(e.subjects.contains(&pack.to_string()), "subject filter")?;
    // Remote listeners on non-loopback addresses must use TLS.
    if let crate::target::Target::Remote(r) = &cx.target {
        if let openaevc::transport::client::Endpoint::Tcp(addr) = &r.endpoint {
            let ip: Option<std::net::IpAddr> = addr
                .rsplit_once(':')
                .and_then(|(h, _)| h.trim_matches(['[', ']']).parse().ok());
            ensure(
                ip.is_none_or(|ip| ip.is_loopback()),
                "plaintext TCP is only acceptable on loopback",
            )?;
        }
    }
    Ok(())
}

/// AEVC-EXE-0009: a provider registration belongs to its principal; nobody else may replace it
/// (and so take over driving its executions).
pub async fn provider_ownership(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let owner = cx.member(&ns).await?;
    let other = cx.member(&ns).await?;
    for m in [&owner, &other] {
        cx.grant(&ns, m.id, &["provider.register"]).await?;
    }
    let register = |c: &crate::target::Client, p: PrincipalId| {
        let c = c.clone();
        async move {
            c.command(Command::RegisterProvider {
                provider: crate::ctx::provider(p, false),
            })
            .await
        }
    };
    register(&owner.client, owner.id).await.c()?;
    let e = expect_code(
        register(&other.client, other.id).await,
        ErrorCode::Forbidden,
    )?;
    ensure(
        e.missing_action.as_deref() == Some("provider.register"),
        "hijack refusal names provider.register",
    )?;
    // The owner and a root may update it.
    register(&owner.client, owner.id).await.c()?;
    register(&ns.root, owner.id).await.c().map(drop)
}
