//! AUTHORITY profile: authentication, default deny, capabilities, delegation, revocation,
//! replay protection, Namespace isolation.

use openaevc_crypto::SigningKey;
use openaevc_protocol::*;
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::json;
use std::collections::BTreeMap;

use crate::ctx::{ensure, expect_code, fresh, key_principal, kv_set, provider, Check, Ctx};
use crate::CaseResult;

pub async fn unauthenticated(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    // Unknown caller.
    let stranger = SigningKey::generate();
    let v = cx.signed_value(
        &stranger,
        fresh(),
        Some(ns.id),
        json!({"type": "GetNamespace"}),
        |_| {},
    );
    expect_code(cx.target.query_value(v).await, ErrorCode::Unauthorized)?;
    // Missing signature.
    let mut v = cx.signed_value(
        &ns.root_key,
        ns.root_id,
        Some(ns.id),
        json!({"type": "GetNamespace"}),
        |_| {},
    );
    v.as_object_mut().ok_or("object")?.remove("signature");
    expect_code(cx.target.query_value(v).await, ErrorCode::Unauthorized)?;
    // An ACTOR cannot authenticate directly.
    let actor = ns
        .root
        .register_principal(NewPrincipal {
            kind: PrincipalKind::Actor,
            public_key: None,
            linked_to: Some(ns.root_id),
            attributes: BTreeMap::new(),
        })
        .await
        .c()?;
    let v = cx.signed_value(
        &ns.root_key,
        actor,
        Some(ns.id),
        json!({"type": "GetNamespace"}),
        |_| {},
    );
    expect_code(cx.target.query_value(v).await, ErrorCode::Unauthorized).map(drop)
}

pub async fn act_as(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let alice = cx.member(&ns).await?;
    let bob = cx.member(&ns).await?;
    let attrs = BTreeMap::from([(
        "org.openaevc.conformance.kind".to_string(),
        "agent".to_string(),
    )]);
    let actor = ns
        .root
        .register_principal(NewPrincipal {
            kind: PrincipalKind::Actor,
            public_key: None,
            linked_to: Some(alice.id),
            attributes: attrs,
        })
        .await
        .c()?;
    cx.grant(&ns, actor, &["namespace.read"]).await?;
    let as_actor = cx.target.client(
        cx.target
            .session(alice.key.clone(), alice.id, Some(ns.id))
            .act_as(actor),
    );
    as_actor.query(Query::GetNamespace {}).await.c()?;
    expect_code(
        alice.client.query(Query::GetNamespace {}).await,
        ErrorCode::Forbidden,
    )?;
    let bob_as = cx.target.client(
        cx.target
            .session(bob.key.clone(), bob.id, Some(ns.id))
            .act_as(actor),
    );
    expect_code(
        bob_as.query(Query::GetNamespace {}).await,
        ErrorCode::Forbidden,
    )
    .map(drop)
}

pub async fn default_deny(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let m = cx.member(&ns).await?;
    expect_code(
        m.client.create_change_pack(PackSpec::default()).await,
        ErrorCode::Forbidden,
    )?;
    expect_code(
        m.client.query(Query::GetNamespace {}).await,
        ErrorCode::Forbidden,
    )?;
    cx.grant(&ns, m.id, &["changepack.create"]).await?;
    m.client.create_change_pack(PackSpec::default()).await.c()?;
    expect_code(
        m.client
            .command(Command::SealChangePack {
                pack: PackId::Change(fresh()),
                expected_generation: 1,
            })
            .await,
        ErrorCode::Forbidden,
    )?;
    // Roots hold every action: they pass authorization and reach the lookup.
    expect_code(
        ns.root
            .command(Command::SealChangePack {
                pack: PackId::Change(fresh()),
                expected_generation: 1,
            })
            .await,
        ErrorCode::NotFound,
    )
    .map(drop)
}

fn command_samples(
    cx: &Ctx,
    ns: NamespaceId,
    subject: PrincipalId,
    issuer: &SigningKey,
) -> Vec<Command> {
    let d = openaevc_crypto::sha256(b"conformance");
    let pack = PackId::Change(fresh());
    let (exe, lease, wu): (ExecutionId, LeaseId, WorkUnitId) = (fresh(), fresh(), fresh());
    let doc: PolicyDocument = serde_json::from_value(
        json!({"name": "org.x.p", "rules": [{"id": "r", "expr": {"all": []}}]}),
    )
    .unwrap_or_else(|_| PolicyDocument {
        name: "org.x.p".into(),
        description: None,
        rules: vec![],
    });
    let grant = openaevc_authority::sign_grant(
        cx.grant_body(ns, subject, subject, &["*"], None, 0),
        issuer,
    )
    .ok();
    let mut v = vec![
        Command::RegisterPrincipal {
            principal: key_principal(&SigningKey::generate()),
        },
        Command::RevokeCapabilityGrant {
            grant: fresh(),
            reason: None,
        },
        Command::RegisterPolicy {
            document: doc,
            mandatory: true,
        },
        Command::RegisterExtension {
            entrypoint: "x".into(),
            artifact_digest: d,
            approved_host_capabilities: vec![],
        },
        Command::UnregisterExtension {
            extension: "org.x.y".into(),
        },
        Command::RegisterProvider {
            provider: provider(subject, false),
        },
        Command::CreateChangePack {
            spec: PackSpec::default(),
        },
        Command::CreateRevisionPack {
            relation: RevisionRelation::Amends,
            targets: vec![d],
            spec: PackSpec::default(),
        },
        Command::UpdateChangePack {
            pack,
            expected_generation: 1,
            intent: None,
            resource_refs: None,
            required_policies: None,
            extension_bindings: None,
            conflicts_with: None,
            metadata: None,
        },
        Command::AddWorkUnit {
            pack,
            expected_generation: 1,
            kind: "org.x.t".into(),
            spec: None,
            depends_on: vec![],
        },
        Command::UpdateWorkUnit {
            pack,
            expected_generation: 1,
            work_unit: wu,
            spec: None,
            state: None,
        },
        Command::AddActiveDependency {
            pack,
            expected_generation: 1,
            from: pack.into(),
            to: wu.into(),
            kind: ActiveEdgeKind::DependsOn,
            annotations: BTreeMap::new(),
        },
        Command::RemoveActiveDependency {
            pack,
            expected_generation: 1,
            from: pack.into(),
            to: wu.into(),
            kind: ActiveEdgeKind::DependsOn,
        },
        Command::SealChangePack {
            pack,
            expected_generation: 1,
        },
        Command::ReopenChangePack {
            pack,
            expected_generation: 1,
        },
        Command::AbandonChangePack {
            pack,
            expected_generation: 1,
        },
        Command::QuarantineChangePack {
            pack,
            reason: "x".into(),
        },
        Command::ReleaseQuarantine { pack },
        Command::StartExecution {
            request: cx.execution_request(pack, 1, wu, &["kv.set"]),
        },
        Command::HeartbeatExecution {
            execution: exe,
            lease,
            generation: 1,
        },
        Command::CancelExecution {
            execution: exe,
            reason: None,
        },
        Command::SubmitEffectProposal {
            execution: exe,
            lease,
            effect: kv_set("a", "b"),
        },
        Command::AppendObservation {
            execution: exe,
            lease,
            kind: "org.x.o".into(),
            payload: Some(json!({})),
            blob: None,
            related_resources: vec![],
            related_effects: vec![],
        },
        Command::CompleteExecution {
            execution: exe,
            lease,
        },
        Command::FailExecution {
            execution: exe,
            lease,
            reason: "x".into(),
        },
        Command::RegisterEvidence {
            pack,
            generation: 1,
            candidate: d,
            kind: "org.x.e".into(),
            payload: Blob {
                media_type: "text/plain".into(),
                data: vec![1],
            },
            schema: None,
            sources: vec![],
            extension: None,
        },
        Command::RunVerification {
            pack,
            generation: 1,
            verifier: "org.x.v".into(),
            config: None,
            evidence: vec![],
        },
        Command::RunEvaluation {
            pack,
            generation: 1,
            evaluator: "org.x.e".into(),
            config: None,
            inputs: vec![],
        },
        Command::RefreshQualification {
            pack,
            generation: 1,
        },
        Command::PromoteChangePack {
            pack,
            generation: 1,
        },
        Command::CreateBaseline {
            members: vec![d],
            edges: vec![],
            policies: vec![],
            metadata: BTreeMap::new(),
        },
        Command::PutImmutableObject {
            digest: d,
            bytes: vec![0],
        },
    ];
    if let Some(g) = grant {
        v.push(Command::IssueCapabilityGrant { grant: g });
    }
    v
}

fn query_samples(subject: PrincipalId) -> Vec<Query> {
    let d = openaevc_crypto::sha256(b"conformance");
    let pack = PackId::Change(fresh());
    vec![
        Query::GetRuntimeInfo {},
        Query::GetNamespace {},
        Query::GetPrincipal { principal: subject },
        Query::GetGrant { grant: fresh() },
        Query::Authorize {
            principal: subject,
            action: "x.y".into(),
            resource: None,
        },
        Query::GetChangePack {
            pack,
            generation: None,
        },
        Query::GetRevisionPack {
            pack,
            generation: None,
        },
        Query::GetActiveChangeGraph { pack: None },
        Query::GetNode {
            node: NodeRef::Digest(d),
        },
        Query::GetDependencyClosure {
            node: NodeRef::Digest(d),
            reverse: false,
        },
        Query::GetAffectedNodes {
            node: NodeRef::Digest(d),
        },
        Query::GetReadyWork { pack: None },
        Query::GetBlockedWork { pack: None },
        Query::GetExecution { execution: fresh() },
        Query::ListExecutions {
            pack: None,
            state: None,
        },
        Query::GetEvidence { digest: d },
        Query::GetVerification { digest: d },
        Query::GetEvaluation { digest: d },
        Query::GetPolicyDecision { digest: d },
        Query::GetPromotedPack {
            pack: None,
            digest: Some(d),
        },
        Query::GetBaseline { baseline: fresh() },
        Query::ValidateBaseline { digest: d },
        Query::GetBaselineClosure { baseline: fresh() },
        Query::GetObjectClosure { digest: d },
        Query::GetPackClosure { digest: d },
        Query::GetObject { digest: d },
        Query::HasObject { digests: vec![d] },
        Query::ComputeMissingObjects { digests: vec![d] },
        Query::ListObjectDigests {
            kind: None,
            after: None,
            limit: None,
        },
        Query::ListEvents {
            after: 0,
            limit: None,
            kinds: vec![],
        },
        Query::GetJournalCheckpoint {},
        Query::ListExtensions {},
    ]
}

pub async fn every_entry_point(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let m = cx.member(&ns).await?;
    let commands = command_samples(cx, ns.id, m.id, &m.key);
    let names: std::collections::BTreeSet<&str> = commands.iter().map(Command::name).collect();
    ensure(
        names.len() == Command::NAMES.len() - 1,
        "every command except CreateNamespace must be sampled",
    )?;
    for c in commands {
        let name = c.name();
        expect_code(m.client.command(c).await, ErrorCode::Forbidden)
            .map_err(|e| format!("{name}: {e}"))?;
    }
    for q in query_samples(m.id) {
        let name = q.name();
        expect_code(m.client.query(q).await, ErrorCode::Forbidden)
            .map_err(|e| format!("{name}: {e}"))?;
    }
    // Only administrators create Namespaces.
    let v = cx.signed_value(
        &m.key,
        m.id,
        None,
        json!({"type": "CreateNamespace", "root_principals": [key_principal(&m.key)]}),
        |_| {},
    );
    expect_code(cx.target.command_value(v).await, ErrorCode::Unauthorized).map(drop)
}

pub async fn replay(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let body = json!({"type": "CreateChangePack", "spec": {}});
    // Outside the freshness window.
    let old = Timestamp::from_unix_nanos(cx.target.now().unix_nanos() - 3_600_000_000_000);
    let v = cx.signed_value(&ns.root_key, ns.root_id, Some(ns.id), body.clone(), |v| {
        v["issued_at"] = json!(old)
    });
    expect_code(cx.target.command_value(v).await, ErrorCode::ReplayDetected)?;
    // Expired.
    let v = cx.signed_value(&ns.root_key, ns.root_id, Some(ns.id), body.clone(), |v| {
        v["expires_at"] = json!(old)
    });
    expect_code(cx.target.command_value(v).await, ErrorCode::ReplayDetected)?;
    // Nonce reuse with a different request ID.
    let first = cx.signed_value(&ns.root_key, ns.root_id, Some(ns.id), body.clone(), |_| {});
    cx.target.command_value(first.clone()).await.c()?;
    let nonce = first["nonce"].clone();
    let again = cx.signed_value(&ns.root_key, ns.root_id, Some(ns.id), body, |v| {
        v["nonce"] = nonce
    });
    expect_code(
        cx.target.command_value(again).await,
        ErrorCode::ReplayDetected,
    )
    .map(drop)
}

pub async fn idempotency(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let v = cx.signed_value(
        &ns.root_key,
        ns.root_id,
        Some(ns.id),
        json!({"type": "CreateChangePack", "spec": {}}),
        |_| {},
    );
    let a = cx.target.command_value(v.clone()).await.c()?;
    let before = cx.events(&ns.root).await?.len();
    let b = cx.target.command_value(v.clone()).await.c()?;
    ensure(a == b, "a retried request must return the original receipt")?;
    ensure(
        cx.events(&ns.root).await?.len() == before,
        "a retried request must not re-execute",
    )?;
    let rid = v["request_id"].clone();
    let other = cx.signed_value(
        &ns.root_key,
        ns.root_id,
        Some(ns.id),
        json!({"type": "CreateChangePack", "spec": {"metadata": {"org.x.a": 1}}}),
        |v| v["request_id"] = rid,
    );
    expect_code(
        cx.target.command_value(other).await,
        ErrorCode::ReplayDetected,
    )
    .map(drop)
}

pub async fn denial_audit(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let m = cx.member(&ns).await?;
    expect_code(
        m.client.create_change_pack(PackSpec::default()).await,
        ErrorCode::Forbidden,
    )?;
    let last = cx.events(&ns.root).await?.pop().ok_or("no events")?;
    ensure(
        last.kind == "authorization.denied"
            && last.actor == Some(m.id)
            && last.body["action"] == "changepack.create",
        format!("denial not audited: {last:?}"),
    )?;
    // An authenticated caller refused `act_as` is audited too, as are denied reads.
    let other = cx.member(&ns).await?;
    let as_other = cx.target.client(
        cx.target
            .session(m.key.clone(), m.id, Some(ns.id))
            .act_as(other.id),
    );
    expect_code(
        as_other.query(Query::GetNamespace {}).await,
        ErrorCode::Forbidden,
    )?;
    let last = cx.events(&ns.root).await?.pop().ok_or("no events")?;
    ensure(
        last.kind == "authorization.denied" && last.actor == Some(m.id),
        format!("act_as denial not audited: {last:?}"),
    )?;
    expect_code(
        m.client.query(Query::GetNamespace {}).await,
        ErrorCode::Forbidden,
    )?;
    let last = cx.events(&ns.root).await?.pop().ok_or("no events")?;
    ensure(
        last.kind == "authorization.denied" && last.body["action"] == "namespace.read",
        format!("query denial not audited: {last:?}"),
    )
}

/// AEVC-CAP-0006: protocol 0.1 enforces no constraints, so grants carrying one are refused.
pub async fn constraints(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let m = cx.member(&ns).await?;
    let mut body = cx.grant_body(ns.id, ns.root_id, m.id, &["changepack.create"], None, 0);
    body.constraints
        .insert("org.example.max-effects".into(), json!(1));
    expect_code(ns.root.issue_grant(body).await, ErrorCode::InvalidArgument)?;
    expect_code(
        m.client.create_change_pack(PackSpec::default()).await,
        ErrorCode::Forbidden,
    )
    .map(drop)
}

/// AEVC-CAP-0007: a resource-scoped grant never confers non-resource actions.
pub async fn resource_scoped(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let m = cx.member(&ns).await?;
    let mut body = cx.grant_body(ns.id, ns.root_id, m.id, &["*"], None, 0);
    body.resources = vec![ResourceSelector {
        kind: "kv.entry".into(),
        locator_prefix: Some("app/".into()),
    }];
    ns.root.issue_grant(body).await.c()?;
    for (what, r) in [
        (
            "changepack.create",
            m.client
                .create_change_pack(PackSpec::default())
                .await
                .map(drop),
        ),
        (
            "grant.issue",
            m.client
                .issue_grant(cx.grant_body(ns.id, m.id, m.id, &["*"], None, 0))
                .await
                .map(drop),
        ),
        (
            "namespace.read",
            m.client.query(Query::GetNamespace {}).await.map(drop),
        ),
    ] {
        let e = expect_code(r, ErrorCode::Forbidden).map_err(|e| format!("{what}: {e}"))?;
        ensure(
            e.missing_action.as_deref() == Some(what),
            format!("{what}: missing_action {:?}", e.missing_action),
        )?;
    }
    Ok(())
}

pub async fn grant_validity(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let m = cx.member(&ns).await?;
    // Forged: signed by someone other than the issuer.
    let forged = openaevc_authority::sign_grant(
        cx.grant_body(ns.id, ns.root_id, m.id, &["*"], None, 0),
        m.key.as_ref(),
    )
    .c()?;
    expect_code(
        ns.root
            .command(Command::IssueCapabilityGrant { grant: forged })
            .await,
        ErrorCode::Unauthorized,
    )?;
    // Tampered after signing.
    let mut g = openaevc_authority::sign_grant(
        cx.grant_body(ns.id, ns.root_id, m.id, &["namespace.read"], None, 0),
        ns.root_key.as_ref(),
    )
    .c()?;
    g.body.actions.insert("*".into());
    expect_code(
        ns.root
            .command(Command::IssueCapabilityGrant { grant: g })
            .await,
        ErrorCode::Unauthorized,
    )?;
    // Expired window.
    let mut b = cx.grant_body(ns.id, ns.root_id, m.id, &["namespace.read"], None, 0);
    b.not_before = Timestamp::from_unix_nanos(b.not_before.unix_nanos() - 7_200_000_000_000);
    b.expires_at = Timestamp::from_unix_nanos(b.not_before.unix_nanos() + 1_000_000_000);
    expect_code(ns.root.issue_grant(b).await, ErrorCode::CapabilityExpired).map(drop)
}

pub async fn rooted(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let alice = cx.member(&ns).await?;
    let bob = cx.member(&ns).await?;
    cx.grant(&ns, alice.id, &["grant.issue"]).await?;
    let b = cx.grant_body(ns.id, alice.id, bob.id, &["namespace.read"], None, 0);
    expect_code(alice.client.issue_grant(b).await, ErrorCode::Forbidden).map(drop)
}

pub async fn delegation(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let alice = cx.member(&ns).await?;
    let bob = cx.member(&ns).await?;
    let pb = cx.grant_body(
        ns.id,
        ns.root_id,
        alice.id,
        &["changepack.*", "grant.issue", "namespace.read"],
        None,
        1,
    );
    let parent = ns.root.issue_grant(pb.clone()).await.c()?;
    // Widening actions, not decreasing depth and outliving the parent are refused.
    let mut wide = cx.grant_body(
        ns.id,
        alice.id,
        bob.id,
        &["baseline.create"],
        Some(parent),
        0,
    );
    wide.expires_at = pb.expires_at;
    expect_code(alice.client.issue_grant(wide).await, ErrorCode::Forbidden)?;
    let mut deep = cx.grant_body(
        ns.id,
        alice.id,
        bob.id,
        &["changepack.create"],
        Some(parent),
        1,
    );
    deep.expires_at = pb.expires_at;
    expect_code(alice.client.issue_grant(deep).await, ErrorCode::Forbidden)?;
    let mut long = cx.grant_body(
        ns.id,
        alice.id,
        bob.id,
        &["changepack.create"],
        Some(parent),
        0,
    );
    long.expires_at = pb.expires_at.plus_millis(1_000);
    expect_code(alice.client.issue_grant(long).await, ErrorCode::Forbidden)?;
    let mut ok = cx.grant_body(
        ns.id,
        alice.id,
        bob.id,
        &["changepack.create"],
        Some(parent),
        0,
    );
    ok.expires_at = pb.expires_at;
    ok.not_before = pb.not_before;
    alice.client.issue_grant(ok).await.c()?;
    bob.client
        .create_change_pack(PackSpec::default())
        .await
        .c()
        .map(drop)
}

pub async fn issuer_submits(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let alice = cx.member(&ns).await?;
    cx.grant(&ns, alice.id, &["grant.issue"]).await?;
    let root_signed = openaevc_authority::sign_grant(
        cx.grant_body(ns.id, ns.root_id, alice.id, &["*"], None, 0),
        ns.root_key.as_ref(),
    )
    .c()?;
    expect_code(
        alice
            .client
            .command(Command::IssueCapabilityGrant { grant: root_signed })
            .await,
        ErrorCode::Forbidden,
    )
    .map(drop)
}

pub async fn revocation(cx: &Ctx) -> CaseResult {
    let ns = cx.namespace().await?;
    let alice = cx.member(&ns).await?;
    let bob = cx.member(&ns).await?;
    let pb = cx.grant_body(
        ns.id,
        ns.root_id,
        alice.id,
        &["changepack.create", "grant.issue"],
        None,
        1,
    );
    let parent_id = pb.id;
    let parent = ns.root.issue_grant(pb.clone()).await.c()?;
    let mut cb = cx.grant_body(
        ns.id,
        alice.id,
        bob.id,
        &["changepack.create"],
        Some(parent),
        0,
    );
    cb.expires_at = pb.expires_at;
    cb.not_before = pb.not_before;
    alice.client.issue_grant(cb).await.c()?;
    bob.client
        .create_change_pack(PackSpec::default())
        .await
        .c()?;
    ns.root
        .command(Command::RevokeCapabilityGrant {
            grant: parent_id,
            reason: None,
        })
        .await
        .c()?;
    expect_code(
        bob.client.create_change_pack(PackSpec::default()).await,
        ErrorCode::CapabilityRevoked,
    )?;
    expect_code(
        alice.client.create_change_pack(PackSpec::default()).await,
        ErrorCode::CapabilityRevoked,
    )
    .map(drop)
}

pub async fn namespaces(cx: &Ctx) -> CaseResult {
    let a = cx.namespace().await?;
    let b = cx.namespace().await?;
    // Envelopes must name their Namespace.
    let v = cx.signed_value(
        &a.root_key,
        a.root_id,
        None,
        json!({"type": "GetNamespace"}),
        |_| {},
    );
    expect_code(cx.target.query_value(v).await, ErrorCode::InvalidArgument)?;
    // Principals and objects are Namespace-scoped.
    let cross = cx.client_for(b.id, a.root_key.clone(), a.root_id);
    expect_code(
        cross.query(Query::GetNamespace {}).await,
        ErrorCode::Unauthorized,
    )?;
    let (_, promoted) = cx.promote_empty(&a.root).await?;
    expect_code(b.root.get_object(promoted).await, ErrorCode::NotFound)?;
    // Namespaced names.
    let spec = PackSpec {
        metadata: BTreeMap::from([("title".to_string(), json!("x"))]),
        ..Default::default()
    };
    expect_code(
        a.root.create_change_pack(spec).await,
        ErrorCode::InvalidArgument,
    )?;
    Ok(())
}
