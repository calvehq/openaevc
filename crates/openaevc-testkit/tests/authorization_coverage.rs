//! Architecture test (PLAN §54, AEVC-INV-004): every command and query passes authorization.
//! An authenticated principal without grants is refused on every entry point, and nothing but
//! `authorization.denied` audit events is written.

use std::collections::BTreeSet;

use openaevc::protocol::*;
use openaevc_testkit::*;
use serde_json::json;

fn samples(h: &Harness, ns: NamespaceId, subject: PrincipalId, issuer: &Identity) -> Vec<Command> {
    let d = openaevc::crypto::sha256(b"any");
    let pack = PackId::Change(h.ids_next());
    let exe: ExecutionId = h.ids_next();
    let lease: LeaseId = h.ids_next();
    let wu: WorkUnitId = h.ids_next();
    let doc: PolicyDocument = serde_json::from_value(
        json!({"name": "org.x.p", "rules": [{"id": "r", "expr": {"all": []}}]}),
    )
    .unwrap();
    vec![
        Command::RegisterPrincipal {
            principal: Identity::generate().new_principal(),
        },
        Command::IssueCapabilityGrant {
            grant: h.sign_grant(issuer, ns, subject, &["*"], None),
        },
        Command::RevokeCapabilityGrant {
            grant: h.ids_next(),
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
            provider: provider_descriptor(subject, false),
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
            kind: "org.x.task".into(),
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
            annotations: Default::default(),
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
            request: h.execution_request(pack, 1, wu),
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
            metadata: Default::default(),
        },
        Command::PutImmutableObject {
            digest: d,
            bytes: vec![0],
        },
    ]
}

fn query_samples(h: &Harness, subject: PrincipalId) -> Vec<Query> {
    let d = openaevc::crypto::sha256(b"any");
    let pack = PackId::Change(h.ids_next());
    let node = NodeRef::Digest(d);
    vec![
        Query::GetRuntimeInfo {},
        Query::GetNamespace {},
        Query::GetPrincipal { principal: subject },
        Query::GetGrant {
            grant: h.ids_next(),
        },
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
        Query::GetNode { node: node.clone() },
        Query::GetDependencyClosure {
            node: node.clone(),
            reverse: false,
        },
        Query::GetAffectedNodes { node },
        Query::GetReadyWork { pack: None },
        Query::GetBlockedWork { pack: None },
        Query::GetExecution {
            execution: h.ids_next(),
        },
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
        Query::GetBaseline {
            baseline: h.ids_next(),
        },
        Query::ValidateBaseline { digest: d },
        Query::GetBaselineClosure {
            baseline: h.ids_next(),
        },
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

#[test]
fn every_command_requires_authority() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let mallory = h.register_key_principal(&root, ns);
    let cmds = samples(&h, ns, mallory.id(), &mallory);
    let names: BTreeSet<&str> = cmds.iter().map(Command::name).collect();
    let expected: BTreeSet<&str> = Command::NAMES
        .iter()
        .copied()
        .filter(|n| *n != "CreateNamespace")
        .collect();
    assert_eq!(names, expected, "every command variant must be covered");
    let before = h.events(&root, ns).len();
    for c in &cmds {
        let e = h.client(&mallory, ns).cmd(c.clone()).unwrap_err();
        assert_eq!(
            e.code,
            ErrorCode::Forbidden,
            "{} returned {:?}",
            c.name(),
            e
        );
    }
    // CreateNamespace is reserved for runtime administrators.
    let e = h
        .admin_client_as(&mallory)
        .cmd(Command::CreateNamespace {
            root_principals: vec![mallory.new_principal()],
            metadata: Default::default(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unauthorized);
    let events = h.events(&root, ns);
    assert_eq!(events.len(), before + cmds.len());
    assert!(events[before..]
        .iter()
        .all(|e| e["kind"] == "authorization.denied"));
}

#[test]
fn every_query_requires_authority() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let mallory = h.register_key_principal(&root, ns);
    let qs = query_samples(&h, mallory.id());
    let names: BTreeSet<&str> = qs.iter().map(Query::name).collect();
    assert_eq!(
        names,
        Query::NAMES.iter().copied().collect::<BTreeSet<_>>(),
        "every query variant must be covered"
    );
    for q in qs {
        let e = h.client(&mallory, ns).query(q.clone()).unwrap_err();
        assert_eq!(
            e.code,
            ErrorCode::Forbidden,
            "{} returned {:?}",
            q.name(),
            e
        );
    }
}
