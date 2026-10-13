//! Phase 11: Baselines and accepted composition; Scenario F.

use openaevc::protocol::*;
use openaevc_testkit::*;
use serde_json::{json, Value};

fn setup() -> (Extensions, Harness, Identity, NamespaceId) {
    let ext = Extensions::install();
    let h = Harness::with_extensions(&ext);
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    h.setup_kv(&root, ns, &ext);
    (ext, h, root, ns)
}

fn baseline(h: &Harness, who: &Identity, ns: NamespaceId, id: BaselineId) -> Value {
    h.client(who, ns)
        .query(Query::GetBaseline { baseline: id })
        .unwrap()
}

fn validate(h: &Harness, who: &Identity, ns: NamespaceId, d: Digest) -> Value {
    h.client(who, ns)
        .query(Query::ValidateBaseline { digest: d })
        .unwrap()
}

#[test]
fn scenario_f_independent_baselines() {
    let (_ext, h, root, ns) = setup();
    let p: Vec<Digest> = (0..6)
        .map(|i| {
            h.promote_new(&root, ns, vec![kv_set(&format!("k{i}"), "v")])
                .1
        })
        .collect();
    let mk = |ms: [usize; 3]| {
        let r = h
            .create_baseline(&root, ns, ms.iter().map(|i| p[*i]).collect(), vec![])
            .unwrap();
        (receipt_id::<BaselineId>(&r), r.result.digest.unwrap())
    };
    let (b0, d0) = mk([0, 1, 3]);
    let before = baseline(&h, &root, ns, b0);
    let (b1, d1) = mk([0, 1, 2]);
    let (b2, d2) = mk([0, 2, 5]);
    // Each validates independently.
    for d in [d0, d1, d2] {
        let v = validate(&h, &root, ns, d);
        assert_eq!(v["valid"], true, "{v}");
        assert_eq!(v["validators"]["kv.terminal-values"], "passed");
    }
    // Creating B1/B2 did not change B0; shared members are the same digests (stored once).
    assert_eq!(baseline(&h, &root, ns, b0), before);
    let members = |id| baseline(&h, &root, ns, id)["envelope"]["body"]["members"].clone();
    for id in [b0, b1, b2] {
        assert!(members(id)
            .as_array()
            .unwrap()
            .contains(&json!(p[0].to_string())));
    }
    assert_ne!(d0, d1);
    // No Baseline is another's parent.
    assert!(before["envelope"]["body"].get("parent").is_none());
    let _ = (b2, d2);
}

#[test]
fn terminal_value_conflicts_need_explicit_ordering() {
    let (_ext, h, root, ns) = setup();
    let (_, a) = h.promote_new(&root, ns, vec![kv_set("mode", "fast")]);
    let (_, b) = h.promote_new(&root, ns, vec![kv_set("mode", "safe")]);
    let e = h
        .create_baseline(&root, ns, vec![a, b], vec![])
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::CompositionInvalid);
    let ordered = CompositionEdge {
        from: b,
        to: a,
        kind: CompositionEdgeKind::OrdersAfter,
        relation: None,
    };
    let r = h
        .create_baseline(&root, ns, vec![a, b], vec![ordered])
        .unwrap();
    let body = &baseline(&h, &root, ns, receipt_id(&r))["envelope"]["body"];
    assert_eq!(body["facts"]["kv.members"], 2);
    assert_eq!(body["facts"]["composition.members"], 2);
}

#[test]
fn invalid_graphs_fail_deterministically() {
    let (_ext, h, root, ns) = setup();
    let (base, db) = h.promote_new(&root, ns, vec![kv_set("a", "1")]);
    let dep: PackId = receipt_id(
        &h.client(&root, ns)
            .cmd(Command::CreateChangePack {
                spec: PackSpec::default(),
            })
            .unwrap(),
    );
    h.client(&root, ns)
        .cmd(Command::AddActiveDependency {
            pack: dep,
            expected_generation: 1,
            from: NodeRef::from(dep),
            to: NodeRef::from(base),
            kind: ActiveEdgeKind::DependsOn,
            annotations: Default::default(),
        })
        .unwrap();
    let (_, dd) = h.finish_pack(&root, ns, dep, vec![kv_set("b", "1")]);
    // Missing dependency.
    for _ in 0..2 {
        assert_eq!(
            h.create_baseline(&root, ns, vec![dd], vec![])
                .unwrap_err()
                .code,
            ErrorCode::DependencyMissing
        );
    }
    // Ordering cycle.
    let cycle = vec![CompositionEdge {
        from: db,
        to: dd,
        kind: CompositionEdgeKind::OrdersAfter,
        relation: None,
    }];
    assert_eq!(
        h.create_baseline(&root, ns, vec![db, dd], cycle)
            .unwrap_err()
            .code,
        ErrorCode::DependencyCycle
    );
    // Unknown member and non-promoted objects.
    assert_eq!(
        h.create_baseline(&root, ns, vec![openaevc::crypto::sha256(b"nope")], vec![])
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    let receipt = h
        .client(&root, ns)
        .cmd(Command::RegisterPrincipal {
            principal: Identity::generate().new_principal(),
        })
        .unwrap()
        .receipt;
    assert_eq!(
        h.create_baseline(&root, ns, vec![receipt], vec![])
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    // Valid with both members.
    h.create_baseline(&root, ns, vec![db, dd], vec![]).unwrap();
}

#[test]
fn baseline_policies_gate_composition() {
    let (_ext, h, root, ns) = setup();
    let (_, a) = h.promote_new(&root, ns, vec![kv_set("a", "1")]);
    let doc: PolicyDocument = serde_json::from_value(json!({
        "name": "org.example.composition",
        "rules": [{"id": "at-least-two", "expr": {"ge": {"fact": "composition.members", "value": 2}}}]
    }))
    .unwrap();
    let pol = h
        .client(&root, ns)
        .cmd(Command::RegisterPolicy {
            document: doc,
            mandatory: false,
        })
        .unwrap()
        .result
        .digest
        .unwrap();
    let e = h
        .client(&root, ns)
        .cmd(Command::CreateBaseline {
            members: vec![a],
            edges: vec![],
            policies: vec![pol],
            metadata: Default::default(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    let (_, b) = h.promote_new(&root, ns, vec![kv_set("b", "1")]);
    h.client(&root, ns)
        .cmd(Command::CreateBaseline {
            members: vec![a, b],
            edges: vec![],
            policies: vec![pol],
            metadata: Default::default(),
        })
        .unwrap();
}

#[test]
fn baseline_creation_requires_authority() {
    let (_ext, h, root, ns) = setup();
    let (_, a) = h.promote_new(&root, ns, vec![kv_set("a", "1")]);
    let alice = h.register_key_principal(&root, ns);
    let e = h.create_baseline(&alice, ns, vec![a], vec![]).unwrap_err();
    assert_eq!(
        (e.code, e.missing_action.as_deref()),
        (ErrorCode::Forbidden, Some("baseline.create"))
    );
}
