//! Phase 5: ChangePack / RevisionPack generations, lifecycle, Active Change Graph.

use openaevc::protocol::*;
use openaevc_testkit::{Harness, Identity};
use serde_json::json;

fn setup() -> (Harness, Identity, NamespaceId) {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    (h, root, ns)
}

fn pack(h: &Harness, who: &Identity, ns: NamespaceId, id: PackId) -> ChangePack {
    serde_json::from_value(
        h.client(who, ns)
            .query(Query::GetChangePack {
                pack: id,
                generation: None,
            })
            .unwrap(),
    )
    .unwrap()
}

fn create(h: &Harness, who: &Identity, ns: NamespaceId) -> PackId {
    h.client(who, ns)
        .cmd(Command::CreateChangePack {
            spec: PackSpec::default(),
        })
        .unwrap()
        .result
        .id
        .unwrap()
        .parse()
        .unwrap()
}

fn add_wu(
    h: &Harness,
    who: &Identity,
    ns: NamespaceId,
    p: PackId,
    gen: u64,
    deps: Vec<NodeRef>,
) -> WorkUnitId {
    h.client(who, ns)
        .cmd(Command::AddWorkUnit {
            pack: p,
            expected_generation: gen,
            kind: "org.example.task".into(),
            spec: None,
            depends_on: deps,
        })
        .unwrap()
        .result
        .id
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn mutations_create_generations_and_history_is_auditable() {
    let (h, root, ns) = setup();
    let p = create(&h, &root, ns);
    assert_eq!(pack(&h, &root, ns, p).generation, 1);
    assert_eq!(pack(&h, &root, ns, p).state, PackState::Open);
    let r = h
        .client(&root, ns)
        .cmd(Command::UpdateChangePack {
            pack: p,
            expected_generation: 1,
            intent: Some(json!({"org.example.summary": "raise limit"})),
            resource_refs: None,
            required_policies: None,
            extension_bindings: None,
            conflicts_with: None,
            metadata: None,
        })
        .unwrap();
    assert_eq!(r.result.generation, Some(2));
    add_wu(&h, &root, ns, p, 2, vec![]);
    let cur = pack(&h, &root, ns, p);
    assert_eq!(cur.generation, 3);
    assert_eq!(cur.work_units.len(), 1);
    let g1: ChangePack = serde_json::from_value(
        h.client(&root, ns)
            .query(Query::GetChangePack {
                pack: p,
                generation: Some(1),
            })
            .unwrap(),
    )
    .unwrap();
    assert!(g1.intent.is_none());
    assert!(g1.work_units.is_empty());
}

#[test]
fn stale_generation_rejected() {
    let (h, root, ns) = setup();
    let p = create(&h, &root, ns);
    add_wu(&h, &root, ns, p, 1, vec![]);
    let e = h
        .client(&root, ns)
        .cmd(Command::AddWorkUnit {
            pack: p,
            expected_generation: 1,
            kind: "org.example.task".into(),
            spec: None,
            depends_on: vec![],
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::StaleGeneration);
    assert_eq!(
        (e.expected_generation, e.actual_generation),
        (Some(1), Some(2))
    );
}

#[test]
fn sealed_pack_requires_reopen_which_bumps_generation() {
    let (h, root, ns) = setup();
    let p = create(&h, &root, ns);
    let r = h
        .client(&root, ns)
        .cmd(Command::SealChangePack {
            pack: p,
            expected_generation: 1,
        })
        .unwrap();
    assert!(r.result.digest.is_some(), "seal freezes a candidate digest");
    let sealed = pack(&h, &root, ns, p);
    assert_eq!(sealed.state, PackState::Sealed);
    assert_eq!(sealed.sealed.as_ref().unwrap().generation, 1);
    let e = h
        .client(&root, ns)
        .cmd(Command::AddWorkUnit {
            pack: p,
            expected_generation: 1,
            kind: "org.example.task".into(),
            spec: None,
            depends_on: vec![],
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidTransition);
    h.client(&root, ns)
        .cmd(Command::ReopenChangePack {
            pack: p,
            expected_generation: 1,
        })
        .unwrap();
    let reopened = pack(&h, &root, ns, p);
    assert_eq!((reopened.state, reopened.generation), (PackState::Open, 2));
    assert!(reopened.sealed.is_none() && reopened.qualification.is_none());
    add_wu(&h, &root, ns, p, 2, vec![]);
}

#[test]
fn candidate_object_is_frozen_at_seal() {
    let (h, root, ns) = setup();
    let p = create(&h, &root, ns);
    let r = h
        .client(&root, ns)
        .cmd(Command::SealChangePack {
            pack: p,
            expected_generation: 1,
        })
        .unwrap();
    let obj = h
        .client(&root, ns)
        .query(Query::GetObject {
            digest: r.result.digest.unwrap(),
        })
        .unwrap();
    assert_eq!(obj["envelope"]["kind"], "candidate");
    assert_eq!(obj["envelope"]["body"]["generation"], 1);
    assert_eq!(obj["envelope"]["body"]["pack"], p.to_string());
}

#[test]
fn invalid_transitions_are_rejected() {
    let (h, root, ns) = setup();
    let c = h.client(&root, ns);
    let p = create(&h, &root, ns);
    // Reopen an open pack.
    assert_eq!(
        c.cmd(Command::ReopenChangePack {
            pack: p,
            expected_generation: 1
        })
        .unwrap_err()
        .code,
        ErrorCode::InvalidTransition
    );
    // Promote before qualification.
    assert_eq!(
        c.cmd(Command::PromoteChangePack {
            pack: p,
            generation: 1
        })
        .unwrap_err()
        .code,
        ErrorCode::NotQualified
    );
    // Abandon, then everything fails.
    c.cmd(Command::AbandonChangePack {
        pack: p,
        expected_generation: 1,
    })
    .unwrap();
    assert_eq!(pack(&h, &root, ns, p).state, PackState::Abandoned);
    for cmd in [
        Command::SealChangePack {
            pack: p,
            expected_generation: 1,
        },
        Command::ReopenChangePack {
            pack: p,
            expected_generation: 1,
        },
        Command::AbandonChangePack {
            pack: p,
            expected_generation: 1,
        },
        Command::QuarantineChangePack {
            pack: p,
            reason: "x".into(),
        },
        Command::AddWorkUnit {
            pack: p,
            expected_generation: 1,
            kind: "org.example.task".into(),
            spec: None,
            depends_on: vec![],
        },
    ] {
        assert_eq!(
            c.cmd(cmd.clone()).unwrap_err().code,
            ErrorCode::InvalidTransition,
            "{cmd:?}"
        );
    }
    assert_eq!(
        c.cmd(Command::PromoteChangePack {
            pack: p,
            generation: 1
        })
        .unwrap_err()
        .code,
        ErrorCode::InvalidTransition
    );
}

#[test]
fn quarantine_blocks_and_release_restores() {
    let (h, root, ns) = setup();
    let c = h.client(&root, ns);
    let p = create(&h, &root, ns);
    c.cmd(Command::SealChangePack {
        pack: p,
        expected_generation: 1,
    })
    .unwrap();
    c.cmd(Command::QuarantineChangePack {
        pack: p,
        reason: "suspicious".into(),
    })
    .unwrap();
    let q = pack(&h, &root, ns, p);
    assert_eq!(q.state, PackState::Quarantined);
    assert_eq!(q.quarantine.unwrap().previous_state, PackState::Sealed);
    assert_eq!(
        c.cmd(Command::ReopenChangePack {
            pack: p,
            expected_generation: 1
        })
        .unwrap_err()
        .code,
        ErrorCode::Quarantined
    );
    assert_eq!(
        c.cmd(Command::PromoteChangePack {
            pack: p,
            generation: 1
        })
        .unwrap_err()
        .code,
        ErrorCode::Quarantined
    );
    c.cmd(Command::ReleaseQuarantine { pack: p }).unwrap();
    assert_eq!(pack(&h, &root, ns, p).state, PackState::Sealed);
    assert_eq!(
        c.cmd(Command::ReleaseQuarantine { pack: p })
            .unwrap_err()
            .code,
        ErrorCode::InvalidTransition
    );
}

#[test]
fn quarantine_requires_its_own_capability() {
    let (h, root, ns) = setup();
    let alice = h.register_key_principal(&root, ns);
    h.grant(&root, ns, &alice, &["changepack.*", "namespace.read"]);
    let p = create(&h, &alice, ns);
    let e = h
        .client(&alice, ns)
        .cmd(Command::QuarantineChangePack {
            pack: p,
            reason: "x".into(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    assert_eq!(e.missing_action.as_deref(), Some("quarantine.manage"));
}

#[test]
fn cross_pack_dependencies_drive_readiness() {
    let (h, root, ns) = setup();
    let a = create(&h, &root, ns);
    let b = create(&h, &root, ns);
    let wa = add_wu(&h, &root, ns, a, 1, vec![]);
    let wb = add_wu(&h, &root, ns, b, 1, vec![NodeRef::from(wa)]);
    let ready: Vec<String> = serde_json::from_value::<Vec<serde_json::Value>>(
        h.client(&root, ns)
            .query(Query::GetReadyWork { pack: None })
            .unwrap(),
    )
    .unwrap()
    .iter()
    .map(|w| w["work_unit"].as_str().unwrap().to_owned())
    .collect();
    assert_eq!(ready, vec![wa.to_string()]);
    let blocked = h
        .client(&root, ns)
        .query(Query::GetBlockedWork { pack: None })
        .unwrap();
    assert_eq!(blocked[0]["work_unit"], wb.to_string());
    assert_eq!(blocked[0]["waiting_on"][0]["node"], wa.to_string());
    let closure = h
        .client(&root, ns)
        .query(Query::GetDependencyClosure {
            node: NodeRef::from(wb),
            reverse: false,
        })
        .unwrap();
    assert_eq!(closure, json!([wa.to_string()]));
    let rev = h
        .client(&root, ns)
        .query(Query::GetDependencyClosure {
            node: NodeRef::from(wa),
            reverse: true,
        })
        .unwrap();
    assert_eq!(rev, json!([wb.to_string()]));
    let affected = h
        .client(&root, ns)
        .query(Query::GetAffectedNodes {
            node: NodeRef::from(a),
        })
        .unwrap();
    assert!(affected
        .as_array()
        .unwrap()
        .contains(&json!(wb.to_string())));
    // Pack-level dependency: b waits on a being sealed.
    h.client(&root, ns)
        .cmd(Command::AddActiveDependency {
            pack: b,
            expected_generation: 2,
            from: NodeRef::from(b),
            to: NodeRef::from(a),
            kind: ActiveEdgeKind::DependsOn,
            annotations: Default::default(),
        })
        .unwrap();
    let graph = h
        .client(&root, ns)
        .query(Query::GetActiveChangeGraph { pack: Some(b) })
        .unwrap();
    assert_eq!(graph["edges"].as_array().unwrap().len(), 2);
    let node = h
        .client(&root, ns)
        .query(Query::GetNode {
            node: NodeRef::from(wb),
        })
        .unwrap();
    assert_eq!(node["pack"], b.to_string());
}

#[test]
fn dependency_cycles_report_the_minimal_cycle() {
    let (h, root, ns) = setup();
    let a = create(&h, &root, ns);
    let w1 = add_wu(&h, &root, ns, a, 1, vec![]);
    let w2 = add_wu(&h, &root, ns, a, 2, vec![NodeRef::from(w1)]);
    let w3 = add_wu(&h, &root, ns, a, 3, vec![NodeRef::from(w2)]);
    let e = h
        .client(&root, ns)
        .cmd(Command::AddActiveDependency {
            pack: a,
            expected_generation: 4,
            from: NodeRef::from(w1),
            to: NodeRef::from(w3),
            kind: ActiveEdgeKind::DependsOn,
            annotations: Default::default(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::DependencyCycle);
    assert_eq!(
        e.cycle,
        vec![
            w1.to_string(),
            w3.to_string(),
            w2.to_string(),
            w1.to_string()
        ]
    );
    // BLOCKS edges participate: w3 BLOCKS w1 is the same cycle.
    let e = h
        .client(&root, ns)
        .cmd(Command::AddActiveDependency {
            pack: a,
            expected_generation: 4,
            from: NodeRef::from(w3),
            to: NodeRef::from(w1),
            kind: ActiveEdgeKind::Blocks,
            annotations: Default::default(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::DependencyCycle);
    // Runtime-owned edge kinds cannot be added by clients.
    let e = h
        .client(&root, ns)
        .cmd(Command::AddActiveDependency {
            pack: a,
            expected_generation: 4,
            from: NodeRef::from(w3),
            to: NodeRef::from(w1),
            kind: ActiveEdgeKind::Produces,
            annotations: Default::default(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[test]
fn removing_dependency_unblocks_and_missing_nodes_rejected() {
    let (h, root, ns) = setup();
    let a = create(&h, &root, ns);
    let w1 = add_wu(&h, &root, ns, a, 1, vec![]);
    let w2 = add_wu(&h, &root, ns, a, 2, vec![NodeRef::from(w1)]);
    h.client(&root, ns)
        .cmd(Command::RemoveActiveDependency {
            pack: a,
            expected_generation: 3,
            from: NodeRef::from(w2),
            to: NodeRef::from(w1),
            kind: ActiveEdgeKind::DependsOn,
        })
        .unwrap();
    let ready = h
        .client(&root, ns)
        .query(Query::GetReadyWork { pack: Some(a) })
        .unwrap();
    assert_eq!(ready.as_array().unwrap().len(), 2);
    let ghost: WorkUnitId = h.ids_next();
    let e = h
        .client(&root, ns)
        .cmd(Command::AddWorkUnit {
            pack: a,
            expected_generation: 4,
            kind: "org.example.task".into(),
            spec: None,
            depends_on: vec![NodeRef::from(ghost)],
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::DependencyMissing);
}

#[test]
fn revision_pack_requires_promoted_targets() {
    let (h, root, ns) = setup();
    let e = h
        .client(&root, ns)
        .cmd(Command::CreateRevisionPack {
            relation: RevisionRelation::Reverts,
            targets: vec![],
            spec: PackSpec::default(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let bogus = openaevc::crypto::sha256(b"nope");
    let e = h
        .client(&root, ns)
        .cmd(Command::CreateRevisionPack {
            relation: RevisionRelation::Reverts,
            targets: vec![bogus],
            spec: PackSpec::default(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[test]
fn metadata_keys_must_be_namespaced() {
    let (h, root, ns) = setup();
    let spec = PackSpec {
        metadata: [("title".to_string(), json!("x"))].into_iter().collect(),
        ..Default::default()
    };
    let e = h
        .client(&root, ns)
        .cmd(Command::CreateChangePack { spec })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}
