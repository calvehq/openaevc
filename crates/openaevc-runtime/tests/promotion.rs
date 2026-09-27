//! Phase 10: promotion, immutable accepted objects; Scenarios A, E, I.

use std::collections::BTreeSet;

use openaevc_protocol::*;
use openaevc_testkit::*;
use serde_json::{json, Value};

fn object(h: &Harness, who: &Identity, ns: NamespaceId, d: Digest) -> Value {
    h.client(who, ns)
        .query(Query::GetObject { digest: d })
        .unwrap()
}

/// Every object reachable from `root` loads and verifies (immutable closure).
fn closure_complete(h: &Harness, who: &Identity, ns: NamespaceId, root: Digest) -> usize {
    let mut seen = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(d) = stack.pop() {
        if !seen.insert(d) {
            continue;
        }
        let v = object(h, who, ns, d);
        let bytes = b64::decode(v["canonical"].as_str().unwrap()).unwrap();
        let obj = openaevc_core::ImmutableObject::from_bytes(&bytes, Some(d)).unwrap();
        stack.extend(obj.references().unwrap());
    }
    seen.len()
}

#[test]
fn scenario_a_minimal_trusted_change() {
    let ext = Extensions::install();
    let h = Harness::with_extensions(&ext);
    let root = Identity::generate();
    // 1-4: namespace, principal, capability, extension.
    let ns = h.create_namespace(&root);
    let alice = h.register_key_principal(&root, ns);
    h.grant(
        &root,
        ns,
        &alice,
        &[
            "changepack.*",
            "execution.start",
            "observation.append",
            "verification.run",
            "evaluation.run",
            "kv.write",
            "namespace.read",
            "object.read",
        ],
    );
    h.setup_kv(&root, ns, &ext);
    h.kv_gate(&root, ns);
    // 5-8: pack, work unit, execute kv.set, observation.
    let pack = h.create_pack(&alice, ns);
    h.run(
        &alice,
        ns,
        pack,
        &mut ScriptedHarness {
            effects: vec![kv_set("limits/max", "10")],
        },
    );
    // 9-12: seal, verify, evaluate, qualify.
    h.seal(&alice, ns, pack);
    h.verify(
        &alice,
        ns,
        pack,
        "kv.expect",
        json!({"key": "limits/max", "value": "10"}),
    )
    .unwrap();
    h.evaluate(&alice, ns, pack, "kv.size", json!({"max_keys": 3}))
        .unwrap();
    assert_eq!(
        h.qualify(&alice, ns, pack).result.state.as_deref(),
        Some("QUALIFIED")
    );
    // 13: promote.
    let promoted = h.promote(&alice, ns, pack).unwrap();
    // 14: fetch immutable PromotedPack.
    let obj = h
        .client(&alice, ns)
        .query(Query::GetPromotedPack {
            pack: Some(pack),
            digest: None,
        })
        .unwrap();
    assert_eq!(obj["digest"], promoted.to_string());
    let body = &obj["envelope"]["body"];
    assert_eq!(body["pack"], pack.to_string());
    assert_eq!(body["effects"][0]["kind"], "kv.set");
    assert_eq!(body["verifications"].as_array().unwrap().len(), 1);
    assert_eq!(body["evaluations"].as_array().unwrap().len(), 1);
    assert!(closure_complete(&h, &alice, ns, promoted) > 5);
    let p = h.pack(&alice, ns, pack);
    assert_eq!(p.state, PackState::Promoted);
    assert_eq!(p.promotion.as_ref().unwrap().promoted_pack, promoted);
    // 15: mutation fails.
    let c = h.client(&alice, ns);
    for cmd in [
        Command::ReopenChangePack {
            pack,
            expected_generation: p.generation,
        },
        Command::AddWorkUnit {
            pack,
            expected_generation: p.generation,
            kind: "org.example.task".into(),
            spec: None,
            depends_on: vec![],
        },
        Command::SealChangePack {
            pack,
            expected_generation: p.generation,
        },
        Command::AbandonChangePack {
            pack,
            expected_generation: p.generation,
        },
        Command::PromoteChangePack {
            pack,
            generation: p.generation,
        },
    ] {
        assert_eq!(
            c.cmd(cmd.clone()).unwrap_err().code,
            ErrorCode::ImmutableObject,
            "{cmd:?}"
        );
    }
    let promoted_again = object(&h, &alice, ns, promoted);
    assert_eq!(promoted_again, obj);
    assert!(h
        .events(&root, ns)
        .iter()
        .any(|e| e["kind"] == "changepack.promoted"));
}

#[test]
fn promotion_requires_authority_qualification_and_matching_generation() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let alice = h.register_key_principal(&root, ns);
    h.grant(
        &root,
        ns,
        &alice,
        &[
            "changepack.create",
            "changepack.seal",
            "verification.run",
            "namespace.read",
        ],
    );
    let pack = h.create_pack(&alice, ns);
    h.seal(&alice, ns, pack);
    assert_eq!(
        h.promote(&root, ns, pack).unwrap_err().code,
        ErrorCode::NotQualified
    );
    h.qualify(&alice, ns, pack);
    let e = h.promote(&alice, ns, pack).unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    assert_eq!(e.missing_action.as_deref(), Some("changepack.promote"));
    let e = h
        .client(&root, ns)
        .cmd(Command::PromoteChangePack {
            pack,
            generation: 7,
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::StaleGeneration);
    h.promote(&root, ns, pack).unwrap();
}

#[test]
fn policy_changes_after_qualification_are_enforced_at_promotion() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let pack = h.create_pack(&root, ns);
    h.seal(&root, ns, pack);
    h.qualify(&root, ns, pack);
    let strict: PolicyDocument = serde_json::from_value(
        json!({"name": "org.example.strict", "rules": [{"id": "never", "expr": {"any": []}}]}),
    )
    .unwrap();
    h.client(&root, ns)
        .cmd(Command::RegisterPolicy {
            document: strict,
            mandatory: true,
        })
        .unwrap();
    assert_eq!(
        h.promote(&root, ns, pack).unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(h.pack(&root, ns, pack).state, PackState::Qualified);
}

#[test]
fn dependencies_must_be_promoted_first_and_are_recorded() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let base = h.create_pack(&root, ns);
    let dependent = h.create_pack(&root, ns);
    h.client(&root, ns)
        .cmd(Command::AddActiveDependency {
            pack: dependent,
            expected_generation: 1,
            from: NodeRef::from(dependent),
            to: NodeRef::from(base),
            kind: ActiveEdgeKind::DependsOn,
            annotations: Default::default(),
        })
        .unwrap();
    h.seal(&root, ns, base);
    h.seal(&root, ns, dependent);
    h.qualify(&root, ns, dependent);
    assert_eq!(
        h.promote(&root, ns, dependent).unwrap_err().code,
        ErrorCode::DependencyMissing
    );
    h.qualify(&root, ns, base);
    let base_digest = h.promote(&root, ns, base).unwrap();
    let d = h.promote(&root, ns, dependent).unwrap();
    assert_eq!(
        object(&h, &root, ns, d)["envelope"]["body"]["dependencies"],
        json!([base_digest.to_string()])
    );
}

#[test]
fn scenario_e_revision_reverts_without_mutating_history() {
    let ext = Extensions::install();
    let h = Harness::with_extensions(&ext);
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    h.setup_kv(&root, ns, &ext);
    let (p0, d0) = h.promote_new(&root, ns, vec![kv_set("feature/x", "on")]);
    let before = object(&h, &root, ns, d0);
    let r0: PackId = receipt_id(
        &h.client(&root, ns)
            .cmd(Command::CreateRevisionPack {
                relation: RevisionRelation::Reverts,
                targets: vec![d0],
                spec: PackSpec::default(),
            })
            .unwrap(),
    );
    assert!(r0.is_revision());
    h.run(
        &root,
        ns,
        r0,
        &mut ScriptedHarness {
            effects: vec![kv_delete("feature/x")],
        },
    );
    h.seal(&root, ns, r0);
    h.verify(
        &root,
        ns,
        r0,
        "kv.expect",
        json!({"key": "feature/x", "absent": true}),
    )
    .unwrap();
    h.qualify(&root, ns, r0);
    let dr = h.promote(&root, ns, r0).unwrap();
    let rev = object(&h, &root, ns, dr);
    assert_eq!(
        rev["envelope"]["body"]["revision"],
        json!({"relation": "REVERTS", "targets": [d0.to_string()]})
    );
    // P0 is still present, unchanged and promoted.
    assert_eq!(object(&h, &root, ns, d0), before);
    assert_eq!(h.pack(&root, ns, p0).state, PackState::Promoted);
    let rv: ChangePack = serde_json::from_value(
        h.client(&root, ns)
            .query(Query::GetRevisionPack {
                pack: r0,
                generation: None,
            })
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rv.state, PackState::Promoted);
}

mod scenario_i {
    use super::*;
    use openaevc_store::{Failpoint, Store};

    #[test]
    fn crash_at_every_promotion_stage_is_all_or_nothing() {
        for fp in [
            Failpoint::AfterCasTempWrite,
            Failpoint::AfterCasRename,
            Failpoint::BeforeSqliteCommit,
            Failpoint::AfterSqliteCommit,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = Identity::generate();
            let (ns, pack, env) = {
                let (h, store) = Harness::sqlite_with_store(dir.path(), None);
                let ns = h.create_namespace(&root);
                // Large intent forces the promoted object into the CAS so CAS failpoints fire.
                let spec = PackSpec {
                    intent: Some(json!({"org.example.notes": "x".repeat(20_000)})),
                    ..Default::default()
                };
                let pack: PackId = receipt_id(
                    &h.client(&root, ns)
                        .cmd(Command::CreateChangePack { spec })
                        .unwrap(),
                );
                h.seal(&root, ns, pack);
                h.qualify(&root, ns, pack);
                let g = h.pack(&root, ns, pack).generation;
                let env = h
                    .client(&root, ns)
                    .command_envelope(Command::PromoteChangePack {
                        pack,
                        generation: g,
                    });
                store.set_failpoint(Some(fp));
                assert!(
                    h.rt.execute(env.clone()).is_err(),
                    "{fp:?} must interrupt promotion"
                );
                store.set_failpoint(None);
                (ns, pack, env)
            };
            // Restart.
            let (h, store) = Harness::sqlite_with_store(dir.path(), None);
            assert!(store.verify_integrity().unwrap().ok(), "{fp:?}");
            let p = h.pack(&root, ns, pack);
            if fp == Failpoint::AfterSqliteCommit {
                assert_eq!(p.state, PackState::Promoted, "{fp:?}");
                let digest = p.promotion.unwrap().promoted_pack;
                assert!(closure_complete(&h, &root, ns, digest) >= 3);
                // Retrying the same request returns the original receipt.
                assert_eq!(h.rt.execute(env).unwrap().result.digest, Some(digest));
            } else {
                assert_eq!(p.state, PackState::Qualified, "{fp:?}");
                assert!(p.promotion.is_none());
                // Retryable: the same request now succeeds.
                let r = h.rt.execute(env).unwrap();
                assert_eq!(h.pack(&root, ns, pack).state, PackState::Promoted, "{fp:?}");
                assert!(closure_complete(&h, &root, ns, r.result.digest.unwrap()) >= 3);
            }
        }
    }
}
