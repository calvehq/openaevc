//! Phase 9: evidence, verification, evaluation, qualification; Scenario B and H.

use openaevc_protocol::*;
use openaevc_testkit::*;
use serde_json::json;

fn setup() -> (Extensions, Harness, Identity, NamespaceId) {
    let ext = Extensions::install();
    let h = Harness::with_extensions(&ext);
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    h.setup_kv(&root, ns, &ext);
    (ext, h, root, ns)
}

fn state(h: &Harness, who: &Identity, ns: NamespaceId, p: PackId) -> PackState {
    h.pack(who, ns, p).state
}

#[test]
fn verification_produces_immutable_candidate_bound_results_and_evidence() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    h.run(
        &root,
        ns,
        pack,
        &mut ScriptedHarness {
            effects: vec![kv_set("a", "1")],
        },
    );
    let candidate = h.seal(&root, ns, pack);
    let r = h
        .verify(
            &root,
            ns,
            pack,
            "kv.expect",
            json!({"key": "a", "value": "1"}),
        )
        .unwrap();
    assert_eq!(r.result.state.as_deref(), Some("PASS"));
    let v = h
        .client(&root, ns)
        .query(Query::GetVerification {
            digest: r.result.digest.unwrap(),
        })
        .unwrap();
    let body = &v["envelope"]["body"];
    assert_eq!(body["status"], "PASS");
    assert_eq!(body["candidate"], candidate.to_string());
    assert_eq!(body["extension"]["id"], KV);
    // The verifier attached a snapshot as candidate-bound evidence.
    let ev: Digest = body["evidence"][0].as_str().unwrap().parse().unwrap();
    let e = h
        .client(&root, ns)
        .query(Query::GetEvidence { digest: ev })
        .unwrap();
    assert_eq!(e["envelope"]["body"]["kind"], "kv.snapshot");
    assert_eq!(e["envelope"]["body"]["candidate"], candidate.to_string());
    // A rerun creates a new result; failing expectations are reported, not hidden.
    let fail = h
        .verify(
            &root,
            ns,
            pack,
            "kv.expect",
            json!({"key": "a", "value": "2"}),
        )
        .unwrap();
    assert_eq!(fail.result.state.as_deref(), Some("FAIL"));
    assert_ne!(fail.result.digest, r.result.digest);
}

#[test]
fn verification_requires_a_sealed_current_generation() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    let e = h
        .verify(
            &root,
            ns,
            pack,
            "kv.expect",
            json!({"key": "a", "value": "1"}),
        )
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidTransition);
    h.seal(&root, ns, pack);
    let e = h
        .client(&root, ns)
        .cmd(Command::RunVerification {
            pack,
            generation: 99,
            verifier: "kv.expect".into(),
            config: None,
            evidence: vec![],
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::StaleGeneration);
    let e = h
        .verify(&root, ns, pack, "org.example.nothing", json!({}))
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = h
        .verify(&root, ns, pack, "kv.expect", json!({"wrong": 1}))
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ExtensionFailed);
}

#[test]
fn qualification_follows_policy_over_current_facts() {
    let (_ext, h, root, ns) = setup();
    h.kv_gate(&root, ns);
    let pack = h.create_pack(&root, ns);
    h.run(
        &root,
        ns,
        pack,
        &mut ScriptedHarness {
            effects: vec![kv_set("a", "1")],
        },
    );
    h.seal(&root, ns, pack);
    // No verification yet: denied, pack stays SEALED, the decision is recorded.
    let r = h.qualify(&root, ns, pack);
    assert_eq!(r.result.state.as_deref(), Some("SEALED"));
    let d = h
        .client(&root, ns)
        .query(Query::GetPolicyDecision {
            digest: r.result.digest.unwrap(),
        })
        .unwrap();
    assert_eq!(d["envelope"]["body"]["outcome"], "DENY");
    // Required verifier failure blocks qualification.
    h.verify(
        &root,
        ns,
        pack,
        "kv.expect",
        json!({"key": "a", "value": "2"}),
    )
    .unwrap();
    assert_eq!(
        h.qualify(&root, ns, pack).result.state.as_deref(),
        Some("SEALED")
    );
    // Passing verification + allowing evaluation qualifies.
    h.verify(
        &root,
        ns,
        pack,
        "kv.expect",
        json!({"key": "a", "value": "1"}),
    )
    .unwrap();
    let ev = h
        .evaluate(&root, ns, pack, "kv.size", json!({"max_keys": 5}))
        .unwrap();
    assert_eq!(ev.result.state.as_deref(), Some("ALLOW"));
    let r = h.qualify(&root, ns, pack);
    assert_eq!(r.result.state.as_deref(), Some("QUALIFIED"));
    assert_eq!(state(&h, &root, ns, pack), PackState::Qualified);
    let q = h.pack(&root, ns, pack).qualification.unwrap();
    assert_eq!(q.decision, r.result.digest.unwrap());
    // New facts invalidate qualification until refreshed.
    h.evaluate(&root, ns, pack, "kv.size", json!({"max_keys": 0}))
        .unwrap();
    assert_eq!(state(&h, &root, ns, pack), PackState::Sealed);
    assert_eq!(
        h.qualify(&root, ns, pack).result.state.as_deref(),
        Some("SEALED")
    );
}

#[test]
fn pack_policies_add_gates_on_top_of_mandatory_ones() {
    let (_ext, h, root, ns) = setup();
    let extra: PolicyDocument = serde_json::from_value(json!({
        "name": "org.example.extra",
        "rules": [{"id": "has-snapshot", "expr": {"evidence": {"kind": "org.example.approval"}}}]
    }))
    .unwrap();
    let extra = h
        .client(&root, ns)
        .cmd(Command::RegisterPolicy {
            document: extra,
            mandatory: false,
        })
        .unwrap()
        .result
        .digest
        .unwrap();
    let spec = PackSpec {
        required_policies: vec![extra],
        ..Default::default()
    };
    let pack: PackId = receipt_id(
        &h.client(&root, ns)
            .cmd(Command::CreateChangePack { spec })
            .unwrap(),
    );
    h.seal(&root, ns, pack);
    assert_eq!(
        h.qualify(&root, ns, pack).result.state.as_deref(),
        Some("SEALED")
    );
    let p = h.pack(&root, ns, pack);
    let sealed = p.sealed.unwrap();
    h.client(&root, ns)
        .cmd(Command::RegisterEvidence {
            pack,
            generation: sealed.generation,
            candidate: sealed.candidate,
            kind: "org.example.approval".into(),
            payload: Blob {
                media_type: "text/plain".into(),
                data: b"approved by release board".to_vec(),
            },
            schema: None,
            sources: vec![],
            extension: None,
        })
        .unwrap();
    assert_eq!(
        h.qualify(&root, ns, pack).result.state.as_deref(),
        Some("QUALIFIED")
    );
}

#[test]
fn scenario_b_reopen_invalidates_evidence() {
    let (_ext, h, root, ns) = setup();
    h.kv_gate(&root, ns);
    let pack = h.create_pack(&root, ns);
    h.run(
        &root,
        ns,
        pack,
        &mut ScriptedHarness {
            effects: vec![kv_set("a", "1")],
        },
    );
    let gen_n = h.pack(&root, ns, pack).generation;
    let cand_n = h.seal(&root, ns, pack);
    h.verify(
        &root,
        ns,
        pack,
        "kv.expect",
        json!({"key": "a", "value": "1"}),
    )
    .unwrap();
    // Reopen and mutate into N+1.
    h.client(&root, ns)
        .cmd(Command::ReopenChangePack {
            pack,
            expected_generation: gen_n,
        })
        .unwrap();
    h.run(
        &root,
        ns,
        pack,
        &mut ScriptedHarness {
            effects: vec![kv_set("b", "2")],
        },
    );
    let cand_n1 = h.seal(&root, ns, pack);
    assert_ne!(cand_n, cand_n1);
    // Generation N verification cannot qualify N+1.
    assert_eq!(
        h.qualify(&root, ns, pack).result.state.as_deref(),
        Some("SEALED")
    );
    // Stale evidence cannot even be attached to the new generation.
    let e = h
        .client(&root, ns)
        .cmd(Command::RegisterEvidence {
            pack,
            generation: gen_n,
            candidate: cand_n,
            kind: "org.example.approval".into(),
            payload: Blob {
                media_type: "text/plain".into(),
                data: b"old".to_vec(),
            },
            schema: None,
            sources: vec![],
            extension: None,
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::EvidenceInvalid);
    // Rerun verification: qualifies.
    h.verify(
        &root,
        ns,
        pack,
        "kv.expect",
        json!({"key": "b", "value": "2"}),
    )
    .unwrap();
    assert_eq!(
        h.qualify(&root, ns, pack).result.state.as_deref(),
        Some("QUALIFIED")
    );
}

#[test]
fn scenario_h_malicious_extensions_fail_closed_and_runtime_stays_healthy() {
    let (ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    h.seal(&root, ns, pack);
    // Wrong manifest digest never registers.
    let name = "conformance-fixture-wrong-digest";
    let e = h
        .client(&root, ns)
        .cmd(Command::RegisterExtension {
            entrypoint: Extensions::entrypoint(name),
            artifact_digest: ext.digest(name),
            approved_host_capabilities: vec![],
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ExtensionIncompatible);
    for mode in [
        "undeclared-resource",
        "undeclared-process",
        "oversized",
        "invalid-frame",
        "slow",
        "crash",
    ] {
        h.register_extension(&root, ns, &ext, &format!("conformance-fixture-{mode}"));
    }
    let h2 = &h;
    let run = |mode: &str| h2.verify(&root, ns, pack, &format!("fixture.{mode}.check"), json!({}));
    for mode in [
        "undeclared-resource",
        "undeclared-process",
        "invalid-frame",
        "crash",
    ] {
        assert_eq!(
            run(mode).unwrap_err().code,
            ErrorCode::ExtensionFailed,
            "{mode}"
        );
    }
    // Healthy afterwards: normal commands still work.
    let p2 = h.create_pack(&root, ns);
    assert_eq!(h.pack(&root, ns, p2).state, PackState::Open);
    // No verification results were recorded for the failed invocations.
    let results = h
        .events(&root, ns)
        .iter()
        .filter(|e| e["kind"] == "verification.completed")
        .count();
    assert_eq!(results, 0);
}

#[test]
fn deadline_and_frame_limits_apply_through_the_runtime() {
    let ext = Extensions::install();
    let dir = ext.dir.path().to_path_buf();
    let h = Harness::with_config(move |c| {
        c.extension_dirs = vec![dir];
        c.extension_deadline_ms = 3_000;
        c.max_extension_frame = 1024 * 1024;
    });
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    for mode in ["oversized", "slow"] {
        h.register_extension(&root, ns, &ext, &format!("conformance-fixture-{mode}"));
    }
    let pack = h.create_pack(&root, ns);
    h.seal(&root, ns, pack);
    for mode in ["oversized", "slow"] {
        let e = h
            .verify(&root, ns, pack, &format!("fixture.{mode}.check"), json!({}))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::ExtensionFailed, "{mode}");
    }
}

#[test]
fn evaluation_is_distinct_and_cannot_grant_authority() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    h.run(
        &root,
        ns,
        pack,
        &mut ScriptedHarness {
            effects: vec![kv_set("a", "1"), kv_set("b", "2")],
        },
    );
    h.seal(&root, ns, pack);
    let r = h
        .evaluate(&root, ns, pack, "kv.size", json!({"max_keys": 1}))
        .unwrap();
    assert_eq!(r.result.state.as_deref(), Some("DENY"));
    let v = h
        .client(&root, ns)
        .query(Query::GetEvaluation {
            digest: r.result.digest.unwrap(),
        })
        .unwrap();
    assert_eq!(v["envelope"]["body"]["metrics"]["kv.keys"], 2);
    // Evaluation/verification commands are themselves authority-gated.
    let alice = h.register_key_principal(&root, ns);
    let g = h.pack(&root, ns, pack).generation;
    let e = h
        .client(&alice, ns)
        .cmd(Command::RunEvaluation {
            pack,
            generation: g,
            evaluator: "kv.size".into(),
            config: Some(json!({"max_keys": 1})),
            inputs: vec![],
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
}
