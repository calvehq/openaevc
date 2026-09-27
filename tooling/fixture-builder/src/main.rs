//! `cargo run -p fixture-builder [-- --check]`: writes deterministic golden fixtures to
//! `fixtures/canonical/`. Every SDK's test-suite consumes these files.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use openaevc_core::{sign_envelope, IdGeneratorExt, ImmutableObject, SequentialIds};
use openaevc_crypto::{Domain, Signer, SigningKey};
use openaevc_protocol::*;
use serde::Serialize;
use serde_json::{json, Value};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ts(s: &str) -> Timestamp {
    s.parse().unwrap()
}

struct Ctx {
    ids: SequentialIds,
    ns: NamespaceId,
    pri: PrincipalId,
    key: SigningKey,
    runtime_key: SigningKey,
}

impl Ctx {
    fn new() -> Self {
        let ids = SequentialIds::new(7);
        let ns = ids.next();
        let pri = ids.next();
        Ctx {
            ids,
            ns,
            pri,
            key: SigningKey::from_seed([1; 32]),
            runtime_key: SigningKey::from_seed([2; 32]),
        }
    }

    fn env<T: Serialize>(&self, kind: ObjectKind, seq: u64, body: &T) -> ObjectEnvelope {
        ObjectEnvelope {
            kind,
            protocol_version: PROTOCOL_VERSION,
            namespace: self.ns,
            id: None,
            created_seq: seq,
            creator: self.pri,
            body: serde_json::to_value(body).unwrap(),
            signatures: vec![],
        }
    }
}

fn values() -> Value {
    let valid: Vec<(&str, Value)> = vec![
        ("zero", json!(0)),
        ("uint_23", json!(23)),
        ("uint_24", json!(24)),
        ("uint_255", json!(255)),
        ("uint_256", json!(256)),
        ("uint_65536", json!(65536)),
        ("uint_2_32", json!(4294967296u64)),
        ("max_safe", json!(9007199254740991u64)),
        ("neg_one", json!(-1)),
        ("neg_25", json!(-25)),
        ("min_safe", json!(-9007199254740991i64)),
        ("true", json!(true)),
        ("false", json!(false)),
        ("empty_text", json!("")),
        ("utf8_text", json!("ünïcødé ✓")),
        ("nfd_text_not_normalized", json!("e\u{301}")),
        ("empty_array", json!([])),
        ("empty_map", json!({})),
        ("key_order_length_first", json!({"aa": 1, "b": 2, "a": 3})),
        ("key_order_bytewise", json!({"B": 1, "a": 2, "_": 3})),
        (
            "nested",
            json!({"list": [1, [2, {"x": "y"}]], "map": {"k": false}}),
        ),
        ("long_text_24", json!("abcdefghijklmnopqrstuvwx")),
    ];
    let valid: Vec<Value> = valid
        .into_iter()
        .map(|(name, v)| {
            let b = openaevc_canonical::encode(&v).unwrap();
            json!({"name": name, "json": v, "cbor_hex": hex(&b), "digest": openaevc_crypto::sha256(&b).to_string()})
        })
        .collect();
    let invalid_cbor = json!([
        {"name": "non_shortest_uint", "cbor_hex": "1817"},
        {"name": "non_shortest_length", "cbor_hex": "780161"},
        {"name": "indefinite_array", "cbor_hex": "9f01ff"},
        {"name": "indefinite_map", "cbor_hex": "bf616101ff"},
        {"name": "indefinite_text", "cbor_hex": "7f6161ff"},
        {"name": "unsorted_keys", "cbor_hex": "a2616201616101"},
        {"name": "length_order_violation", "cbor_hex": "a2626161016162 02".replace(' ', "")},
        {"name": "duplicate_keys", "cbor_hex": "a2616101616102"},
        {"name": "half_float", "cbor_hex": "f93c00"},
        {"name": "double_float", "cbor_hex": "fb3ff0000000000000"},
        {"name": "null", "cbor_hex": "f6"},
        {"name": "undefined", "cbor_hex": "f7"},
        {"name": "tag", "cbor_hex": "c074323031332d30332d32315432303a30343a30305a"},
        {"name": "byte_string", "cbor_hex": "4101"},
        {"name": "integer_key", "cbor_hex": "a10101"},
        {"name": "truncated", "cbor_hex": "62c3"},
        {"name": "trailing_bytes", "cbor_hex": "0000"},
        {"name": "invalid_utf8", "cbor_hex": "61ff"},
        {"name": "uint_above_safe", "cbor_hex": "1b0020000000000000"},
        {"name": "nint_below_safe", "cbor_hex": "3b001fffffffffffff"},
        {"name": "empty", "cbor_hex": ""},
    ]);
    let invalid_json = json!([
        {"name": "float", "json": 1.5},
        {"name": "integral_float", "json": 2.0, "requires_float_distinction": true},
        {"name": "null_value", "json": {"a": null}},
        {"name": "uint_above_safe", "json": 9007199254740992u64},
        {"name": "nint_below_safe", "json": -9007199254740992i64},
    ]);
    json!({"protocol_version": PROTOCOL_VERSION, "valid": valid, "invalid_cbor": invalid_cbor, "invalid_json": invalid_json})
}

fn objects(cx: &Ctx) -> Value {
    let d = |s: &str| openaevc_crypto::sha256(s.as_bytes());
    let pack = PackId::Change(cx.ids.next());
    let exe: ExecutionId = cx.ids.next();
    let wu: WorkUnitId = cx.ids.next();
    let req: RequestId = cx.ids.next();
    let rti: RuntimeInstanceId = cx.ids.next();
    let t0 = ts("2024-05-01T12:00:00.000000000Z");
    let t1 = ts("2024-05-01T12:00:01.500000000Z");
    let ext = ExtensionRef {
        id: "org.openaevc.reference.kv".into(),
        version: "0.1.0".into(),
        manifest_digest: d("manifest"),
    };
    let resource = ResourceRef {
        kind: "kv.entry".into(),
        locator: "config/limit".into(),
        version: None,
        extension: ext.id.clone(),
    };
    let prov = Provenance {
        actor: cx.pri,
        caller: cx.pri,
        provider: "org.openaevc.testkit.provider".into(),
        worker: Some("worker-1".into()),
        harness: "org.openaevc.testkit.harness".into(),
        extension: Some(ext.clone()),
        grants: vec![d("grant")],
        request_id: req,
        pack,
        generation: 2,
        execution: exe,
        runtime_instance: rti,
        inputs: vec![],
    };
    let blob = Blob {
        media_type: "application/json".into(),
        data: br#"{"key":"config/limit","value":"42"}"#.to_vec(),
    };
    let grant_body = GrantBody {
        id: cx.ids.next(),
        namespace: cx.ns,
        issuer: cx.pri,
        subject: cx.ids.next(),
        actions: ["changepack.create", "changepack.seal", "kv.*"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        resources: vec![ResourceSelector {
            kind: "kv.entry".into(),
            locator_prefix: Some("config/".into()),
        }],
        constraints: BTreeMap::new(),
        not_before: t0,
        expires_at: ts("2025-05-01T12:00:00Z"),
        delegation_depth: 1,
        parent: Some(d("parent-grant")),
        nonce: "bm9uY2UtMQ".into(),
    };
    let grant_msg = openaevc_canonical::to_canonical(&grant_body).unwrap();
    let grant = SignedGrant {
        signature: cx.key.sign(Domain::Grant, &grant_msg),
        body: grant_body,
    };
    let policy = PolicyDocument {
        name: "org.example.gates".into(),
        description: Some("Require passing expectation checks.".into()),
        rules: vec![PolicyRule {
            id: "expect-pass".into(),
            expr: Expr::All(vec![
                Expr::Verifier(VerifierCondition {
                    kind: "kv.expect".into(),
                    status: VerificationStatus::Pass,
                }),
                Expr::Not(Box::new(Expr::Evaluator(EvaluatorCondition {
                    kind: "kv.size".into(),
                    verdict: EvaluationVerdict::Deny,
                }))),
            ]),
        }],
    };
    let mut facts = Facts::new();
    facts.insert(
        "verification.kv.expect.status".into(),
        FactValue::Text("PASS".into()),
    );
    facts.insert(
        "kv.keys".into(),
        FactValue::Set(BTreeSet::from(["config/limit".to_string()])),
    );
    facts.insert("kv.count".into(), FactValue::Int(1));
    let effect = AppliedEffect {
        id: cx.ids.next(),
        work_unit: wu,
        kind: "kv.set".into(),
        target: resource.clone(),
        payload: json!({"value": "42"}),
        preconditions: vec![json!({"absent": true})],
        outputs: vec![],
        outcome: json!({"previous": "absent"}),
        provenance: prov.clone(),
    };
    let manifest = ExtensionManifest {
        id: ext.id.clone(),
        version: "0.1.0".into(),
        protocol: SUPPORTED_PROTOCOL,
        contract: SUPPORTED_CONTRACT,
        publisher: Some(cx.key.public_key()),
        artifact_digest: d("artifact"),
        resource_kinds: vec![ResourceKindDecl {
            kind: "kv.entry".into(),
            description: None,
        }],
        effect_kinds: vec![EffectKindDecl {
            kind: "kv.set".into(),
            resource_kind: "kv.entry".into(),
            required_actions: vec!["kv.write".into()],
        }],
        verifier_kinds: vec!["kv.expect".into()],
        evaluator_kinds: vec!["kv.size".into()],
        composition_validators: vec!["kv.terminal-values".into()],
        host_capabilities: vec![HostCapability::ResourceRead],
        schemas: BTreeMap::new(),
        execution_modes: vec!["subprocess".into()],
        entrypoint: Entrypoint {
            command: "openaevc-ext-reference-kv".into(),
            args: vec![],
        },
    };
    let decision = PolicyDecision {
        pack,
        generation: 2,
        candidate: d("candidate"),
        policies: vec![d("policy")],
        facts: facts.clone(),
        outcome: DecisionOutcome::Allow,
        rules: vec![RuleResult {
            policy: d("policy"),
            rule: "expect-pass".into(),
            passed: true,
        }],
        evaluated_at: t1,
    };
    let run = RunProvenance {
        caller: cx.pri,
        request_id: req,
        runtime_instance: rti,
    };
    let record = PromotionRecord {
        id: cx.ids.next(),
        pack,
        generation: 2,
        candidate: d("candidate"),
        policy_decision: d("decision"),
        promoted_by: cx.pri,
        promoted_at: t1,
        request_id: req,
    };
    let promoted = PromotedPack {
        pack,
        generation: 2,
        candidate: d("candidate"),
        effects: vec![EffectSummary {
            kind: "kv.set".into(),
            target: resource.clone(),
        }],
        resources: vec![resource.clone()],
        dependencies: vec![d("dependency")],
        conflicts_with: vec![],
        revision: Some(RevisionInfo {
            relation: RevisionRelation::Amends,
            targets: vec![d("target")],
        }),
        verifications: vec![d("verification")],
        evaluations: vec![d("evaluation")],
        evidence: vec![d("evidence")],
        policy_decisions: vec![d("decision")],
        promotion_record: d("record"),
        extensions: vec![ext.clone()],
        intent: Some(json!({"org.example.summary": "raise limit"})),
        metadata: BTreeMap::new(),
        provenance_root: d("provenance"),
    };
    let (m0, m1) = (d("member-0"), d("member-1"));
    let baseline = Baseline {
        id: cx.ids.next(),
        members: vec![m0.min(m1), m0.max(m1)],
        edges: vec![CompositionEdge {
            from: m0.max(m1),
            to: m0.min(m1),
            kind: CompositionEdgeKind::Requires,
            relation: None,
        }],
        heads: vec![m0.min(m1), m0.max(m1)],
        policies: vec![d("policy")],
        facts: Facts::new(),
        graph_digest: d("graph"),
        metadata: BTreeMap::new(),
    };
    let receipt = Receipt {
        request_id: req,
        command: "SealChangePack".into(),
        caller: cx.pri,
        envelope_digest: d("envelope"),
        result: CommandResult {
            id: Some(pack.to_string()),
            generation: Some(2),
            state: Some("SEALED".into()),
            ..Default::default()
        },
        first_seq: 10,
        last_seq: 10,
        runtime_instance: rti,
        completed_at: t1,
    };
    let checkpoint = JournalCheckpoint {
        sequence: 100,
        event_hash: d("event-100"),
        runtime_key: cx.runtime_key.public_key(),
        runtime_instance: rti,
        created_at: t1,
    };
    let bodies: Vec<(&str, ObjectKind, Value)> = vec![
        (
            "blob",
            ObjectKind::Blob,
            serde_json::to_value(&blob).unwrap(),
        ),
        (
            "capability_grant",
            ObjectKind::CapabilityGrant,
            serde_json::to_value(&grant).unwrap(),
        ),
        (
            "revocation",
            ObjectKind::Revocation,
            serde_json::to_value(Revocation {
                grant: grant.body.id,
                grant_digest: d("grant"),
                revoked_by: cx.pri,
                revoked_at: t1,
                reason: Some("rotated".into()),
            })
            .unwrap(),
        ),
        (
            "policy_document",
            ObjectKind::PolicyDocument,
            serde_json::to_value(&policy).unwrap(),
        ),
        (
            "policy_decision",
            ObjectKind::PolicyDecision,
            serde_json::to_value(&decision).unwrap(),
        ),
        (
            "extension_manifest",
            ObjectKind::ExtensionManifest,
            serde_json::to_value(&manifest).unwrap(),
        ),
        (
            "candidate",
            ObjectKind::Candidate,
            serde_json::to_value(Candidate {
                pack,
                generation: 2,
                effects: vec![effect.clone()],
            })
            .unwrap(),
        ),
        (
            "observation",
            ObjectKind::Observation,
            serde_json::to_value(Observation {
                id: cx.ids.next(),
                execution: exe,
                pack,
                generation: 2,
                work_unit: wu,
                producer: cx.pri,
                observed_at: t0,
                kind: "kv.read".into(),
                payload: Some(json!({"value": "41"})),
                blob: Some(d("blob")),
                related_resources: vec![resource.clone()],
                related_effects: vec![effect.id],
                provenance: prov.clone(),
            })
            .unwrap(),
        ),
        (
            "evidence",
            ObjectKind::Evidence,
            serde_json::to_value(Evidence {
                id: cx.ids.next(),
                kind: "kv.snapshot".into(),
                producer: cx.pri,
                pack,
                generation: 2,
                candidate: d("candidate"),
                payload: d("blob"),
                media_type: "application/json".into(),
                schema: Some(SchemaRef {
                    id: "kv.snapshot".into(),
                    version: "1".into(),
                }),
                sources: vec![NodeRef::from(exe)],
                extension: Some(ext.clone()),
                created_at: t1,
            })
            .unwrap(),
        ),
        (
            "verification_result",
            ObjectKind::VerificationResult,
            serde_json::to_value(VerificationResult {
                id: cx.ids.next(),
                pack,
                generation: 2,
                candidate: d("candidate"),
                verifier: "kv.expect".into(),
                extension: Some(ext.clone()),
                config: Some(json!({"key": "config/limit", "value": "42"})),
                status: VerificationStatus::Pass,
                evidence: vec![d("evidence")],
                findings: vec![Finding {
                    code: "kv.match".into(),
                    message: "value matches".into(),
                    resource: Some(resource.clone()),
                }],
                facts: facts.clone(),
                started_at: t0,
                finished_at: t1,
                provenance: run.clone(),
            })
            .unwrap(),
        ),
        (
            "evaluation_result",
            ObjectKind::EvaluationResult,
            serde_json::to_value(EvaluationResult {
                id: cx.ids.next(),
                pack,
                generation: 2,
                candidate: d("candidate"),
                evaluator: "kv.size".into(),
                extension: Some(ext.clone()),
                config: Some(json!({"max_keys": 10})),
                verdict: EvaluationVerdict::Allow,
                metrics: BTreeMap::from([("kv.keys".to_string(), 1)]),
                facts: Facts::new(),
                inputs: vec![d("verification")],
                started_at: t0,
                finished_at: t1,
                provenance: run,
            })
            .unwrap(),
        ),
        (
            "promoted_pack",
            ObjectKind::PromotedPack,
            serde_json::to_value(&promoted).unwrap(),
        ),
        (
            "promotion_record",
            ObjectKind::PromotionRecord,
            serde_json::to_value(&record).unwrap(),
        ),
        (
            "receipt",
            ObjectKind::Receipt,
            serde_json::to_value(&receipt).unwrap(),
        ),
        (
            "baseline",
            ObjectKind::Baseline,
            serde_json::to_value(&baseline).unwrap(),
        ),
        (
            "journal_checkpoint",
            ObjectKind::JournalCheckpoint,
            serde_json::to_value(&checkpoint).unwrap(),
        ),
    ];
    let mut valid = Vec::new();
    for (i, (name, kind, body)) in bodies.into_iter().enumerate() {
        let mut env = cx.env(kind, i as u64 + 1, &body);
        if matches!(kind, ObjectKind::Receipt | ObjectKind::JournalCheckpoint) {
            env = sign_envelope(env, &cx.runtime_key).unwrap();
        }
        if kind == ObjectKind::Baseline {
            env.id = Some(baseline.id.to_string());
        }
        let obj = ImmutableObject::build(env).unwrap();
        let refs: Vec<String> = obj
            .references()
            .unwrap()
            .iter()
            .map(|d| d.to_string())
            .collect();
        valid.push(json!({
            "name": name,
            "kind": kind,
            "json": openaevc_canonical::to_value(obj.envelope()).unwrap(),
            "cbor_hex": hex(obj.bytes()),
            "digest": obj.digest().to_string(),
            "references": refs,
        }));
    }
    // Invalid objects.
    let blob_env = cx.env(ObjectKind::Blob, 1, &blob);
    let good = ImmutableObject::build(blob_env.clone()).unwrap();
    let raw = |v: Value| hex(&openaevc_canonical::encode(&v).unwrap());
    let mut unknown = serde_json::to_value(&blob_env).unwrap();
    unknown["surprise"] = json!(1);
    let mut body_extra = serde_json::to_value(&blob_env).unwrap();
    body_extra["body"]["x"] = json!(1);
    let mut wrong_kind = serde_json::to_value(&blob_env).unwrap();
    wrong_kind["kind"] = json!("policy_document");
    let mut future = serde_json::to_value(&blob_env).unwrap();
    future["protocol_version"] = json!("9.0.0");
    let mut unknown_kind = serde_json::to_value(&blob_env).unwrap();
    unknown_kind["kind"] = json!("branch");
    let mut forged = sign_envelope(blob_env.clone(), &cx.runtime_key).unwrap();
    forged.created_seq = 99;
    let invalid = json!([
        {"name": "digest_mismatch", "cbor_hex": hex(good.bytes()), "digest": openaevc_crypto::sha256(b"x").to_string(), "error": "DIGEST_MISMATCH"},
        {"name": "unknown_envelope_field", "cbor_hex": raw(unknown), "error": "CANONICAL_ENCODING_ERROR"},
        {"name": "unknown_body_field", "cbor_hex": raw(body_extra), "error": "INVALID_ARGUMENT"},
        {"name": "body_does_not_match_kind", "cbor_hex": raw(wrong_kind), "error": "INVALID_ARGUMENT"},
        {"name": "unsupported_protocol_version", "cbor_hex": raw(future), "error": "PROTOCOL_VERSION_UNSUPPORTED"},
        {"name": "unknown_object_kind", "cbor_hex": raw(unknown_kind), "error": "CANONICAL_ENCODING_ERROR"},
        {"name": "forged_signature", "cbor_hex": raw(serde_json::to_value(&forged).unwrap()), "error": "UNAUTHORIZED"},
        {"name": "map_length_mismatch", "cbor_hex": format!("a1{}", &hex(good.bytes())[2..]), "error": "CANONICAL_ENCODING_ERROR"},
    ]);
    json!({"protocol_version": PROTOCOL_VERSION, "valid": valid, "invalid": invalid})
}

fn signatures(cx: &Ctx) -> Value {
    let key = SigningKey::from_seed([3; 32]);
    let env = CommandEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: cx.ids.next(),
        namespace: Some(cx.ns),
        caller: cx.pri,
        act_as: None,
        nonce: "c2lnbmF0dXJlLWZpeHR1cmU".into(),
        issued_at: ts("2024-05-01T12:00:00.000000000Z"),
        expires_at: None,
        body: Command::SealChangePack {
            pack: PackId::Change(cx.ids.next()),
            expected_generation: 3,
        },
        signature: None,
    };
    let unsigned = serde_json::to_value(&env).unwrap();
    let msg = openaevc_canonical::encode(&unsigned).unwrap();
    let grant = GrantBody {
        id: cx.ids.next(),
        namespace: cx.ns,
        issuer: cx.pri,
        subject: cx.ids.next(),
        actions: BTreeSet::from(["*".to_string()]),
        resources: vec![],
        constraints: BTreeMap::new(),
        not_before: ts("2024-01-01T00:00:00Z"),
        expires_at: ts("2030-01-01T00:00:00Z"),
        delegation_depth: 0,
        parent: None,
        nonce: "Z3JhbnQ".into(),
    };
    let gv = serde_json::to_value(&grant).unwrap();
    let gmsg = openaevc_canonical::encode(&gv).unwrap();
    json!({
        "description": "Ed25519 over \"OPENAEVC/1 <domain>\\n\" || canonical(unsigned value).",
        "cases": [
            {"name": "command_envelope", "domain": "request", "seed_hex": hex(&[3; 32]), "public_key": key.public_key(),
             "unsigned": unsigned, "message_hex": hex(&msg), "signature": key.sign(Domain::Request, &msg)},
            {"name": "grant", "domain": "grant", "seed_hex": hex(&[3; 32]), "public_key": key.public_key(),
             "unsigned": gv, "message_hex": hex(&gmsg), "signature": key.sign(Domain::Grant, &gmsg)},
        ]
    })
}

fn identifiers(cx: &Ctx) -> Value {
    let cpk: ChangePackId = cx.ids.next();
    json!({
        "valid": [cx.ns.to_string(), cx.pri.to_string(), cpk.to_string(), cpk.to_string().to_uppercase().replacen("CPK_", "cpk_", 1),
                  format!("sha256:{}", "0".repeat(64)), "2024-05-01T12:00:00Z", "2024-05-01T12:00:00.123456789Z"],
        "invalid": ["cpk_", "cpk_agjdus24nvyadaareizuivlgo", "xyz_agjdus24nvyadaareizuivlgo4", "cpk_aaaaaaaaaaaaaaaaaaaaaaaaaa",
                    format!("sha256:{}", "A".repeat(64)), format!("md5:{}", "0".repeat(32)), "2024-05-01T12:00:00+01:00", "2024-13-01T00:00:00Z", ""],
    })
}

fn authority(cx: &Ctx) -> Value {
    use openaevc_authority::sign_grant;
    let t = |s: &str| ts(s);
    let key = |n: u8| SigningKey::from_seed([n; 32]);
    let (root_k, alice_k, bob_k, carol_k) = (key(10), key(11), key(12), key(13));
    let root: PrincipalId = cx.ids.next();
    let alice: PrincipalId = cx.ids.next();
    let bob: PrincipalId = cx.ids.next();
    let carol: PrincipalId = cx.ids.next();
    let principal = |id: PrincipalId, k: &SigningKey| json!({"id": id, "kind": "KEY", "public_key": k.public_key()});
    let body = |id: GrantId,
                issuer,
                subject,
                actions: &[&str],
                parent: Option<Digest>,
                depth: u32,
                exp: &str| GrantBody {
        id,
        namespace: cx.ns,
        issuer,
        subject,
        actions: actions.iter().map(|s| s.to_string()).collect(),
        resources: vec![ResourceSelector {
            kind: "kv.*".into(),
            locator_prefix: Some("app/".into()),
        }],
        constraints: BTreeMap::new(),
        not_before: t("2024-01-01T00:00:00Z"),
        expires_at: t(exp),
        delegation_depth: depth,
        parent,
        nonce: "Zml4dHVyZQ".into(),
    };
    let g_alice = sign_grant(
        body(
            cx.ids.next(),
            root,
            alice,
            &["changepack.*", "kv.write"],
            None,
            1,
            "2030-01-01T00:00:00Z",
        ),
        &root_k,
    )
    .unwrap();
    let d_alice = openaevc_crypto::digest_of(&g_alice).unwrap();
    let g_bob = sign_grant(
        body(
            cx.ids.next(),
            alice,
            bob,
            &["changepack.create"],
            Some(d_alice),
            0,
            "2029-01-01T00:00:00Z",
        ),
        &alice_k,
    )
    .unwrap();
    let d_bob = openaevc_crypto::digest_of(&g_bob).unwrap();
    let g_bob_wide = sign_grant(
        body(
            cx.ids.next(),
            alice,
            bob,
            &["baseline.create"],
            Some(d_alice),
            0,
            "2029-01-01T00:00:00Z",
        ),
        &alice_k,
    )
    .unwrap();
    let d_bob_wide = openaevc_crypto::digest_of(&g_bob_wide).unwrap();
    let g_carol_expired = sign_grant(
        body(
            cx.ids.next(),
            root,
            carol,
            &["changepack.seal"],
            None,
            0,
            "2024-02-01T00:00:00Z",
        ),
        &root_k,
    )
    .unwrap();
    let d_carol = openaevc_crypto::digest_of(&g_carol_expired).unwrap();
    let mut g_forged = sign_grant(
        body(
            cx.ids.next(),
            root,
            carol,
            &["changepack.create"],
            None,
            0,
            "2030-01-01T00:00:00Z",
        ),
        &carol_k,
    )
    .unwrap();
    g_forged.body.nonce = "Zm9yZ2Vk".into();
    let d_forged = openaevc_crypto::digest_of(&g_forged).unwrap();
    let res = |loc: &str| json!({"kind": "kv.entry", "locator": loc, "extension": "org.openaevc.reference.kv"});
    json!({
        "description": "Authorization matrix. `expect` is ALLOW or an error code; `chain` lists grant digests leaf first.",
        "now": "2025-01-01T00:00:00.000000000Z",
        "namespace": cx.ns,
        "roots": [root],
        "principals": [principal(root, &root_k), principal(alice, &alice_k), principal(bob, &bob_k), principal(carol, &carol_k)],
        "grants": [
            {"digest": d_alice, "grant": g_alice},
            {"digest": d_bob, "grant": g_bob},
            {"digest": d_bob_wide, "grant": g_bob_wide},
            {"digest": d_carol, "grant": g_carol_expired},
            {"digest": d_forged, "grant": g_forged},
        ],
        "cases": [
            {"name": "root_implicit", "principal": root, "action": "baseline.create", "expect": "ALLOW", "chain": []},
            {"name": "direct_grant", "principal": alice, "action": "changepack.seal", "resource": res("app/1"), "expect": "ALLOW", "chain": [d_alice]},
            {"name": "resource_outside_selector", "principal": alice, "action": "kv.write", "resource": res("other/1"), "expect": "FORBIDDEN", "chain": []},
            {"name": "delegated", "principal": bob, "action": "changepack.create", "resource": res("app/2"), "expect": "ALLOW", "chain": [d_bob, d_alice]},
            {"name": "delegation_widening", "principal": bob, "action": "baseline.create", "expect": "FORBIDDEN", "chain": []},
            {"name": "default_deny", "principal": bob, "action": "changepack.promote", "expect": "FORBIDDEN", "chain": []},
            {"name": "expired", "principal": carol, "action": "changepack.seal", "expect": "CAPABILITY_EXPIRED", "chain": []},
            {"name": "forged_signature", "principal": carol, "action": "changepack.create", "expect": "FORBIDDEN", "chain": []},
            {"name": "revoked_parent", "principal": bob, "action": "changepack.create", "resource": res("app/2"), "revoked": [g_alice.body.id], "expect": "CAPABILITY_REVOKED", "chain": []},
        ],
    })
}

fn main() {
    let check = std::env::args().any(|a| a == "--check");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/canonical");
    let cx = Ctx::new();
    let files = [
        ("values.json", values()),
        ("objects.json", objects(&cx)),
        ("signatures.json", signatures(&cx)),
        ("identifiers.json", identifiers(&cx)),
        ("../authority/matrix.json", authority(&cx)),
    ];
    let mut stale = false;
    for (name, v) in files {
        let content = serde_json::to_string_pretty(&v).unwrap() + "\n";
        let path = root.join(name);
        if check {
            if std::fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
                eprintln!(
                    "fixtures/canonical/{name} is out of date; run `cargo run -p fixture-builder`"
                );
                stale = true;
            }
        } else {
            std::fs::write(&path, content).unwrap();
            println!("wrote fixtures/canonical/{name}");
        }
    }
    if stale {
        std::process::exit(1);
    }
}
