//! Phase 8: execution admission, leases, effects, observations, provenance, loss and retry.

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

fn submit(
    h: &Harness,
    who: &Identity,
    ns: NamespaceId,
    exe: ExecutionId,
    lease: &Lease,
    e: EffectProposal,
) -> Result<CommandReceipt, ProtocolError> {
    h.client(who, ns).cmd(Command::SubmitEffectProposal {
        execution: exe,
        lease: lease.id,
        effect: e,
    })
}

fn heartbeat(
    h: &Harness,
    who: &Identity,
    ns: NamespaceId,
    exe: ExecutionId,
    lease: &Lease,
) -> Result<CommandReceipt, ProtocolError> {
    h.client(who, ns).cmd(Command::HeartbeatExecution {
        execution: exe,
        lease: lease.id,
        generation: lease.generation,
    })
}

fn execution(h: &Harness, who: &Identity, ns: NamespaceId, exe: ExecutionId) -> Execution {
    serde_json::from_value(
        h.client(who, ns)
            .query(Query::GetExecution { execution: exe })
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn complete_execution_flow_through_reference_kv() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    let exe = h.run(
        &root,
        ns,
        pack,
        &mut ScriptedHarness {
            effects: vec![kv_set("config/limit", "42"), kv_set("config/mode", "fast")],
        },
    );
    let e = execution(&h, &root, ns, exe);
    assert_eq!(e.state, ExecutionState::Succeeded);
    assert_eq!(e.effects.len(), 2);
    assert_eq!(e.observations.len(), 2);
    let p = h.pack(&root, ns, pack);
    assert_eq!(p.candidate_effects.len(), 2);
    assert_eq!(p.work_units[0].state, WorkUnitState::Completed);
    let prov = &p.candidate_effects[0].provenance;
    assert_eq!(
        (prov.execution, prov.generation, prov.pack),
        (exe, p.generation, pack)
    );
    assert_eq!(prov.harness, HARNESS);
    assert_eq!(prov.worker.as_deref(), Some("worker-1"));
    assert_eq!(prov.extension.as_ref().unwrap().id, KV);
    assert_eq!(p.candidate_effects[0].outcome, json!({"value": "42"}));
    let seal = h
        .client(&root, ns)
        .cmd(Command::SealChangePack {
            pack,
            expected_generation: p.generation,
        })
        .unwrap();
    let cand = h
        .client(&root, ns)
        .query(Query::GetObject {
            digest: seal.result.digest.unwrap(),
        })
        .unwrap();
    assert_eq!(
        cand["envelope"]["body"]["effects"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let kinds: Vec<String> = h
        .events(&root, ns)
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    for k in [
        "execution.admitted",
        "execution.running",
        "effect.applied",
        "observation.appended",
        "execution.succeeded",
    ] {
        assert!(kinds.contains(&k.to_string()), "{k}");
    }
}

#[test]
fn extension_rejections_are_recorded_not_applied() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    let wu = h.add_work(&root, ns, pack);
    let (exe, lease) = h.start(&root, ns, pack, wu);
    let mut e = kv_set("k", "v");
    e.preconditions = vec![json!({"equals": "something-else"})];
    let r = submit(&h, &root, ns, exe, &lease, e).unwrap();
    assert_eq!(r.result.state.as_deref(), Some("REJECTED"));
    assert!(h.pack(&root, ns, pack).candidate_effects.is_empty());
    let bad_payload = EffectProposal {
        payload: json!({"value": 7}),
        ..kv_set("k", "v")
    };
    assert_eq!(
        submit(&h, &root, ns, exe, &lease, bad_payload)
            .unwrap()
            .result
            .state
            .as_deref(),
        Some("REJECTED")
    );
    assert!(h
        .events(&root, ns)
        .iter()
        .any(|e| e["kind"] == "effect.rejected"));
}

#[test]
fn authority_restricts_effects() {
    let (_ext, h, root, ns) = setup();
    let alice = h.register_key_principal(&root, ns);
    h.grant(
        &root,
        ns,
        &alice,
        &[
            "changepack.*",
            "execution.start",
            "observation.append",
            "namespace.read",
        ],
    );
    let pack = h.create_pack(&alice, ns);
    let wu = h.add_work(&alice, ns, pack);
    // Admission: alice cannot claim a kv.write scope she does not hold.
    let g = h.pack(&alice, ns, pack).generation;
    let e = h
        .client(&alice, ns)
        .cmd(Command::StartExecution {
            request: h.execution_request(pack, g, wu),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    assert_eq!(e.missing_action.as_deref(), Some("kv.write"));
    // With kv.write only under app/, effects outside app/ and undeclared kinds are refused.
    let mut b = h.sign_grant(&root, ns, alice.id(), &["kv.write"], None);
    b.body.resources = vec![ResourceSelector {
        kind: "kv.entry".into(),
        locator_prefix: Some("app/".into()),
    }];
    let signed = openaevc_authority::sign_grant(b.body, root.key()).unwrap();
    h.client(&root, ns)
        .cmd(Command::IssueCapabilityGrant { grant: signed })
        .unwrap();
    let mut req = h.execution_request(pack, g, wu);
    req.allowed_resources = vec![ResourceSelector {
        kind: "kv.entry".into(),
        locator_prefix: Some("app/".into()),
    }];
    req.allowed_effects = vec!["kv.set".into()];
    let r = h
        .client(&alice, ns)
        .cmd(Command::StartExecution { request: req })
        .unwrap();
    let (exe, lease): (ExecutionId, Lease) = (receipt_id(&r), r.result.lease.unwrap());
    assert_eq!(
        submit(&h, &alice, ns, exe, &lease, kv_set("app/x", "1"))
            .unwrap()
            .result
            .state
            .as_deref(),
        Some("APPLIED")
    );
    assert_eq!(
        submit(&h, &alice, ns, exe, &lease, kv_set("etc/x", "1"))
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        submit(&h, &alice, ns, exe, &lease, kv_delete("app/x"))
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    // Provenance records the grant chain used.
    let p = h.pack(&alice, ns, pack);
    assert!(!p.candidate_effects[0].provenance.grants.is_empty());
    // Someone else cannot drive alice's execution.
    let bob = h.register_key_principal(&root, ns);
    h.grant(&root, ns, &bob, &["execution.start", "kv.write"]);
    assert_eq!(
        submit(&h, &bob, ns, exe, &lease, kv_set("app/y", "1"))
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
}

#[test]
fn admission_checks_readiness_leases_and_idempotency() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    let first = h.add_work(&root, ns, pack);
    let g = h.pack(&root, ns, pack).generation;
    let second: WorkUnitId = receipt_id(
        &h.client(&root, ns)
            .cmd(Command::AddWorkUnit {
                pack,
                expected_generation: g,
                kind: "org.example.task".into(),
                spec: None,
                depends_on: vec![NodeRef::from(first)],
            })
            .unwrap(),
    );
    let g = h.pack(&root, ns, pack).generation;
    let e = h
        .client(&root, ns)
        .cmd(Command::StartExecution {
            request: h.execution_request(pack, g, second),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ExecutionNotReady);
    let req = h.execution_request(pack, g, first);
    let r1 = h
        .client(&root, ns)
        .cmd(Command::StartExecution {
            request: req.clone(),
        })
        .unwrap();
    // Same idempotency key: same execution.
    let r2 = h
        .client(&root, ns)
        .cmd(Command::StartExecution { request: req })
        .unwrap();
    assert_eq!(r1.result.id, r2.result.id);
    // Different key while active: lease conflict.
    let e = h
        .client(&root, ns)
        .cmd(Command::StartExecution {
            request: h.execution_request(pack, g, first),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    // Sealing while an execution is active is refused.
    assert_eq!(
        h.client(&root, ns)
            .cmd(Command::SealChangePack {
                pack,
                expected_generation: g
            })
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    // Stale generation and unknown effect kinds are refused at admission.
    let mut stale = h.execution_request(pack, g - 1, first);
    stale.idempotency_key = "c3RhbGU".into();
    assert_eq!(
        h.client(&root, ns)
            .cmd(Command::StartExecution { request: stale })
            .unwrap_err()
            .code,
        ErrorCode::StaleGeneration
    );
}

#[test]
fn stale_generation_blocks_effects_of_running_execution() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    let wu = h.add_work(&root, ns, pack);
    let (exe, lease) = h.start(&root, ns, pack, wu);
    heartbeat(&h, &root, ns, exe, &lease).unwrap();
    h.add_work(&root, ns, pack);
    assert_eq!(
        submit(&h, &root, ns, exe, &lease, kv_set("k", "v"))
            .unwrap_err()
            .code,
        ErrorCode::StaleGeneration
    );
}

#[test]
fn wrong_lease_is_rejected() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    let wu = h.add_work(&root, ns, pack);
    let (exe, mut lease) = h.start(&root, ns, pack, wu);
    lease.id = h.ids_next();
    assert_eq!(
        submit(&h, &root, ns, exe, &lease, kv_set("k", "v"))
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        heartbeat(&h, &root, ns, exe, &lease).unwrap_err().code,
        ErrorCode::Forbidden
    );
}

#[test]
fn scenario_d_lost_execution_and_retry() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    let wu = h.add_work(&root, ns, pack);
    let (exe, lease) = h.start(&root, ns, pack, wu);
    heartbeat(&h, &root, ns, exe, &lease).unwrap();
    submit(&h, &root, ns, exe, &lease, kv_set("k", "1")).unwrap();
    // Heartbeats stop; the lease expires.
    h.clock.advance_millis(31_000);
    h.rt.tick().unwrap();
    let old = execution(&h, &root, ns, exe);
    assert_eq!(old.state, ExecutionState::Lost);
    assert!(h
        .events(&root, ns)
        .iter()
        .any(|e| e["kind"] == "execution.lost"));
    // A lost execution never succeeds and cannot submit late effects.
    assert_eq!(
        submit(&h, &root, ns, exe, &lease, kv_set("k", "2"))
            .unwrap_err()
            .code,
        ErrorCode::ExecutionLost
    );
    assert_eq!(
        h.client(&root, ns)
            .cmd(Command::CompleteExecution {
                execution: exe,
                lease: lease.id
            })
            .unwrap_err()
            .code,
        ErrorCode::ExecutionLost
    );
    assert_eq!(
        heartbeat(&h, &root, ns, exe, &lease).unwrap_err().code,
        ErrorCode::ExecutionLost
    );
    // Retry: a new attempt linked to the old one.
    let g = h.pack(&root, ns, pack).generation;
    let mut req = h.execution_request(pack, g, wu);
    req.retry_of = Some(exe);
    let r = h
        .client(&root, ns)
        .cmd(Command::StartExecution { request: req })
        .unwrap();
    let retry: ExecutionId = receipt_id(&r);
    let new = execution(&h, &root, ns, retry);
    assert_eq!((new.attempt, new.retry_of), (2, Some(exe)));
    let graph = h
        .client(&root, ns)
        .query(Query::GetActiveChangeGraph { pack: None })
        .unwrap();
    assert!(graph["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "DERIVED_FROM"
            && e["from"] == retry.to_string()
            && e["to"] == exe.to_string()));
    // The earlier attempt's applied effect remains attributable to it.
    assert_eq!(
        h.pack(&root, ns, pack).candidate_effects[0]
            .provenance
            .execution,
        exe
    );
}

#[test]
fn resumable_provider_can_resume_within_grace() {
    let (_ext, h, root, ns) = setup();
    h.client(&root, ns)
        .cmd(Command::RegisterProvider {
            provider: provider_descriptor(root.id(), true),
        })
        .unwrap();
    let pack = h.create_pack(&root, ns);
    let wu = h.add_work(&root, ns, pack);
    let (exe, lease) = h.start(&root, ns, pack, wu);
    h.clock.advance_millis(31_000);
    h.rt.tick().unwrap();
    assert_eq!(
        execution(&h, &root, ns, exe).state,
        ExecutionState::Starting
    );
    // Effects are refused until the lease is resumed with its exact proof.
    assert_eq!(
        submit(&h, &root, ns, exe, &lease, kv_set("k", "1"))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    heartbeat(&h, &root, ns, exe, &lease).unwrap();
    submit(&h, &root, ns, exe, &lease, kv_set("k", "1")).unwrap();
    // Past the grace period the execution is lost.
    h.clock.advance_millis(61_000);
    h.rt.tick().unwrap();
    assert_eq!(execution(&h, &root, ns, exe).state, ExecutionState::Lost);
}

#[test]
fn cancel_and_fail_are_terminal() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    let wu = h.add_work(&root, ns, pack);
    let (exe, lease) = h.start(&root, ns, pack, wu);
    h.client(&root, ns)
        .cmd(Command::CancelExecution {
            execution: exe,
            reason: Some("stop".into()),
        })
        .unwrap();
    assert_eq!(
        execution(&h, &root, ns, exe).state,
        ExecutionState::Cancelled
    );
    assert_eq!(
        submit(&h, &root, ns, exe, &lease, kv_set("k", "1"))
            .unwrap_err()
            .code,
        ErrorCode::InvalidTransition
    );
    let (exe2, lease2) = h.start(&root, ns, pack, wu);
    h.client(&root, ns)
        .cmd(Command::FailExecution {
            execution: exe2,
            lease: lease2.id,
            reason: "boom".into(),
        })
        .unwrap();
    let e = execution(&h, &root, ns, exe2);
    assert_eq!(
        (e.state, e.failure.as_deref()),
        (ExecutionState::Failed, Some("boom"))
    );
    assert_eq!(
        h.pack(&root, ns, pack).work_units[0].state,
        WorkUnitState::Open
    );
    let list = h
        .client(&root, ns)
        .query(Query::ListExecutions {
            pack: Some(pack),
            state: Some(ExecutionState::Failed),
        })
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[test]
fn observations_are_immutable_objects_with_provenance() {
    let (_ext, h, root, ns) = setup();
    let pack = h.create_pack(&root, ns);
    let wu = h.add_work(&root, ns, pack);
    let (exe, lease) = h.start(&root, ns, pack, wu);
    let r = h
        .client(&root, ns)
        .cmd(Command::AppendObservation {
            execution: exe,
            lease: lease.id,
            kind: "org.example.log".into(),
            payload: None,
            blob: Some(Blob {
                media_type: "text/plain".into(),
                data: b"hello".to_vec(),
            }),
            related_resources: vec![kv_resource("k")],
            related_effects: vec![],
        })
        .unwrap();
    let obj = h
        .client(&root, ns)
        .query(Query::GetObject {
            digest: r.result.digest.unwrap(),
        })
        .unwrap();
    assert_eq!(obj["envelope"]["kind"], "observation");
    assert_eq!(
        obj["envelope"]["body"]["provenance"]["execution"],
        exe.to_string()
    );
    let blob: Digest = obj["envelope"]["body"]["blob"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        h.client(&root, ns)
            .query(Query::GetObject { digest: blob })
            .unwrap()["envelope"]["kind"],
        "blob"
    );
}
