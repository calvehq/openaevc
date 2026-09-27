//! Phase 4: admission, namespaces, principals, grants, receipts, idempotency, journal.

use openaevc_protocol::*;
use openaevc_testkit::{Harness, Identity};
use serde_json::Value;

fn setup() -> (Harness, Identity, NamespaceId) {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    (h, root, ns)
}

#[test]
fn admin_creates_namespace_and_root_can_read_it() {
    let (h, root, ns) = setup();
    let v = h.client(&root, ns).query(Query::GetNamespace {}).unwrap();
    assert_eq!(v["id"], ns.to_string());
    assert_eq!(v["root_principals"][0], root.id().to_string());
}

#[test]
fn non_admin_cannot_create_namespace() {
    let h = Harness::new();
    let stranger = Identity::generate();
    let e = h
        .admin_client_as(&stranger)
        .cmd(Command::CreateNamespace {
            root_principals: vec![stranger.new_principal()],
            metadata: Default::default(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unauthorized);
}

#[test]
fn unsigned_forged_and_wrong_version_requests_rejected() {
    let (h, root, ns) = setup();
    let c = h.client(&root, ns);
    let mut env = c.query_envelope(Query::GetNamespace {});
    env.signature = None;
    assert_eq!(h.rt.query(env).unwrap_err().code, ErrorCode::Unauthorized);

    let mut env = c.query_envelope(Query::GetNamespace {});
    env.nonce = "dGFtcGVyZWQ".into();
    assert_eq!(h.rt.query(env).unwrap_err().code, ErrorCode::Unauthorized);

    let mut env = c.query_envelope(Query::GetNamespace {});
    env.protocol_version = ProtocolVersion::new(9, 0, 0);
    let env = c.resign(env);
    assert_eq!(
        h.rt.query(env).unwrap_err().code,
        ErrorCode::ProtocolVersionUnsupported
    );

    // Imposter claims root's principal ID but signs with its own key.
    let imposter = Identity::generate().with_id(root.id());
    let env = h
        .client(&imposter, ns)
        .query_envelope(Query::GetNamespace {});
    assert_eq!(h.rt.query(env).unwrap_err().code, ErrorCode::Unauthorized);
}

#[test]
fn default_deny_and_denials_are_audited() {
    let (h, root, ns) = setup();
    let alice = h.register_key_principal(&root, ns);
    let e = h
        .client(&alice, ns)
        .cmd(Command::RegisterPrincipal {
            principal: Identity::generate().new_principal(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    assert_eq!(e.missing_action.as_deref(), Some("principal.register"));
    let events = h.events(&root, ns);
    let denied: Vec<&Value> = events
        .iter()
        .filter(|e| e["kind"] == "authorization.denied")
        .collect();
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["body"]["action"], "principal.register");
    assert_eq!(denied[0]["actor"], alice.id().to_string());
    // Reads are protected too.
    assert_eq!(
        h.client(&alice, ns)
            .query(Query::GetNamespace {})
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
}

#[test]
fn granted_principal_can_act_until_revoked() {
    let (h, root, ns) = setup();
    let alice = h.register_key_principal(&root, ns);
    let grant = h.grant(&root, ns, &alice, &["principal.register", "namespace.read"]);
    h.client(&alice, ns)
        .cmd(Command::RegisterPrincipal {
            principal: Identity::generate().new_principal(),
        })
        .unwrap();
    assert_eq!(
        h.client(&alice, ns)
            .cmd(Command::IssueCapabilityGrant {
                grant: h.sign_grant(&alice, ns, root.id(), &["*"], None)
            })
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    h.client(&root, ns)
        .cmd(Command::RevokeCapabilityGrant {
            grant,
            reason: Some("rotation".into()),
        })
        .unwrap();
    let e = h
        .client(&alice, ns)
        .cmd(Command::RegisterPrincipal {
            principal: Identity::generate().new_principal(),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::CapabilityRevoked);
    let kinds: Vec<String> = h
        .events(&root, ns)
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    assert!(kinds.contains(&"grant.revoked".to_string()));
    assert_eq!(kinds.last().unwrap(), "authorization.denied");
}

#[test]
fn grant_must_be_submitted_by_its_issuer_and_valid() {
    let (h, root, ns) = setup();
    let alice = h.register_key_principal(&root, ns);
    let g = h.sign_grant(&root, ns, alice.id(), &["namespace.read"], None);
    let e = h
        .client(&alice, ns)
        .cmd(Command::IssueCapabilityGrant { grant: g.clone() })
        .unwrap_err();
    assert!(
        matches!(e.code, ErrorCode::Forbidden | ErrorCode::InvalidArgument),
        "{e:?}"
    );
    let mut forged = g;
    forged.body.actions.insert("*".into());
    let e = h
        .client(&root, ns)
        .cmd(Command::IssueCapabilityGrant { grant: forged })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unauthorized);
}

#[test]
fn delegated_actor_acts_through_linked_key() {
    let (h, root, ns) = setup();
    let alice = h.register_key_principal(&root, ns);
    let actor = h.register_actor(&root, ns, &alice);
    h.grant(&root, ns, &actor, &["namespace.read"]);
    assert!(h
        .client(&alice, ns)
        .act_as(actor.id())
        .query(Query::GetNamespace {})
        .is_ok());
    assert_eq!(
        h.client(&alice, ns)
            .query(Query::GetNamespace {})
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    let bob = h.register_key_principal(&root, ns);
    assert_eq!(
        h.client(&bob, ns)
            .act_as(actor.id())
            .query(Query::GetNamespace {})
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
}

#[test]
fn commands_are_idempotent_by_request_id() {
    let (h, root, ns) = setup();
    let c = h.client(&root, ns);
    let env = c.command_envelope(Command::RegisterPrincipal {
        principal: Identity::generate().new_principal(),
    });
    let before = h.events(&root, ns).len();
    let r1 = h.rt.execute(env.clone()).unwrap();
    let r2 = h.rt.execute(env.clone()).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(h.events(&root, ns).len(), before + 1);

    let mut other = env.clone();
    other.body = Command::RegisterPrincipal {
        principal: Identity::generate().new_principal(),
    };
    let other = c.resign(other);
    assert_eq!(
        h.rt.execute(other).unwrap_err().code,
        ErrorCode::ReplayDetected
    );

    let mut nonce_reuse = c.command_envelope(Command::RegisterPrincipal {
        principal: Identity::generate().new_principal(),
    });
    nonce_reuse.nonce = env.nonce.clone();
    let nonce_reuse = c.resign(nonce_reuse);
    assert_eq!(
        h.rt.execute(nonce_reuse).unwrap_err().code,
        ErrorCode::ReplayDetected
    );
}

#[test]
fn stale_requests_are_rejected() {
    let (h, root, ns) = setup();
    let c = h.client(&root, ns);
    let env = c.command_envelope(Command::RegisterPrincipal {
        principal: Identity::generate().new_principal(),
    });
    h.clock.advance_millis(301_000);
    assert_eq!(
        h.rt.execute(env).unwrap_err().code,
        ErrorCode::ReplayDetected
    );
}

#[test]
fn receipts_are_runtime_signed_objects() {
    let (h, root, ns) = setup();
    let r = h
        .client(&root, ns)
        .cmd(Command::RegisterPrincipal {
            principal: Identity::generate().new_principal(),
        })
        .unwrap();
    let obj = h
        .client(&root, ns)
        .query(Query::GetObject { digest: r.receipt })
        .unwrap();
    assert_eq!(obj["envelope"]["kind"], "receipt");
    let sig = &obj["envelope"]["signatures"][0];
    assert_eq!(sig["public_key"], h.rt.info().runtime_key.to_string());
    assert_eq!(obj["envelope"]["body"]["command"], "RegisterPrincipal");
    assert_eq!(r.first_seq, r.last_seq);
}

#[test]
fn journal_is_hash_chained_and_monotonic() {
    let (h, root, ns) = setup();
    for _ in 0..3 {
        h.client(&root, ns)
            .cmd(Command::RegisterPrincipal {
                principal: Identity::generate().new_principal(),
            })
            .unwrap();
    }
    let events: Vec<Event> = h
        .events(&root, ns)
        .into_iter()
        .map(|v| serde_json::from_value(v).unwrap())
        .collect();
    assert_eq!(
        events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        (1..=events.len() as u64).collect::<Vec<_>>()
    );
    openaevc_core::events::verify_chain(&events, 0, Digest::ZERO).unwrap();
    let page: Vec<Value> = serde_json::from_value(
        h.client(&root, ns)
            .query(Query::ListEvents {
                after: 2,
                limit: Some(1),
                kinds: vec![],
            })
            .unwrap(),
    )
    .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0]["sequence"], 3);
}

#[test]
fn checkpoints_are_signed_and_periodic() {
    let h = Harness::with_config(|c| c.checkpoint_interval = 3);
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    for _ in 0..4 {
        h.client(&root, ns)
            .cmd(Command::RegisterPrincipal {
                principal: Identity::generate().new_principal(),
            })
            .unwrap();
    }
    let cp = h
        .client(&root, ns)
        .query(Query::GetJournalCheckpoint {})
        .unwrap();
    assert_eq!(cp["envelope"]["kind"], "journal_checkpoint");
    // namespace.created + principal.registered, then 4 commands: events 1..=6, checkpoints at 3 and 6.
    assert_eq!(cp["envelope"]["body"]["sequence"], 6);
    assert_eq!(
        cp["envelope"]["signatures"][0]["public_key"],
        h.rt.info().runtime_key.to_string()
    );
}

#[test]
fn event_notifier_advances_on_commit() {
    let (h, root, ns) = setup();
    let rx = h.rt.subscribe_notifications();
    let before = *rx.borrow();
    h.client(&root, ns)
        .cmd(Command::RegisterPrincipal {
            principal: Identity::generate().new_principal(),
        })
        .unwrap();
    assert!(*rx.borrow() > before);
}

#[test]
fn policies_are_immutable_objects() {
    let (h, root, ns) = setup();
    let doc = PolicyDocument {
        name: "org.example.gates".into(),
        description: None,
        rules: vec![PolicyRule {
            id: "r".into(),
            expr: Expr::All(vec![]),
        }],
    };
    let r = h
        .client(&root, ns)
        .cmd(Command::RegisterPolicy {
            document: doc.clone(),
            mandatory: true,
        })
        .unwrap();
    let d = r.result.digest.unwrap();
    let nsv = h.client(&root, ns).query(Query::GetNamespace {}).unwrap();
    assert_eq!(nsv["mandatory_policies"][0], d.to_string());
    // Registering the same document again is idempotent by digest.
    let again = h
        .client(&root, ns)
        .cmd(Command::RegisterPolicy {
            document: doc,
            mandatory: true,
        })
        .unwrap();
    assert_eq!(again.result.digest, Some(d));
    let nsv = h.client(&root, ns).query(Query::GetNamespace {}).unwrap();
    assert_eq!(nsv["mandatory_policies"].as_array().unwrap().len(), 1);
}

#[test]
fn authorize_diagnostic_query() {
    let (h, root, ns) = setup();
    let alice = h.register_key_principal(&root, ns);
    let v = h
        .client(&root, ns)
        .query(Query::Authorize {
            principal: alice.id(),
            action: "changepack.create".into(),
            resource: None,
        })
        .unwrap();
    assert_eq!(v["allowed"], false);
    assert_eq!(v["error"]["code"], "FORBIDDEN");
    h.grant(&root, ns, &alice, &["changepack.*"]);
    let v = h
        .client(&root, ns)
        .query(Query::Authorize {
            principal: alice.id(),
            action: "changepack.create".into(),
            resource: None,
        })
        .unwrap();
    assert_eq!(v["allowed"], true);
}

#[test]
fn state_survives_runtime_restart_on_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let root = Identity::generate();
    let (ns, head) = {
        let h = Harness::sqlite(dir.path());
        let ns = h.create_namespace(&root);
        h.client(&root, ns)
            .cmd(Command::RegisterPrincipal {
                principal: Identity::generate().new_principal(),
            })
            .unwrap();
        (ns, h.events(&root, ns).len())
    };
    let h = Harness::sqlite(dir.path());
    assert_eq!(h.events(&root, ns).len(), head);
    h.client(&root, ns)
        .cmd(Command::RegisterPrincipal {
            principal: Identity::generate().new_principal(),
        })
        .unwrap();
}
