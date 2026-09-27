//! Runtime support for transports: event subscriptions and out-of-envelope object payloads.

use openaevc_protocol::*;
use openaevc_testkit::*;

#[test]
fn subscriptions_resume_from_cursor_and_filter() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let env = h.client(&root, ns).query_envelope(Query::ListEvents {
        after: 1,
        limit: None,
        kinds: vec!["principal.registered".into()],
    });
    let mut sub = h.rt.subscribe(env, vec![]).unwrap();
    let first = h.rt.poll(&mut sub, 100).unwrap();
    assert_eq!(
        first.len(),
        1,
        "root principal registration after namespace.created"
    );
    assert!(h.rt.poll(&mut sub, 100).unwrap().is_empty());
    h.client(&root, ns)
        .cmd(Command::CreateChangePack {
            spec: PackSpec::default(),
        })
        .unwrap();
    let p = h.register_key_principal(&root, ns);
    let next = h.rt.poll(&mut sub, 100).unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].body["principal"]["id"], p.id().to_string());
    assert_eq!(
        sub.cursor(),
        h.events(&root, ns).last().unwrap()["sequence"]
            .as_u64()
            .unwrap()
    );
    // Long-lived: polling keeps working after the envelope's freshness window.
    h.clock.advance_millis(3_600_000);
    assert!(h.rt.poll(&mut sub, 100).unwrap().is_empty());
}

#[test]
fn subscriptions_filter_by_subject_and_respect_revocation() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let alice = h.register_key_principal(&root, ns);
    let grant = h.grant(&root, ns, &alice, &["namespace.read"]);
    let pack = h.create_pack(&root, ns);
    let env = h.client(&alice, ns).query_envelope(Query::ListEvents {
        after: 0,
        limit: None,
        kinds: vec![],
    });
    let mut sub = h.rt.subscribe(env, vec![pack.to_string()]).unwrap();
    let evs = h.rt.poll(&mut sub, 100).unwrap();
    assert!(!evs.is_empty() && evs.iter().all(|e| e.subjects.contains(&pack.to_string())));
    h.client(&root, ns)
        .cmd(Command::RevokeCapabilityGrant {
            grant,
            reason: None,
        })
        .unwrap();
    assert_eq!(
        h.rt.poll(&mut sub, 100).unwrap_err().code,
        ErrorCode::CapabilityRevoked
    );
}

#[test]
fn subscriptions_require_a_list_events_envelope_with_read_authority() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let env = h.client(&root, ns).query_envelope(Query::GetNamespace {});
    assert_eq!(
        h.rt.subscribe(env, vec![]).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let bob = h.register_key_principal(&root, ns);
    let env = h.client(&bob, ns).query_envelope(Query::ListEvents {
        after: 0,
        limit: None,
        kinds: vec![],
    });
    assert_eq!(
        h.rt.subscribe(env, vec![]).unwrap_err().code,
        ErrorCode::Forbidden
    );
}

#[test]
fn object_payload_travels_outside_the_signed_envelope() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let pack = h.create_pack(&root, ns);
    let cand = h.seal(&root, ns, pack);
    let other = Harness::new();
    let r2 = Identity::generate();
    let ns2 = other.create_namespace(&r2);
    let v = h
        .client(&root, ns)
        .query(Query::GetObject { digest: cand })
        .unwrap();
    let bytes = b64::decode(v["canonical"].as_str().unwrap()).unwrap();
    let c = other.client(&r2, ns2);
    let env = c.command_envelope(Command::PutImmutableObject {
        digest: cand,
        bytes: vec![],
    });
    other.rt.execute_with_payload(env, bytes.clone()).unwrap();
    // Payload must match the signed digest.
    let env = c.command_envelope(Command::PutImmutableObject {
        digest: openaevc_crypto::sha256(b"other"),
        bytes: vec![],
    });
    assert_eq!(
        other
            .rt
            .execute_with_payload(env, bytes.clone())
            .unwrap_err()
            .code,
        ErrorCode::DigestMismatch
    );
    // Only PutImmutableObject with an empty inline payload is accepted.
    let env = c.command_envelope(Command::PutImmutableObject {
        digest: cand,
        bytes: vec![1],
    });
    assert_eq!(
        other
            .rt
            .execute_with_payload(env, bytes.clone())
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    let env = c.command_envelope(Command::CreateChangePack {
        spec: PackSpec::default(),
    });
    assert_eq!(
        other.rt.execute_with_payload(env, bytes).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}
