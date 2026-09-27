//! Phase 12: reachability, inventory and object exchange; Scenario G (and F's closure bullet).

use std::collections::BTreeSet;

use openaevc_protocol::*;
use openaevc_testkit::*;
use serde_json::Value;

fn digests(v: &Value) -> Vec<Digest> {
    serde_json::from_value(v.clone()).unwrap()
}

fn fetch(h: &Harness, who: &Identity, ns: NamespaceId, d: Digest) -> Vec<u8> {
    let v = h
        .client(who, ns)
        .query(Query::GetObject { digest: d })
        .unwrap();
    b64::decode(v["canonical"].as_str().unwrap()).unwrap()
}

/// Copies the objects of `closure` missing on B from A to B; returns how many were sent.
fn sync(
    a: (&Harness, &Identity, NamespaceId),
    b: (&Harness, &Identity, NamespaceId),
    closure: &[Digest],
) -> usize {
    let missing = digests(
        &b.0.client(b.1, b.2)
            .query(Query::ComputeMissingObjects {
                digests: closure.to_vec(),
            })
            .unwrap(),
    );
    for d in &missing {
        let bytes = fetch(a.0, a.1, a.2, *d);
        b.0.client(b.1, b.2)
            .cmd(Command::PutImmutableObject { digest: *d, bytes })
            .unwrap();
    }
    missing.len()
}

#[test]
fn scenario_g_efficient_exchange_and_independent_validation() {
    let ext = Extensions::install();
    let a = Harness::with_extensions(&ext);
    let ra = Identity::generate();
    let na = a.create_namespace(&ra);
    a.setup_kv(&ra, na, &ext);
    // Non-root actor on A so grant objects appear in provenance closures.
    let alice = a.register_key_principal(&ra, na);
    a.grant(
        &ra,
        na,
        &alice,
        &[
            "changepack.*",
            "execution.start",
            "observation.append",
            "verification.run",
            "kv.write",
            "namespace.read",
            "object.read",
        ],
    );
    let p: Vec<Digest> = (0..4)
        .map(|i| {
            a.promote_new(&alice, na, vec![kv_set(&format!("k{i}"), "v")])
                .1
        })
        .collect();
    let b0 = a
        .create_baseline(&ra, na, vec![p[0], p[1]], vec![])
        .unwrap();
    let b1 = a
        .create_baseline(&ra, na, vec![p[0], p[1], p[2]], vec![])
        .unwrap();
    let (b0_id, b1_id): (BaselineId, BaselineId) = (receipt_id(&b0), receipt_id(&b1));

    // Runtime B: independent store, keys and Namespace; kv NOT registered there.
    let b = Harness::new();
    let rb = Identity::generate();
    let nb = b.create_namespace(&rb);

    let c0 = a
        .client(&ra, na)
        .query(Query::GetBaselineClosure { baseline: b0_id })
        .unwrap();
    let c0 = digests(&c0["objects"]);
    assert!(c0.contains(&b0.result.digest.unwrap()));
    let sent0 = sync((&a, &ra, na), (&b, &rb, nb), &c0);
    assert_eq!(sent0, c0.len());
    let v = b
        .client(&rb, nb)
        .query(Query::ValidateBaseline {
            digest: b0.result.digest.unwrap(),
        })
        .unwrap();
    assert_eq!(v["valid"], true, "{v}");
    assert_eq!(v["validators"]["org.openaevc.reference.kv/*"], "skipped");

    // B later wants B1: only B1-specific objects travel.
    let c1 = digests(
        &a.client(&ra, na)
            .query(Query::GetBaselineClosure { baseline: b1_id })
            .unwrap()["objects"],
    );
    let sent1 = sync((&a, &ra, na), (&b, &rb, nb), &c1);
    let shared: BTreeSet<&Digest> = c0.iter().collect();
    assert_eq!(sent1, c1.iter().filter(|d| !shared.contains(d)).count());
    assert!(sent1 < c1.len());
    let v = b
        .client(&rb, nb)
        .query(Query::ValidateBaseline {
            digest: b1.result.digest.unwrap(),
        })
        .unwrap();
    assert_eq!(v["valid"], true, "{v}");

    // Imported identities and extensions are not trusted: no principal, grant or extension
    // registration appears on B.
    assert_eq!(
        b.client(&rb, nb).query(Query::ListExtensions {}).unwrap(),
        serde_json::json!([])
    );
    assert_eq!(
        b.client(&rb, nb)
            .query(Query::GetPrincipal {
                principal: alice.id()
            })
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    let grants_imported = c1
        .iter()
        .filter(|d| {
            fetch(&b, &rb, nb, **d)
                .windows(16)
                .any(|w| w == b"capability_grant")
        })
        .count();
    assert!(grants_imported > 0, "closure carried grant objects");
    let alice_on_b = alice.clone();
    let e = b
        .client(&alice_on_b, nb)
        .query(Query::GetNamespace {})
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unauthorized);
}

#[test]
fn closures_contain_only_what_the_root_requires() {
    let ext = Extensions::install();
    let h = Harness::with_extensions(&ext);
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    h.setup_kv(&root, ns, &ext);
    let p: Vec<Digest> = (0..4)
        .map(|i| {
            h.promote_new(&root, ns, vec![kv_set(&format!("k{i}"), "v")])
                .1
        })
        .collect();
    let b1: BaselineId = receipt_id(
        &h.create_baseline(&root, ns, vec![p[0], p[1], p[2]], vec![])
            .unwrap(),
    );
    let closure = digests(
        &h.client(&root, ns)
            .query(Query::GetBaselineClosure { baseline: b1 })
            .unwrap()["objects"],
    );
    assert!(!closure.contains(&p[3]));
    let pack3 = digests(
        &h.client(&root, ns)
            .query(Query::GetPackClosure { digest: p[3] })
            .unwrap()["objects"],
    );
    assert!(pack3
        .iter()
        .all(|d| !closure.contains(d) || shared_manifest(&h, &root, ns, *d)));
    let obj = h
        .client(&root, ns)
        .query(Query::GetObjectClosure { digest: p[0] })
        .unwrap();
    assert_eq!(obj["missing"], serde_json::json!([]));
}

fn shared_manifest(h: &Harness, who: &Identity, ns: NamespaceId, d: Digest) -> bool {
    // Objects shared between independent packs (extension manifests, grants, policies) may
    // appear in both closures; everything pack-specific must not.
    let kind = h
        .client(who, ns)
        .query(Query::GetObject { digest: d })
        .unwrap()["envelope"]["kind"]
        .clone();
    matches!(
        kind.as_str(),
        Some("extension_manifest" | "capability_grant" | "policy_document")
    )
}

#[test]
fn inventory_listing_and_missing_computation() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let pack = h.create_pack(&root, ns);
    h.seal(&root, ns, pack);
    let page1 = h
        .client(&root, ns)
        .query(Query::ListObjectDigests {
            kind: None,
            after: None,
            limit: Some(2),
        })
        .unwrap();
    assert_eq!(page1["objects"].as_array().unwrap().len(), 2);
    let next: Digest = page1["next"].as_str().unwrap().parse().unwrap();
    let page2 = h
        .client(&root, ns)
        .query(Query::ListObjectDigests {
            kind: None,
            after: Some(next),
            limit: Some(1000),
        })
        .unwrap();
    let all: Vec<Value> = page1["objects"]
        .as_array()
        .unwrap()
        .iter()
        .chain(page2["objects"].as_array().unwrap())
        .cloned()
        .collect();
    let unique: BTreeSet<String> = all
        .iter()
        .map(|o| o["digest"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(unique.len(), all.len());
    let cands = h
        .client(&root, ns)
        .query(Query::ListObjectDigests {
            kind: Some(ObjectKind::Candidate),
            after: None,
            limit: None,
        })
        .unwrap();
    assert_eq!(cands["objects"].as_array().unwrap().len(), 1);
    let known: Digest = cands["objects"][0]["digest"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let unknown = openaevc_crypto::sha256(b"unknown");
    let missing = h
        .client(&root, ns)
        .query(Query::ComputeMissingObjects {
            digests: vec![known, unknown],
        })
        .unwrap();
    assert_eq!(digests(&missing), vec![unknown]);
    let has = h
        .client(&root, ns)
        .query(Query::HasObject {
            digests: vec![known, unknown],
        })
        .unwrap();
    assert_eq!(has[known.to_string()], true);
    assert_eq!(has[unknown.to_string()], false);
}

#[test]
fn imports_are_verified_before_indexing() {
    let h = Harness::new();
    let root = Identity::generate();
    let ns = h.create_namespace(&root);
    let pack = h.create_pack(&root, ns);
    let cand = h.seal(&root, ns, pack);
    let other = Harness::new();
    let r2 = Identity::generate();
    let ns2 = other.create_namespace(&r2);
    let bytes = fetch(&h, &root, ns, cand);
    let c = other.client(&r2, ns2);
    // Digest mismatch.
    assert_eq!(
        c.cmd(Command::PutImmutableObject {
            digest: openaevc_crypto::sha256(b"x"),
            bytes: bytes.clone()
        })
        .unwrap_err()
        .code,
        ErrorCode::DigestMismatch
    );
    // Tampered bytes under their own digest: not canonical / not a valid object.
    let mut bad = bytes.clone();
    bad[0] = 0xa1;
    let e = c
        .cmd(Command::PutImmutableObject {
            digest: openaevc_crypto::sha256(&bad),
            bytes: bad,
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::CanonicalEncodingError);
    // Valid import; idempotent re-import.
    c.cmd(Command::PutImmutableObject {
        digest: cand,
        bytes: bytes.clone(),
    })
    .unwrap();
    c.cmd(Command::PutImmutableObject {
        digest: cand,
        bytes,
    })
    .unwrap();
    assert!(other
        .events(&r2, ns2)
        .iter()
        .any(|e| e["kind"] == "object.imported"));
    // Exchange requires authority.
    let alice = other.register_key_principal(&r2, ns2);
    let bytes = fetch(&h, &root, ns, cand);
    assert_eq!(
        other
            .client(&alice, ns2)
            .cmd(Command::PutImmutableObject {
                digest: cand,
                bytes
            })
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
}
