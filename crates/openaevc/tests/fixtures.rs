//! fixtures/authority/matrix.json: the authorization matrix every implementation must agree on.

use std::collections::HashSet;
use std::path::PathBuf;

use openaevc::authority::{authorize, AuthorityView, Request};
use openaevc::protocol::*;
use serde_json::Value;

struct View {
    ns: NamespaceId,
    roots: Vec<PrincipalId>,
    principals: Vec<Principal>,
    grants: Vec<(Digest, SignedGrant)>,
    revoked: HashSet<GrantId>,
}

impl AuthorityView for View {
    fn namespace(&self) -> NamespaceId {
        self.ns
    }
    fn roots(&self) -> &[PrincipalId] {
        &self.roots
    }
    fn principal(&self, id: &PrincipalId) -> Option<Principal> {
        self.principals.iter().find(|p| &p.id == id).cloned()
    }
    fn grant(&self, d: &Digest) -> Option<SignedGrant> {
        self.grants
            .iter()
            .find(|(x, _)| x == d)
            .map(|(_, g)| g.clone())
    }
    fn grants_for_subject(&self, s: &PrincipalId) -> Vec<(Digest, SignedGrant)> {
        self.grants
            .iter()
            .filter(|(_, g)| &g.body.subject == s)
            .cloned()
            .collect()
    }
    fn is_revoked(&self, id: &GrantId) -> bool {
        self.revoked.contains(id)
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn authorization_matrix() {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/authority/matrix.json");
    let f: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let ns: NamespaceId = serde_json::from_value(f["namespace"].clone()).unwrap();
    let now: Timestamp = serde_json::from_value(f["now"].clone()).unwrap();
    let principals = f["principals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| Principal {
            id: serde_json::from_value(p["id"].clone()).unwrap(),
            namespace: ns,
            kind: PrincipalKind::Key,
            public_key: Some(serde_json::from_value(p["public_key"].clone()).unwrap()),
            linked_to: None,
            attributes: Default::default(),
            registered_at: Timestamp::UNIX_EPOCH,
        })
        .collect();
    let grants: Vec<(Digest, SignedGrant)> = f["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| {
            let grant: SignedGrant = serde_json::from_value(g["grant"].clone()).unwrap();
            let d: Digest = serde_json::from_value(g["digest"].clone()).unwrap();
            // The grant digest is the capability_grant object's digest, not the grant value's.
            let bytes = hex(g["object_cbor_hex"].as_str().unwrap());
            assert_eq!(openaevc::crypto::sha256(&bytes), d);
            let env: ObjectEnvelope = openaevc::canonical::from_canonical(&bytes).unwrap();
            assert_eq!(env.kind, ObjectKind::CapabilityGrant);
            assert_eq!(
                serde_json::from_value::<SignedGrant>(env.body).unwrap(),
                grant
            );
            (d, grant)
        })
        .collect();
    let mut view = View {
        ns,
        roots: serde_json::from_value(f["roots"].clone()).unwrap(),
        principals,
        grants,
        revoked: HashSet::new(),
    };
    for c in f["cases"].as_array().unwrap() {
        view.revoked =
            serde_json::from_value(c.get("revoked").cloned().unwrap_or(Value::Array(vec![])))
                .unwrap();
        let principal: PrincipalId = serde_json::from_value(c["principal"].clone()).unwrap();
        let resource: Option<ResourceRef> = c
            .get("resource")
            .map(|r| serde_json::from_value(r.clone()).unwrap());
        let got = authorize(
            &view,
            now,
            &Request {
                principal,
                action: c["action"].as_str().unwrap(),
                resource: resource.as_ref(),
            },
        );
        match (c["expect"].as_str().unwrap(), got) {
            ("ALLOW", Ok(a)) => {
                let chain: Vec<Digest> = serde_json::from_value(c["chain"].clone()).unwrap();
                assert_eq!(a.grants, chain, "{}", c["name"]);
            }
            (code, Err(e)) => assert_eq!(e.code.as_str(), code, "{}", c["name"]),
            (exp, got) => panic!("{}: expected {exp}, got {got:?}", c["name"]),
        }
    }
}
