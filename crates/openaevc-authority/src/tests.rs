use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use openaevc_core::{IdGeneratorExt, SequentialIds};
use openaevc_crypto::{Signer, SigningKey};
use openaevc_protocol::*;

use super::*;

struct World {
    ids: SequentialIds,
    ns: NamespaceId,
    now: Timestamp,
    roots: Vec<PrincipalId>,
    principals: HashMap<PrincipalId, Principal>,
    keys: HashMap<PrincipalId, SigningKey>,
    grants: HashMap<Digest, SignedGrant>,
    revoked: HashSet<GrantId>,
}

impl AuthorityView for World {
    fn namespace(&self) -> NamespaceId {
        self.ns
    }
    fn roots(&self) -> &[PrincipalId] {
        &self.roots
    }
    fn principal(&self, id: &PrincipalId) -> Option<Principal> {
        self.principals.get(id).cloned()
    }
    fn grant(&self, digest: &Digest) -> Option<SignedGrant> {
        self.grants.get(digest).cloned()
    }
    fn grants_for_subject(&self, subject: &PrincipalId) -> Vec<(Digest, SignedGrant)> {
        let mut v: Vec<_> = self
            .grants
            .iter()
            .filter(|(_, g)| &g.body.subject == subject)
            .map(|(d, g)| (*d, g.clone()))
            .collect();
        v.sort_by_key(|(d, _)| *d);
        v
    }
    fn is_revoked(&self, id: &GrantId) -> bool {
        self.revoked.contains(id)
    }
}

fn t(s: i64) -> Timestamp {
    Timestamp::from_unix_nanos(i128::from(s) * 1_000_000_000)
}

impl World {
    fn new() -> Self {
        let ids = SequentialIds::new(42);
        let mut w = World {
            ns: ids.next(),
            ids,
            now: t(1_000),
            roots: vec![],
            principals: HashMap::new(),
            keys: HashMap::new(),
            grants: HashMap::new(),
            revoked: HashSet::new(),
        };
        let root = w.key_principal();
        w.roots.push(root);
        w
    }

    fn key_principal(&mut self) -> PrincipalId {
        let id: PrincipalId = self.ids.next();
        let key = SigningKey::generate();
        self.principals.insert(
            id,
            Principal {
                id,
                namespace: self.ns,
                kind: PrincipalKind::Key,
                public_key: Some(key.public_key()),
                linked_to: None,
                attributes: BTreeMap::new(),
                registered_at: t(0),
            },
        );
        self.keys.insert(id, key);
        id
    }

    fn root(&self) -> PrincipalId {
        self.roots[0]
    }

    fn body(&self, issuer: PrincipalId, subject: PrincipalId, actions: &[&str]) -> GrantBody {
        GrantBody {
            id: self.ids.next(),
            namespace: self.ns,
            issuer,
            subject,
            actions: actions
                .iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<_>>(),
            resources: vec![],
            constraints: BTreeMap::new(),
            not_before: t(0),
            expires_at: t(10_000),
            delegation_depth: 2,
            parent: None,
            nonce: "n".into(),
        }
    }

    fn sign(&self, body: GrantBody) -> SignedGrant {
        let key = &self.keys[&body.issuer];
        sign_grant(body, key).unwrap()
    }

    fn add(&mut self, g: SignedGrant) -> Digest {
        let d = openaevc_crypto::digest_of(&g).unwrap();
        self.grants.insert(d, g);
        d
    }

    fn authz(&self, who: PrincipalId, action: &str) -> Result<Authorization, ProtocolError> {
        authorize(
            self,
            self.now,
            &Request {
                principal: who,
                action,
                resource: None,
            },
        )
    }

    fn authz_res(
        &self,
        who: PrincipalId,
        action: &str,
        kind: &str,
        loc: &str,
    ) -> Result<Authorization, ProtocolError> {
        let r = ResourceRef {
            kind: kind.into(),
            locator: loc.into(),
            version: None,
            extension: "org.x.y".into(),
        };
        authorize(
            self,
            self.now,
            &Request {
                principal: who,
                action,
                resource: Some(&r),
            },
        )
    }
}

#[test]
fn default_deny() {
    let mut w = World::new();
    let alice = w.key_principal();
    let e = w.authz(alice, "changepack.create").unwrap_err();
    assert_eq!(e.code, ErrorCode::Forbidden);
    assert_eq!(e.missing_action.as_deref(), Some("changepack.create"));
}

#[test]
fn root_principals_hold_namespace_authority() {
    let w = World::new();
    let a = w.authz(w.root(), "changepack.promote").unwrap();
    assert!(a.root);
    assert!(a.grants.is_empty());
}

#[test]
fn root_issued_grant_allows_listed_actions_only() {
    let mut w = World::new();
    let alice = w.key_principal();
    let g = w.sign(w.body(w.root(), alice, &["changepack.create", "execution.*"]));
    let d = w.add(g);
    assert_eq!(w.authz(alice, "changepack.create").unwrap().grants, vec![d]);
    assert!(w.authz(alice, "execution.start").is_ok());
    assert_eq!(
        w.authz(alice, "changepack.promote").unwrap_err().code,
        ErrorCode::Forbidden
    );
}

#[test]
fn forged_signature_rejected() {
    let mut w = World::new();
    let alice = w.key_principal();
    let mut g = w.sign(w.body(w.root(), alice, &["*"]));
    g.body.actions.insert("grant.issue".into());
    w.add(g.clone());
    assert_eq!(
        w.authz(alice, "changepack.create").unwrap_err().code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        validate_grant(&w, w.now, &g).unwrap_err().code,
        ErrorCode::Unauthorized
    );
}

#[test]
fn grant_signed_by_non_issuer_key_rejected() {
    let mut w = World::new();
    let alice = w.key_principal();
    let body = w.body(w.root(), alice, &["*"]);
    let g = sign_grant(body, &w.keys[&alice]).unwrap();
    assert_eq!(
        validate_grant(&w, w.now, &g).unwrap_err().code,
        ErrorCode::Unauthorized
    );
}

#[test]
fn expired_and_not_yet_valid_grants() {
    let mut w = World::new();
    let alice = w.key_principal();
    let mut b = w.body(w.root(), alice, &["changepack.create"]);
    b.expires_at = t(500);
    let g = w.sign(b);
    w.add(g);
    assert_eq!(
        w.authz(alice, "changepack.create").unwrap_err().code,
        ErrorCode::CapabilityExpired
    );
    let bob = w.key_principal();
    let mut b = w.body(w.root(), bob, &["changepack.create"]);
    b.not_before = t(2_000);
    let g = w.sign(b);
    w.add(g);
    assert_eq!(
        w.authz(bob, "changepack.create").unwrap_err().code,
        ErrorCode::Forbidden
    );
}

#[test]
fn non_root_issuer_needs_parent() {
    let mut w = World::new();
    let alice = w.key_principal();
    let bob = w.key_principal();
    let g = w.sign(w.body(alice, bob, &["changepack.create"]));
    w.add(g.clone());
    assert_eq!(
        w.authz(bob, "changepack.create").unwrap_err().code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        validate_grant(&w, w.now, &g).unwrap_err().code,
        ErrorCode::Forbidden
    );
}

fn delegation(w: &mut World) -> (PrincipalId, PrincipalId, Digest, GrantBody) {
    let alice = w.key_principal();
    let bob = w.key_principal();
    let mut pb = w.body(w.root(), alice, &["changepack.*", "execution.start"]);
    pb.resources = vec![ResourceSelector {
        kind: "kv.*".into(),
        locator_prefix: Some("app/".into()),
    }];
    let parent = w.sign(pb);
    let pd = w.add(parent);
    let mut cb = w.body(alice, bob, &["changepack.create"]);
    cb.parent = Some(pd);
    cb.delegation_depth = 1;
    cb.expires_at = t(5_000);
    cb.resources = vec![ResourceSelector {
        kind: "kv.entry".into(),
        locator_prefix: Some("app/x/".into()),
    }];
    (alice, bob, pd, cb)
}

#[test]
fn valid_delegation_chain() {
    let mut w = World::new();
    let (_, bob, pd, cb) = delegation(&mut w);
    let child = w.sign(cb);
    let cd = w.add(child);
    let a = w
        .authz_res(bob, "changepack.create", "kv.entry", "app/x/1")
        .unwrap();
    assert_eq!(a.grants, vec![cd, pd]);
    assert_eq!(
        w.authz_res(bob, "changepack.create", "kv.entry", "app/y/1")
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
}

#[test]
fn over_delegation_rejected() {
    for mutate in [
        |b: &mut GrantBody| {
            b.actions.insert("changepack.promote.extra".into());
            b.actions.insert("grant.issue".into());
        },
        |b: &mut GrantBody| b.delegation_depth = 2,
        |b: &mut GrantBody| b.expires_at = t(20_000),
        |b: &mut GrantBody| b.resources = vec![],
        |b: &mut GrantBody| {
            b.resources = vec![ResourceSelector {
                kind: "*".into(),
                locator_prefix: None,
            }]
        },
        |b: &mut GrantBody| {
            b.resources = vec![ResourceSelector {
                kind: "kv.entry".into(),
                locator_prefix: Some("other/".into()),
            }]
        },
        |b: &mut GrantBody| b.not_before = t(-10),
    ] {
        let mut w = World::new();
        let (_, bob, _, mut cb) = delegation(&mut w);
        mutate(&mut cb);
        let child = w.sign(cb);
        w.add(child.clone());
        assert!(validate_grant(&w, w.now, &child).is_err());
        assert!(w
            .authz_res(bob, "changepack.create", "kv.entry", "app/x/1")
            .is_err());
    }
}

#[test]
fn zero_depth_parent_cannot_delegate() {
    let mut w = World::new();
    let alice = w.key_principal();
    let bob = w.key_principal();
    let mut pb = w.body(w.root(), alice, &["*"]);
    pb.delegation_depth = 0;
    let pd = {
        let g = w.sign(pb);
        w.add(g)
    };
    let mut cb = w.body(alice, bob, &["changepack.create"]);
    cb.parent = Some(pd);
    cb.delegation_depth = 0;
    let child = w.sign(cb);
    assert!(validate_grant(&w, w.now, &child).is_err());
}

#[test]
fn parent_subject_must_be_child_issuer() {
    let mut w = World::new();
    let (_, bob, pd, _) = delegation(&mut w);
    let mallory = w.key_principal();
    let mut cb = w.body(mallory, bob, &["changepack.create"]);
    cb.parent = Some(pd);
    cb.delegation_depth = 0;
    let child = w.sign(cb);
    assert!(validate_grant(&w, w.now, &child).is_err());
}

#[test]
fn revoking_parent_invalidates_descendants() {
    let mut w = World::new();
    let (_, bob, pd, cb) = delegation(&mut w);
    let child = w.sign(cb);
    w.add(child);
    assert!(w
        .authz_res(bob, "changepack.create", "kv.entry", "app/x/1")
        .is_ok());
    let parent_id = w.grants[&pd].body.id;
    w.revoked.insert(parent_id);
    assert_eq!(
        w.authz_res(bob, "changepack.create", "kv.entry", "app/x/1")
            .unwrap_err()
            .code,
        ErrorCode::CapabilityRevoked
    );
}

#[test]
fn wrong_namespace_rejected() {
    let mut w = World::new();
    let alice = w.key_principal();
    let mut b = w.body(w.root(), alice, &["*"]);
    b.namespace = w.ids.next();
    let g = w.sign(b);
    w.add(g.clone());
    assert!(validate_grant(&w, w.now, &g).is_err());
    assert!(w.authz(alice, "changepack.create").is_err());
}

#[test]
fn unknown_issuer_fails_closed() {
    let mut w = World::new();
    let alice = w.key_principal();
    let g = w.sign(w.body(w.root(), alice, &["*"]));
    w.principals.remove(&w.root());
    assert!(validate_grant(&w, w.now, &g).is_err());
}

#[test]
fn action_patterns() {
    assert!(action_matches("*", "changepack.create"));
    assert!(action_matches("changepack.*", "changepack.create"));
    assert!(!action_matches("changepack.*", "changepackx.create"));
    assert!(!action_matches("changepack.create", "changepack.seal"));
    assert!(action_covers("changepack.*", "changepack.create"));
    assert!(action_covers("changepack.*", "changepack.x.*"));
    assert!(!action_covers("changepack.create", "changepack.*"));
    assert!(action_covers("*", "*"));
    assert!(!action_covers("changepack.*", "*"));
}

#[test]
fn selector_matching_and_coverage() {
    let r = ResourceRef {
        kind: "kv.entry".into(),
        locator: "app/a".into(),
        version: None,
        extension: "org.x.y".into(),
    };
    let s = |k: &str, p: Option<&str>| ResourceSelector {
        kind: k.into(),
        locator_prefix: p.map(Into::into),
    };
    assert!(selector_matches(&s("kv.entry", Some("app/")), &r));
    assert!(selector_matches(&s("kv.*", None), &r));
    assert!(selector_matches(&s("*", None), &r));
    assert!(!selector_matches(&s("kv.entry", Some("other/")), &r));
    assert!(!selector_matches(&s("dataset.table", None), &r));
    assert!(selector_covers(
        &s("kv.*", Some("app/")),
        &s("kv.entry", Some("app/x"))
    ));
    assert!(!selector_covers(
        &s("kv.entry", Some("app/x")),
        &s("kv.entry", Some("app/"))
    ));
}

#[test]
fn actor_is_authorized_by_its_own_grants() {
    let mut w = World::new();
    let alice = w.key_principal();
    let actor: PrincipalId = w.ids.next();
    w.principals.insert(
        actor,
        Principal {
            id: actor,
            namespace: w.ns,
            kind: PrincipalKind::Actor,
            public_key: None,
            linked_to: Some(alice),
            attributes: BTreeMap::from([("org.example.kind".into(), "agent".into())]),
            registered_at: t(0),
        },
    );
    let g = w.sign(w.body(w.root(), actor, &["execution.start"]));
    w.add(g);
    assert!(w.authz(actor, "execution.start").is_ok());
    assert!(w.authz(alice, "execution.start").is_err());
    assert!(resolve_caller(&w, alice, Some(actor)).is_ok());
    let bob = w.key_principal();
    assert_eq!(
        resolve_caller(&w, bob, Some(actor)).unwrap_err().code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        resolve_caller(&w, actor, None).unwrap_err().code,
        ErrorCode::Unauthorized
    );
}

#[test]
fn freshness_window() {
    let now = t(1_000);
    assert!(check_freshness(now, t(1_000 - 200), None, 300_000).is_ok());
    assert_eq!(
        check_freshness(now, t(1_000 - 400), None, 300_000)
            .unwrap_err()
            .code,
        ErrorCode::ReplayDetected
    );
    assert_eq!(
        check_freshness(now, t(1_000 + 400), None, 300_000)
            .unwrap_err()
            .code,
        ErrorCode::ReplayDetected
    );
    assert!(check_freshness(now, t(1_000), Some(t(999)), 300_000).is_err());
}

mod props {
    use super::*;
    use proptest::prelude::*;

    const ACTIONS: [&str; 6] = [
        "changepack.create",
        "changepack.seal",
        "execution.start",
        "evidence.append",
        "kv.write",
        "kv.read",
    ];

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test]
        fn delegation_is_valid_iff_subset(parent_mask in 1u8..64, child_mask in 1u8..64) {
            let pick = |m: u8| ACTIONS.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, a)| *a).collect::<Vec<_>>();
            let mut w = World::new();
            let alice = w.key_principal();
            let bob = w.key_principal();
            let parent = w.sign(w.body(w.root(), alice, &pick(parent_mask)));
            let pd = w.add(parent);
            let mut cb = w.body(alice, bob, &pick(child_mask));
            cb.parent = Some(pd);
            cb.delegation_depth = 1;
            let child = w.sign(cb);
            let is_subset = child_mask & !parent_mask == 0;
            prop_assert_eq!(validate_grant(&w, w.now, &child).is_ok(), is_subset);
        }

        #[test]
        fn action_cover_implies_match(a in "[a-c]{1,2}(\\.[a-c]{1,2}){0,2}", b in "[a-c]{1,2}(\\.[a-c]{1,2}){0,2}") {
            let pattern = format!("{a}.*");
            if action_covers(&pattern, &b) {
                prop_assert!(action_matches(&pattern, &b));
            }
        }
    }
}
