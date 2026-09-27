//! Storage conformance profile (PLAN §28.6): every `Store` implementation must pass
//! [`run_storage_profile`]. Panics on the first violated invariant.

use openaevc_core::{IdGeneratorExt, ImmutableObject, SequentialIds};
use openaevc_protocol::{
    Blob, Digest, ErrorCode, Event, NamespaceId, ObjectEnvelope, ObjectKind, PrincipalId,
    RequestId, Timestamp, PROTOCOL_VERSION,
};
use serde_json::json;

use crate::{AggregatePut, IndexEntry, RequestRecord, SnapshotRecord, Store, WriteBatch};

/// Deterministic test data for storage tests.
#[derive(Debug)]
pub struct Fixture {
    ids: SequentialIds,
    pub ns: NamespaceId,
    pub principal: PrincipalId,
    /// Canonical size well below a 600-byte inline threshold.
    pub small: ImmutableObject,
    /// Canonical size above a 600-byte inline threshold (lands in a CAS when one exists).
    pub large: ImmutableObject,
    pub second_large: ImmutableObject,
    pub second_small: ImmutableObject,
    pub agg_key: String,
}

fn blob(ns: NamespaceId, creator: PrincipalId, data: Vec<u8>) -> ImmutableObject {
    ImmutableObject::build(ObjectEnvelope {
        kind: ObjectKind::Blob,
        protocol_version: PROTOCOL_VERSION,
        namespace: ns,
        id: None,
        created_seq: 1,
        creator,
        body: serde_json::to_value(Blob {
            media_type: "application/octet-stream".into(),
            data,
        })
        .expect("blob"),
        signatures: vec![],
    })
    .expect("valid blob")
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

impl Fixture {
    pub fn new() -> Self {
        let ids = SequentialIds::new(99);
        let ns: NamespaceId = ids.next();
        let principal: PrincipalId = ids.next();
        Fixture {
            small: blob(ns, principal, b"s".to_vec()),
            large: blob(ns, principal, vec![7; 1000]),
            second_large: blob(ns, principal, vec![8; 1000]),
            second_small: blob(ns, principal, b"t".to_vec()),
            agg_key: format!("{ns}/thing"),
            ns,
            principal,
            ids,
        }
    }

    /// Builds a correctly chained event following `(seq-1, prev)`.
    pub fn event(&self, seq: u64, prev: Digest) -> Event {
        // IDs derive from the sequence so the same event can be rebuilt identically.
        let per_seq = SequentialIds::new(seq);
        let mut e = Event {
            id: per_seq.next(),
            namespace: self.ns,
            sequence: seq,
            runtime_instance: per_seq.next(),
            request_id: None,
            actor: Some(self.principal),
            kind: "test.event".into(),
            body: json!({"n": seq}),
            subjects: vec![],
            timestamp: Timestamp::from_unix_nanos(i128::from(seq)),
            previous_hash: prev,
            hash: Digest::ZERO,
        };
        e.hash = openaevc_core::events::event_hash(&e).expect("hash");
        e
    }

    fn chain(&self, from_seq: u64, prev: Digest, n: u64) -> Vec<Event> {
        let mut out = Vec::new();
        let mut prev = prev;
        for s in from_seq..from_seq + n {
            let e = self.event(s, prev);
            prev = e.hash;
            out.push(e);
        }
        out
    }

    fn index(&self, o: &ImmutableObject) -> IndexEntry {
        IndexEntry {
            namespace: self.ns,
            digest: o.digest(),
            kind: o.kind(),
        }
    }

    /// First batch: aggregate v1, both objects indexed, `n` events.
    pub fn batch_with_events(&self, n: u64) -> WriteBatch {
        WriteBatch {
            aggregates: vec![AggregatePut {
                kind: "test".into(),
                key: self.agg_key.clone(),
                expected_version: 0,
                body: json!({"v": 1}),
            }],
            objects: vec![self.small.clone(), self.large.clone()],
            index: vec![self.index(&self.small), self.index(&self.large)],
            events: self.chain(1, Digest::ZERO, n),
            ..Default::default()
        }
    }

    /// Second batch applied on top of `batch_with_events(1)`.
    pub fn second_batch(&self) -> WriteBatch {
        let first = self.event(1, Digest::ZERO);
        WriteBatch {
            aggregates: vec![AggregatePut {
                kind: "test".into(),
                key: self.agg_key.clone(),
                expected_version: 1,
                body: json!({"v": 2}),
            }],
            objects: vec![self.second_large.clone(), self.second_small.clone()],
            index: vec![
                self.index(&self.second_large),
                self.index(&self.second_small),
            ],
            events: vec![self.event(2, first.hash)],
            ..Default::default()
        }
    }

    fn request(&self, nonce: &str) -> RequestRecord {
        RequestRecord {
            principal: self.principal,
            request_id: self.ids.next::<RequestId>(),
            nonce: nonce.into(),
            envelope_digest: self.small.digest(),
            receipt: None,
            issued_at: Timestamp::from_unix_nanos(1_000),
        }
    }
}

fn expect_err<T: std::fmt::Debug>(r: crate::Result<T>, what: &str) -> ErrorCode {
    match r {
        Ok(v) => panic!("{what}: expected an error, got {v:?}"),
        Err(e) => e.code,
    }
}

/// Runs every storage invariant against fresh stores produced by `make`.
pub fn run_storage_profile(make: &dyn Fn() -> Box<dyn Store>) {
    // Empty store.
    let s = make();
    let fx = Fixture::new();
    assert!(s.journal_head(&fx.ns).unwrap().is_none());
    assert!(s.get_aggregate("test", &fx.agg_key).unwrap().is_none());
    assert!(s.namespaces().unwrap().is_empty());

    // Batch visibility.
    s.commit(fx.batch_with_events(3)).unwrap();
    let head = s.journal_head(&fx.ns).unwrap().unwrap();
    assert_eq!(head.0, 3);
    assert_eq!(
        s.get_aggregate("test", &fx.agg_key)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        s.get_object(&fx.large.digest()).unwrap().unwrap().bytes(),
        fx.large.bytes()
    );
    assert!(s.is_indexed(&fx.ns, &fx.small.digest()).unwrap());
    assert_eq!(s.namespaces().unwrap(), vec![fx.ns]);
    let events = s.read_events(&fx.ns, 1, 10).unwrap();
    assert_eq!(
        events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(s.read_events(&fx.ns, 0, 1).unwrap().len(), 1);
    assert!(s.verify_integrity().unwrap().ok());

    // Atomicity: a stale aggregate version rejects the whole batch, events included.
    let mut stale = fx.second_batch();
    stale.aggregates[0].expected_version = 0;
    stale.events = vec![fx.event(4, head.1)];
    assert_eq!(
        expect_err(s.commit(stale), "stale version"),
        ErrorCode::Conflict
    );
    assert_eq!(s.journal_head(&fx.ns).unwrap().unwrap().0, 3);
    assert!(!s.has_object(&fx.second_large.digest()).unwrap());

    // Journal continuity: gaps, relinks and tampered hashes are rejected; nothing applies.
    let gap = WriteBatch {
        events: vec![fx.event(5, head.1)],
        aggregates: vec![AggregatePut {
            kind: "test".into(),
            key: "other".into(),
            expected_version: 0,
            body: json!(1),
        }],
        ..Default::default()
    };
    expect_err(s.commit(gap), "journal gap");
    assert!(s.get_aggregate("test", "other").unwrap().is_none());
    let relink = WriteBatch {
        events: vec![fx.event(4, Digest::ZERO)],
        ..Default::default()
    };
    expect_err(s.commit(relink), "journal relink");
    let mut forged = fx.event(4, head.1);
    forged.body = json!({"forged": true});
    expect_err(
        s.commit(WriteBatch {
            events: vec![forged],
            ..Default::default()
        }),
        "tampered event",
    );
    assert_eq!(s.journal_head(&fx.ns).unwrap().unwrap(), head);

    // Referential integrity of the index.
    let dangling = WriteBatch {
        index: vec![IndexEntry {
            namespace: fx.ns,
            digest: fx.second_large.digest(),
            kind: ObjectKind::Blob,
        }],
        ..Default::default()
    };
    expect_err(s.commit(dangling), "dangling index");

    // Idempotent object writes; logical visibility is per Namespace.
    let other_ns: NamespaceId = fx.ids.next();
    s.commit(WriteBatch {
        objects: vec![fx.large.clone()],
        index: vec![IndexEntry {
            namespace: other_ns,
            digest: fx.large.digest(),
            kind: ObjectKind::Blob,
        }],
        ..Default::default()
    })
    .unwrap();
    assert!(s.is_indexed(&other_ns, &fx.large.digest()).unwrap());
    assert!(!s.is_indexed(&other_ns, &fx.small.digest()).unwrap());

    // Index listing: order, kind filter, pagination.
    let all = s.list_index(&fx.ns, None, None, 10).unwrap();
    assert_eq!(all.len(), 2);
    assert!(all[0].0 < all[1].0);
    assert_eq!(
        s.list_index(&fx.ns, None, Some(all[0].0), 10).unwrap(),
        vec![all[1]]
    );
    assert!(s
        .list_index(&fx.ns, Some(ObjectKind::Baseline), None, 10)
        .unwrap()
        .is_empty());
    assert_eq!(
        s.list_index(&fx.ns, Some(ObjectKind::Blob), None, 1)
            .unwrap()
            .len(),
        1
    );

    // Requests: unique request IDs and nonces per principal; pruning.
    let r1 = fx.request("n1");
    s.commit(WriteBatch {
        requests: vec![r1.clone()],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        s.get_request(&fx.principal, &r1.request_id)
            .unwrap()
            .unwrap(),
        r1
    );
    assert!(s.nonce_used(&fx.principal, "n1").unwrap());
    let mut dup_id = fx.request("n2");
    dup_id.request_id = r1.request_id;
    assert_eq!(
        expect_err(
            s.commit(WriteBatch {
                requests: vec![dup_id],
                ..Default::default()
            }),
            "dup request"
        ),
        ErrorCode::ReplayDetected
    );
    assert_eq!(
        expect_err(
            s.commit(WriteBatch {
                requests: vec![fx.request("n1")],
                ..Default::default()
            }),
            "dup nonce"
        ),
        ErrorCode::ReplayDetected
    );
    assert_eq!(
        s.prune_requests(Timestamp::from_unix_nanos(2_000)).unwrap(),
        1
    );
    assert!(!s.nonce_used(&fx.principal, "n1").unwrap());

    // Aggregate listing by prefix and optimistic updates.
    s.commit(fx.second_batch_after(head)).unwrap();
    assert_eq!(
        s.get_aggregate("test", &fx.agg_key).unwrap().unwrap().body,
        json!({"v": 2})
    );
    let listed = s.list_aggregates("test", &format!("{}/", fx.ns)).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(s.list_aggregates("test", "zzz").unwrap().is_empty());

    // Snapshots.
    let (seq, hash) = s.journal_head(&fx.ns).unwrap().unwrap();
    let snap = SnapshotRecord {
        namespace: fx.ns,
        sequence: seq,
        event_hash: hash,
        projection_digest: fx.small.digest(),
    };
    s.commit(WriteBatch {
        snapshots: vec![snap.clone()],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(s.latest_snapshot(&fx.ns).unwrap().unwrap(), snap);
    assert!(s.verify_integrity().unwrap().ok());
}

impl Fixture {
    fn second_batch_after(&self, head: (u64, Digest)) -> WriteBatch {
        let mut b = self.second_batch();
        b.events = vec![self.event(head.0 + 1, head.1)];
        b
    }
}
