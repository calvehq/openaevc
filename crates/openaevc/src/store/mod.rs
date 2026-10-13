//! OpenAEVC persistence.
//!
//! The runtime depends only on the [`Store`] trait. Every state transition is one
//! [`WriteBatch`] committed atomically: aggregate updates (optimistically versioned), new
//! immutable objects, Namespace index entries, journal events (hash-chain checked), request
//! records (replay protection) and snapshots. Either all of a batch becomes visible or none of
//! it does.
//!
//! Two reference backends are provided: [`MemoryStore`] (tests/conformance) and
//! [`SqliteStore`] (SQLite WAL + filesystem CAS). The storage layout and SQLite schema are
//! implementation details, never an integration API. Alternate backends must pass
//! [`conformance::run_storage_profile`].
#![forbid(unsafe_code)]

pub mod conformance;
mod memory;
mod sqlite;

use std::collections::{HashMap, HashSet};

use crate::core::ImmutableObject;
use crate::protocol::{
    err, Digest, ErrorCode, Event, NamespaceId, ObjectKind, PrincipalId, ProtocolError, RequestId,
    Sequence, Timestamp,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub use memory::MemoryStore;
pub use sqlite::{Durability, Failpoint, SqliteOptions, SqliteStore, SCHEMA_VERSION};

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// A versioned mutable aggregate (ChangePack, Execution, registry entries...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateRecord {
    pub version: u64,
    pub body: Value,
}

impl AggregateRecord {
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.body.clone())
            .map_err(|e| err::integrity(format!("stored aggregate is malformed: {e}")))
    }
}

/// Create-or-update of an aggregate. `expected_version` 0 means "must not exist yet"; the new
/// version is `expected_version + 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatePut {
    pub kind: String,
    pub key: String,
    pub expected_version: u64,
    pub body: Value,
}

/// Logical visibility of an immutable object inside a Namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    pub namespace: NamespaceId,
    pub digest: Digest,
    pub kind: ObjectKind,
}

/// Replay-protection record of an admitted command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRecord {
    pub principal: PrincipalId,
    pub request_id: RequestId,
    pub nonce: String,
    pub envelope_digest: Digest,
    pub receipt: Option<Digest>,
    pub issued_at: Timestamp,
}

/// Derived recovery accelerator: journal position plus a digest of the aggregate projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRecord {
    pub namespace: NamespaceId,
    pub sequence: Sequence,
    pub event_hash: Digest,
    pub projection_digest: Digest,
}

#[derive(Debug, Clone, Default)]
pub struct WriteBatch {
    pub aggregates: Vec<AggregatePut>,
    pub objects: Vec<ImmutableObject>,
    pub index: Vec<IndexEntry>,
    pub events: Vec<Event>,
    pub requests: Vec<RequestRecord>,
    pub snapshots: Vec<SnapshotRecord>,
}

impl WriteBatch {
    pub fn is_empty(&self) -> bool {
        self.aggregates.is_empty()
            && self.objects.is_empty()
            && self.index.is_empty()
            && self.events.is_empty()
            && self.requests.is_empty()
            && self.snapshots.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntegrityReport {
    pub problems: Vec<String>,
    pub namespaces: usize,
    pub events: u64,
    pub objects: u64,
}

impl IntegrityReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    pub scanned: usize,
    pub removed: usize,
}

pub trait Store: Send + Sync {
    fn get_aggregate(&self, kind: &str, key: &str) -> Result<Option<AggregateRecord>>;
    /// Aggregates of `kind` whose key starts with `prefix`, ordered by key.
    fn list_aggregates(&self, kind: &str, prefix: &str) -> Result<Vec<(String, AggregateRecord)>>;
    /// Loads and digest-verifies an object (`STORAGE_INTEGRITY_ERROR` on mismatch).
    fn get_object(&self, digest: &Digest) -> Result<Option<ImmutableObject>>;
    fn has_object(&self, digest: &Digest) -> Result<bool>;
    fn is_indexed(&self, namespace: &NamespaceId, digest: &Digest) -> Result<bool>;
    /// Namespace index in digest order after `after`, optionally filtered by kind.
    fn list_index(
        &self,
        namespace: &NamespaceId,
        kind: Option<ObjectKind>,
        after: Option<Digest>,
        limit: usize,
    ) -> Result<Vec<(Digest, ObjectKind)>>;
    fn journal_head(&self, namespace: &NamespaceId) -> Result<Option<(Sequence, Digest)>>;
    /// Events with sequence > `after`, ascending, at most `limit`.
    fn read_events(
        &self,
        namespace: &NamespaceId,
        after: Sequence,
        limit: usize,
    ) -> Result<Vec<Event>>;
    fn get_request(
        &self,
        principal: &PrincipalId,
        request_id: &RequestId,
    ) -> Result<Option<RequestRecord>>;
    fn nonce_used(&self, principal: &PrincipalId, nonce: &str) -> Result<bool>;
    /// Drops request records issued before `before` (outside the replay window).
    fn prune_requests(&self, before: Timestamp) -> Result<usize>;
    fn latest_snapshot(&self, namespace: &NamespaceId) -> Result<Option<SnapshotRecord>>;
    fn namespaces(&self) -> Result<Vec<NamespaceId>>;
    /// Atomically applies a batch after validating it (versions, journal chain, references, replay).
    fn commit(&self, batch: WriteBatch) -> Result<()>;
    /// Full offline integrity scan: journal chains, object digests, index references,
    /// snapshots.
    fn verify_integrity(&self) -> Result<IntegrityReport>;
}

/// Current-state lookups used to validate a batch.
pub(crate) trait BatchContext {
    fn version(&self, kind: &str, key: &str) -> Result<u64>;
    fn head(&self, ns: &NamespaceId) -> Result<Option<(Sequence, Digest)>>;
    fn has_object(&self, d: &Digest) -> Result<bool>;
    fn has_request(&self, p: &PrincipalId, r: &RequestId) -> Result<bool>;
    fn nonce_used(&self, p: &PrincipalId, n: &str) -> Result<bool>;
}

fn conflict(msg: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorCode::Conflict, msg)
}

/// Validation shared by all backends. Guarantees journal continuity, event hash integrity,
/// optimistic aggregate versions, request/nonce uniqueness and index referential integrity.
pub(crate) fn validate_batch(b: &WriteBatch, cx: &dyn BatchContext) -> Result<()> {
    let mut seen = HashSet::new();
    for a in &b.aggregates {
        if !seen.insert((a.kind.as_str(), a.key.as_str())) {
            return Err(err::internal(format!(
                "batch updates aggregate {}/{} twice",
                a.kind, a.key
            )));
        }
        let current = cx.version(&a.kind, &a.key)?;
        if current != a.expected_version {
            return Err(conflict(format!(
                "aggregate {}/{} changed concurrently (version {current}, expected {})",
                a.kind, a.key, a.expected_version
            )));
        }
    }
    let mut heads: HashMap<NamespaceId, (Sequence, Digest)> = HashMap::new();
    for e in &b.events {
        let (seq, hash) = match heads.get(&e.namespace) {
            Some(h) => *h,
            None => cx.head(&e.namespace)?.unwrap_or((0, Digest::ZERO)),
        };
        if e.sequence != seq + 1 || e.previous_hash != hash {
            return Err(conflict(format!(
                "journal of {} moved (expected sequence {})",
                e.namespace,
                seq + 1
            )));
        }
        if crate::core::events::event_hash(e)? != e.hash {
            return Err(err::integrity(format!(
                "event {} hash does not match its content",
                e.sequence
            )));
        }
        heads.insert(e.namespace, (e.sequence, e.hash));
    }
    let batch_objects: HashSet<Digest> = b.objects.iter().map(ImmutableObject::digest).collect();
    for i in &b.index {
        if !batch_objects.contains(&i.digest) && !cx.has_object(&i.digest)? {
            return Err(err::integrity(format!(
                "index entry references missing object {}",
                i.digest
            )));
        }
    }
    let mut reqs = HashSet::new();
    let mut nonces = HashSet::new();
    for r in &b.requests {
        if !reqs.insert((r.principal, r.request_id))
            || cx.has_request(&r.principal, &r.request_id)?
        {
            return Err(ProtocolError::new(
                ErrorCode::ReplayDetected,
                format!("request {} already recorded", r.request_id),
            ));
        }
        if !nonces.insert((r.principal, r.nonce.clone()))
            || cx.nonce_used(&r.principal, &r.nonce)?
        {
            return Err(ProtocolError::new(
                ErrorCode::ReplayDetected,
                "nonce already used",
            ));
        }
    }
    Ok(())
}
