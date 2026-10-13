//! In-memory backend for unit and conformance tests. Same validation as the SQLite backend.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use crate::core::ImmutableObject;
use crate::protocol::{
    err, Digest, Event, NamespaceId, ObjectKind, PrincipalId, RequestId, Sequence, Timestamp,
};

use crate::store::{
    validate_batch, AggregateRecord, BatchContext, IntegrityReport, RequestRecord, Result,
    SnapshotRecord, Store, WriteBatch,
};

#[derive(Default)]
struct Inner {
    aggregates: BTreeMap<(String, String), AggregateRecord>,
    objects: HashMap<Digest, ImmutableObject>,
    index: BTreeMap<(NamespaceId, Digest), ObjectKind>,
    journals: HashMap<NamespaceId, Vec<Event>>,
    requests: HashMap<(PrincipalId, RequestId), RequestRecord>,
    nonces: HashSet<(PrincipalId, String)>,
    snapshots: HashMap<NamespaceId, SnapshotRecord>,
}

impl BatchContext for Inner {
    fn version(&self, kind: &str, key: &str) -> Result<u64> {
        Ok(self
            .aggregates
            .get(&(kind.to_owned(), key.to_owned()))
            .map_or(0, |a| a.version))
    }
    fn head(&self, ns: &NamespaceId) -> Result<Option<(Sequence, Digest)>> {
        Ok(self
            .journals
            .get(ns)
            .and_then(|j| j.last())
            .map(|e| (e.sequence, e.hash)))
    }
    fn has_object(&self, d: &Digest) -> Result<bool> {
        Ok(self.objects.contains_key(d))
    }
    fn has_request(&self, p: &PrincipalId, r: &RequestId) -> Result<bool> {
        Ok(self.requests.contains_key(&(*p, *r)))
    }
    fn nonce_used(&self, p: &PrincipalId, n: &str) -> Result<bool> {
        Ok(self.nonces.contains(&(*p, n.to_owned())))
    }
}

/// Volatile store; everything is lost on drop.
#[derive(Default)]
pub struct MemoryStore(Mutex<Inner>);

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryStore")
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn inner(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.0
            .lock()
            .map_err(|_| err::internal("store lock poisoned"))
    }
}

impl Store for MemoryStore {
    fn get_aggregate(&self, kind: &str, key: &str) -> Result<Option<AggregateRecord>> {
        Ok(self
            .inner()?
            .aggregates
            .get(&(kind.to_owned(), key.to_owned()))
            .cloned())
    }

    fn list_aggregates(&self, kind: &str, prefix: &str) -> Result<Vec<(String, AggregateRecord)>> {
        let g = self.inner()?;
        Ok(g.aggregates
            .range((kind.to_owned(), prefix.to_owned())..)
            .take_while(|((k, key), _)| k == kind && key.starts_with(prefix))
            .map(|((_, key), v)| (key.clone(), v.clone()))
            .collect())
    }

    fn get_object(&self, digest: &Digest) -> Result<Option<ImmutableObject>> {
        Ok(self.inner()?.objects.get(digest).cloned())
    }

    fn has_object(&self, digest: &Digest) -> Result<bool> {
        Ok(self.inner()?.objects.contains_key(digest))
    }

    fn is_indexed(&self, ns: &NamespaceId, digest: &Digest) -> Result<bool> {
        Ok(self.inner()?.index.contains_key(&(*ns, *digest)))
    }

    fn list_index(
        &self,
        ns: &NamespaceId,
        kind: Option<ObjectKind>,
        after: Option<Digest>,
        limit: usize,
    ) -> Result<Vec<(Digest, ObjectKind)>> {
        let g = self.inner()?;
        Ok(g.index
            .range((*ns, after.unwrap_or(Digest::ZERO))..)
            .take_while(|((n, _), _)| n == ns)
            .filter(|((_, d), k)| Some(*d) != after && kind.is_none_or(|x| x == **k))
            .take(limit)
            .map(|((_, d), k)| (*d, *k))
            .collect())
    }

    fn journal_head(&self, ns: &NamespaceId) -> Result<Option<(Sequence, Digest)>> {
        self.inner()?.head(ns)
    }

    fn read_events(&self, ns: &NamespaceId, after: Sequence, limit: usize) -> Result<Vec<Event>> {
        let g = self.inner()?;
        Ok(g.journals
            .get(ns)
            .map(|j| j.iter().skip(after as usize).take(limit).cloned().collect())
            .unwrap_or_default())
    }

    fn get_request(&self, p: &PrincipalId, r: &RequestId) -> Result<Option<RequestRecord>> {
        Ok(self.inner()?.requests.get(&(*p, *r)).cloned())
    }

    fn nonce_used(&self, p: &PrincipalId, n: &str) -> Result<bool> {
        self.inner()?.nonce_used(p, n)
    }

    fn prune_requests(&self, before: Timestamp) -> Result<usize> {
        let mut g = self.inner()?;
        let old: Vec<_> = g
            .requests
            .iter()
            .filter(|(_, r)| r.issued_at < before)
            .map(|(k, r)| (*k, r.nonce.clone()))
            .collect();
        for (k, nonce) in &old {
            g.requests.remove(k);
            g.nonces.remove(&(k.0, nonce.clone()));
        }
        Ok(old.len())
    }

    fn latest_snapshot(&self, ns: &NamespaceId) -> Result<Option<SnapshotRecord>> {
        Ok(self.inner()?.snapshots.get(ns).cloned())
    }

    fn namespaces(&self) -> Result<Vec<NamespaceId>> {
        let mut v: Vec<_> = self.inner()?.journals.keys().copied().collect();
        v.sort();
        Ok(v)
    }

    fn commit(&self, b: WriteBatch) -> Result<()> {
        let mut g = self.inner()?;
        validate_batch(&b, &*g)?;
        for a in b.aggregates {
            g.aggregates.insert(
                (a.kind, a.key),
                AggregateRecord {
                    version: a.expected_version + 1,
                    body: a.body,
                },
            );
        }
        for o in b.objects {
            g.objects.entry(o.digest()).or_insert(o);
        }
        for i in b.index {
            g.index.insert((i.namespace, i.digest), i.kind);
        }
        for e in b.events {
            g.journals.entry(e.namespace).or_default().push(e);
        }
        for r in b.requests {
            g.nonces.insert((r.principal, r.nonce.clone()));
            g.requests.insert((r.principal, r.request_id), r);
        }
        for s in b.snapshots {
            g.snapshots.insert(s.namespace, s);
        }
        Ok(())
    }

    fn verify_integrity(&self) -> Result<IntegrityReport> {
        let g = self.inner()?;
        let mut report = IntegrityReport {
            namespaces: g.journals.len(),
            ..Default::default()
        };
        for (ns, events) in &g.journals {
            report.events += events.len() as u64;
            if let Err(e) = crate::core::events::verify_chain(events, 0, Digest::ZERO) {
                report.problems.push(format!("{ns}: {}", e.message));
            }
        }
        for (d, o) in &g.objects {
            report.objects += 1;
            if crate::crypto::sha256(o.bytes()) != *d {
                report.problems.push(format!("object {d} digest mismatch"));
            }
        }
        for (ns, d) in g.index.keys() {
            if !g.objects.contains_key(d) {
                report
                    .problems
                    .push(format!("{ns}: index references missing object {d}"));
            }
        }
        Ok(report)
    }
}
