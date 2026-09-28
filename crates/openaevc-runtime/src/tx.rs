//! Command transaction: a read-through overlay over the store that accumulates aggregate
//! updates, new immutable objects and journal events, then turns them into one atomic
//! `WriteBatch`. A command either commits everything it staged or nothing.

use std::collections::BTreeMap;

use openaevc_core::{IdGeneratorExt, ImmutableObject};
use openaevc_protocol::{
    err, Digest, Event, JournalCheckpoint, NamespaceId, ObjectEnvelope, ObjectKind, PrincipalId,
    ProtocolError, RequestId, Sequence, Timestamp, PROTOCOL_VERSION,
};
use openaevc_store::{AggregatePut, IndexEntry, WriteBatch};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::records;
use crate::Shared;

pub(crate) struct PendingEvent {
    pub kind: String,
    pub body: Value,
    pub subjects: Vec<String>,
}

pub(crate) struct Tx<'a> {
    pub rt: &'a Shared,
    pub ns: NamespaceId,
    pub now: Timestamp,
    pub request_id: Option<RequestId>,
    pub actor: Option<PrincipalId>,
    /// Principal recorded as creator of new objects.
    pub creator: PrincipalId,
    pub first_seq: Sequence,
    pub head_hash: Digest,
    reads: BTreeMap<(String, String), u64>,
    writes: BTreeMap<(String, String), Value>,
    objects: Vec<ImmutableObject>,
    index: Vec<IndexEntry>,
    events: Vec<PendingEvent>,
}

impl<'a> Tx<'a> {
    pub fn new(
        rt: &'a Shared,
        ns: NamespaceId,
        creator: PrincipalId,
    ) -> Result<Self, ProtocolError> {
        let (seq, head_hash) = rt.store.journal_head(&ns)?.unwrap_or((0, Digest::ZERO));
        Ok(Tx {
            rt,
            ns,
            now: rt.clock.now(),
            request_id: None,
            actor: None,
            creator,
            first_seq: seq + 1,
            head_hash,
            reads: BTreeMap::new(),
            writes: BTreeMap::new(),
            objects: Vec::new(),
            index: Vec::new(),
            events: Vec::new(),
        })
    }

    fn version_of(&mut self, kind: &str, key: &str) -> Result<u64, ProtocolError> {
        let k = (kind.to_owned(), key.to_owned());
        if let Some(v) = self.reads.get(&k) {
            return Ok(*v);
        }
        let v = self
            .rt
            .store
            .get_aggregate(kind, key)?
            .map_or(0, |r| r.version);
        self.reads.insert(k, v);
        Ok(v)
    }

    pub fn get<T: DeserializeOwned>(
        &mut self,
        kind: &str,
        key: &str,
    ) -> Result<Option<T>, ProtocolError> {
        let k = (kind.to_owned(), key.to_owned());
        if let Some(v) = self.writes.get(&k) {
            return serde_json::from_value(v.clone())
                .map(Some)
                .map_err(|e| err::internal(format!("aggregate decode: {e}")));
        }
        match self.rt.store.get_aggregate(kind, key)? {
            None => {
                self.reads.entry(k).or_insert(0);
                Ok(None)
            }
            Some(r) => {
                self.reads.entry(k).or_insert(r.version);
                r.decode().map(Some)
            }
        }
    }

    /// Read without recording a version dependency (authorization views, queries).
    pub fn peek<T: DeserializeOwned>(
        &self,
        kind: &str,
        key: &str,
    ) -> Result<Option<T>, ProtocolError> {
        if let Some(v) = self.writes.get(&(kind.to_owned(), key.to_owned())) {
            return serde_json::from_value(v.clone())
                .map(Some)
                .map_err(|e| err::internal(format!("aggregate decode: {e}")));
        }
        self.rt
            .store
            .get_aggregate(kind, key)?
            .map(|r| r.decode())
            .transpose()
    }

    pub fn peek_list<T: DeserializeOwned>(
        &self,
        kind: &str,
        prefix: &str,
    ) -> Result<Vec<(String, T)>, ProtocolError> {
        let mut map: BTreeMap<String, Value> = self
            .rt
            .store
            .list_aggregates(kind, prefix)?
            .into_iter()
            .map(|(k, r)| (k, r.body))
            .collect();
        for ((wk, key), v) in &self.writes {
            if wk == kind && key.starts_with(prefix) {
                map.insert(key.clone(), v.clone());
            }
        }
        map.into_iter()
            .map(|(k, v)| {
                serde_json::from_value(v)
                    .map(|t| (k, t))
                    .map_err(|e| err::internal(format!("aggregate decode: {e}")))
            })
            .collect()
    }

    pub fn require<T: DeserializeOwned>(
        &mut self,
        kind: &str,
        key: &str,
        what: &str,
    ) -> Result<T, ProtocolError> {
        self.get(kind, key)?
            .ok_or_else(|| err::not_found(format!("{what} not found")))
    }

    pub fn put<T: Serialize>(
        &mut self,
        kind: &str,
        key: &str,
        value: &T,
    ) -> Result<(), ProtocolError> {
        self.version_of(kind, key)?;
        let v = serde_json::to_value(value)
            .map_err(|e| err::internal(format!("aggregate encode: {e}")))?;
        self.writes.insert((kind.to_owned(), key.to_owned()), v);
        Ok(())
    }

    /// Builds, stores and indexes a new immutable object created by this command.
    pub fn object<T: Serialize>(
        &mut self,
        kind: ObjectKind,
        id: Option<String>,
        body: &T,
        runtime_signed: bool,
    ) -> Result<ImmutableObject, ProtocolError> {
        let env = ObjectEnvelope {
            kind,
            protocol_version: PROTOCOL_VERSION,
            namespace: self.ns,
            id,
            created_seq: self.first_seq,
            creator: if runtime_signed {
                self.rt.runtime_principal
            } else {
                self.creator
            },
            body: openaevc_canonical::to_value(body)?,
            signatures: vec![],
        };
        let env = if runtime_signed {
            openaevc_core::sign_envelope(env, self.rt.signer.as_ref())?
        } else {
            env
        };
        let obj = ImmutableObject::build(env)?;
        self.add_object(obj.clone());
        Ok(obj)
    }

    /// Stages an existing (e.g. imported) object and indexes it into this Namespace.
    pub fn add_object(&mut self, obj: ImmutableObject) {
        self.index.push(IndexEntry {
            namespace: self.ns,
            digest: obj.digest(),
            kind: obj.kind(),
        });
        if !self.objects.iter().any(|o| o.digest() == obj.digest()) {
            self.objects.push(obj);
        }
    }

    /// Object visible in this Namespace (staged in this tx or indexed).
    pub fn load_object(&self, d: &Digest) -> Result<Option<ImmutableObject>, ProtocolError> {
        if let Some(o) = self.objects.iter().find(|o| &o.digest() == d) {
            return Ok(Some(o.clone()));
        }
        if !self.rt.store.is_indexed(&self.ns, d)? {
            return Ok(None);
        }
        self.rt.store.get_object(d)
    }

    pub fn require_object<T: Serialize + DeserializeOwned>(
        &self,
        d: &Digest,
        kind: ObjectKind,
    ) -> Result<(ImmutableObject, T), ProtocolError> {
        let o = self
            .load_object(d)?
            .ok_or_else(|| err::not_found(format!("object {d} not found")).with_object(d))?;
        if o.kind() != kind {
            return Err(err::invalid(format!(
                "object {d} is a {}, expected {}",
                o.kind().as_str(),
                kind.as_str()
            ))
            .with_object(d));
        }
        let body = o.body()?;
        Ok((o, body))
    }

    /// Stages a journal event. Absent (`null`) fields are omitted, as in every canonical object.
    pub fn emit(&mut self, kind: &str, body: Value, subjects: Vec<String>) {
        fn strip(v: Value) -> Value {
            match v {
                Value::Object(m) => Value::Object(
                    m.into_iter()
                        .filter(|(_, v)| !v.is_null())
                        .map(|(k, v)| (k, strip(v)))
                        .collect(),
                ),
                Value::Array(a) => Value::Array(a.into_iter().map(strip).collect()),
                other => other,
            }
        }
        self.events.push(PendingEvent {
            kind: kind.to_owned(),
            body: strip(body),
            subjects,
        });
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Sequence of the last event staged so far.
    pub fn last_seq(&self) -> Sequence {
        self.first_seq + self.events.len() as u64 - 1
    }

    /// Assigns sequences and hash-chains the staged events.
    pub fn finish_events(&mut self) -> Result<Vec<Event>, ProtocolError> {
        let mut prev = self.head_hash;
        let mut events = Vec::with_capacity(self.events.len());
        for (i, p) in std::mem::take(&mut self.events).into_iter().enumerate() {
            let mut e = Event {
                id: self.rt.ids.next(),
                namespace: self.ns,
                sequence: self.first_seq + i as u64,
                runtime_instance: self.rt.instance,
                request_id: self.request_id,
                actor: self.actor,
                kind: p.kind,
                body: p.body,
                subjects: p.subjects,
                timestamp: self.now,
                previous_hash: prev,
                hash: Digest::ZERO,
            };
            e.hash = openaevc_core::events::event_hash(&e)?;
            prev = e.hash;
            events.push(e);
        }
        self.checkpoint(&events)?;
        Ok(events)
    }

    /// AEVC-EVT-0004: when this commit's events include a multiple of `checkpoint_interval`,
    /// stage a runtime-signed `journal_checkpoint` for the highest one. Every commit path
    /// (commands, denials, lease sweeps) goes through `finish_events`.
    fn checkpoint(&mut self, events: &[Event]) -> Result<(), ProtocolError> {
        let interval = self.rt.config.checkpoint_interval.max(1);
        let Some(e) = events.iter().rev().find(|e| e.sequence % interval == 0) else {
            return Ok(());
        };
        let cp = JournalCheckpoint {
            sequence: e.sequence,
            event_hash: e.hash,
            runtime_key: self.rt.signer.public_key(),
            runtime_instance: self.rt.instance,
            created_at: self.now,
        };
        let obj = self.object(ObjectKind::JournalCheckpoint, None, &cp, true)?;
        let ns = self.ns.to_string();
        self.put(
            records::CHECKPOINT,
            &ns,
            &records::CheckpointRecord {
                digest: obj.digest(),
                sequence: e.sequence,
            },
        )
    }

    pub fn into_batch(self, events: Vec<Event>) -> Result<WriteBatch, ProtocolError> {
        let aggregates = self
            .writes
            .into_iter()
            .map(|((kind, key), body)| {
                let expected_version = self
                    .reads
                    .get(&(kind.clone(), key.clone()))
                    .copied()
                    .unwrap_or(0);
                AggregatePut {
                    kind,
                    key,
                    expected_version,
                    body,
                }
            })
            .collect();
        Ok(WriteBatch {
            aggregates,
            objects: self.objects,
            index: self.index,
            events,
            ..Default::default()
        })
    }
}
