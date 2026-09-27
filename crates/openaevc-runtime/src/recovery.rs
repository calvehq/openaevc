//! Startup recovery and lease expiry (spec/recovery.md).

use openaevc_protocol::{err, Digest, JournalCheckpoint, NamespaceId};

use crate::records::{self, CheckpointRecord};
use crate::{Result, Shared};

/// Verifies every Namespace journal from its latest signed checkpoint (or genesis) to the head.
/// Fails closed with `STORAGE_INTEGRITY_ERROR`.
pub(crate) fn startup(rt: &Shared) -> Result<()> {
    for ns in rt.store.namespaces()? {
        verify_journal(rt, ns)?;
        expire_leases(rt, ns)?;
    }
    Ok(())
}

pub(crate) fn verify_journal(rt: &Shared, ns: NamespaceId) -> Result<()> {
    let (mut seq, mut hash) = (0, Digest::ZERO);
    if let Some(rec) = rt
        .store
        .get_aggregate(records::CHECKPOINT, &ns.to_string())?
    {
        let rec: CheckpointRecord = rec.decode()?;
        let obj = rt
            .store
            .get_object(&rec.digest)?
            .ok_or_else(|| err::integrity(format!("{ns}: checkpoint object missing")))?;
        if obj.envelope().signatures.is_empty() {
            return Err(err::integrity(format!("{ns}: checkpoint is unsigned")));
        }
        let cp: JournalCheckpoint = obj.body()?;
        let at = rt.store.read_events(&ns, cp.sequence - 1, 1)?;
        if at.first().map(|e| (e.sequence, e.hash)) != Some((cp.sequence, cp.event_hash)) {
            return Err(err::integrity(format!(
                "{ns}: journal does not match signed checkpoint {}",
                cp.sequence
            )));
        }
        (seq, hash) = (cp.sequence, cp.event_hash);
    }
    loop {
        let events = rt.store.read_events(&ns, seq, 1000)?;
        if events.is_empty() {
            return Ok(());
        }
        (seq, hash) = openaevc_core::events::verify_chain(&events, seq, hash)
            .map_err(|e| err::integrity(format!("{ns}: {}", e.message)))?;
    }
}

/// Marks executions whose lease expired as LOST. No-op until executions exist.
pub(crate) fn expire_leases(rt: &Shared, ns: NamespaceId) -> Result<()> {
    crate::handlers::expire_leases(rt, ns)
}
