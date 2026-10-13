//! Startup recovery and lease expiry (spec/recovery.md).

use crate::protocol::{err, Digest, JournalCheckpoint, NamespaceId, Timestamp};

use crate::runtime::records::{self, CheckpointRecord};
use crate::runtime::{Result, Shared};

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
        // Signatures were verified on load; the checkpoint must also be this runtime's own.
        let key = rt.signer.public_key();
        let cp: JournalCheckpoint = obj.body()?;
        if cp.runtime_key != key
            || !obj
                .envelope()
                .signatures
                .iter()
                .any(|s| s.public_key == key)
        {
            return Err(err::integrity(format!(
                "{ns}: checkpoint is not signed by this runtime's key"
            )));
        }
        let at = rt.store.read_events(&ns, cp.sequence - 1, 1)?;
        // The checkpointed event itself is re-hashed: verification resumes after it.
        let rehashed = at
            .first()
            .map(crate::core::events::event_hash)
            .transpose()?;
        if at.first().map(|e| (e.sequence, e.hash)) != Some((cp.sequence, cp.event_hash))
            || rehashed != Some(cp.event_hash)
        {
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
        (seq, hash) = crate::core::events::verify_chain(&events, seq, hash)
            .map_err(|e| err::integrity(format!("{ns}: {}", e.message)))?;
    }
}

/// Marks executions whose lease expired as LOST. No-op until executions exist.
pub(crate) fn expire_leases(rt: &Shared, ns: NamespaceId) -> Result<Timestamp> {
    crate::runtime::handlers::expire_leases(rt, ns)
}
