//! Tamper-evident event hash chain (spec/events.md).
//!
//! `hash = SHA-256(canonical(event without "hash") || previous_hash raw bytes)`; the genesis
//! `previous_hash` is the all-zero SHA-256 value.

use openaevc_protocol::{err, Digest, Event, ProtocolError, Sequence};

pub fn event_hash(e: &Event) -> Result<Digest, ProtocolError> {
    let mut v = openaevc_canonical::to_value(e)?;
    if let Some(m) = v.as_object_mut() {
        m.remove("hash");
    }
    let mut bytes = openaevc_canonical::encode(&v)?;
    bytes.extend_from_slice(e.previous_hash.as_bytes());
    Ok(openaevc_crypto::sha256(&bytes))
}

/// Verifies a contiguous run of events following `(prev_seq, prev_hash)`. Returns the last
/// `(sequence, hash)`. Fails with `STORAGE_INTEGRITY_ERROR` on any gap, relink or tampering.
pub fn verify_chain(events: &[Event], prev_seq: Sequence, prev_hash: Digest) -> Result<(Sequence, Digest), ProtocolError> {
    let (mut seq, mut hash) = (prev_seq, prev_hash);
    for e in events {
        if e.sequence != seq + 1 {
            return Err(err::integrity(format!("journal gap: expected sequence {}, found {}", seq + 1, e.sequence)));
        }
        if e.previous_hash != hash {
            return Err(err::integrity(format!("journal link broken at sequence {}", e.sequence)));
        }
        if event_hash(e)? != e.hash {
            return Err(err::integrity(format!("journal event {} has been modified", e.sequence)));
        }
        seq = e.sequence;
        hash = e.hash;
    }
    Ok((seq, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaevc_protocol::Digest;
    use serde_json::json;

    fn ev(seq: u64, prev: Digest) -> Event {
        let mut e = Event {
            id: "evt_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            namespace: "ns_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            sequence: seq,
            runtime_instance: "rti_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            request_id: None,
            actor: None,
            kind: "test.event".into(),
            body: json!({"n": seq}),
            subjects: vec![],
            timestamp: openaevc_protocol::Timestamp::from_unix_nanos(0),
            previous_hash: prev,
            hash: Digest::ZERO,
        };
        e.hash = event_hash(&e).unwrap();
        e
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let a = ev(1, Digest::ZERO);
        let b = ev(2, a.hash);
        let c = ev(3, b.hash);
        let chain = vec![a, b, c];
        assert_eq!(verify_chain(&chain, 0, Digest::ZERO).unwrap(), (3, chain[2].hash));

        let mut tampered = chain.clone();
        tampered[1].body = json!({"n": 99});
        assert!(verify_chain(&tampered, 0, Digest::ZERO).is_err());

        let mut gap = chain.clone();
        gap.remove(1);
        assert!(verify_chain(&gap, 0, Digest::ZERO).is_err());

        let mut relinked = chain;
        relinked[2].previous_hash = Digest::ZERO;
        assert!(verify_chain(&relinked, 0, Digest::ZERO).is_err());
    }
}
