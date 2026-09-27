//! Immutable object envelopes: building, signing, strict decoding and closure references
//! (spec/object-model.md).

use std::sync::Arc;

use openaevc_crypto::{Domain, Signer};
use openaevc_protocol::{
    err, Baseline, Blob, Candidate, Digest, ErrorCode, EvaluationResult, Evidence,
    ExtensionManifest, JournalCheckpoint, ObjectEnvelope, ObjectKind, Observation, PolicyDecision,
    PolicyDocument, PromotedPack, PromotionRecord, ProtocolError, Receipt, Revocation, SignedGrant,
    VerificationResult, SUPPORTED_PROTOCOL,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// A validated immutable object: its envelope, exact canonical bytes and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableObject {
    envelope: ObjectEnvelope,
    bytes: Arc<[u8]>,
    digest: Digest,
}

/// Digest that object signatures cover: canonical envelope with `signatures` omitted.
pub fn signing_digest(env: &ObjectEnvelope) -> Result<Digest, ProtocolError> {
    let mut unsigned = env.clone();
    unsigned.signatures.clear();
    openaevc_crypto::digest_of(&unsigned)
}

/// Adds `signer`'s signature over the envelope's signing digest.
pub fn sign_envelope(
    mut env: ObjectEnvelope,
    signer: &dyn Signer,
) -> Result<ObjectEnvelope, ProtocolError> {
    let d = signing_digest(&env)?;
    env.signatures.push(openaevc_crypto::sign_entry(
        signer,
        Domain::Object,
        d.as_bytes(),
    ));
    env.signatures.sort();
    env.signatures.dedup();
    Ok(env)
}

fn strict<T: Serialize + DeserializeOwned>(v: &serde_json::Value) -> Result<T, ProtocolError> {
    openaevc_canonical::from_value(v.clone())
        .map_err(|e| ProtocolError::new(ErrorCode::InvalidArgument, format!("object body: {e}")))
}

/// Validates an envelope body against the schema of its kind.
pub fn validate_body(kind: ObjectKind, body: &serde_json::Value) -> Result<(), ProtocolError> {
    match kind {
        ObjectKind::Blob => strict::<Blob>(body).map(drop),
        ObjectKind::CapabilityGrant => strict::<SignedGrant>(body).map(drop),
        ObjectKind::Revocation => strict::<Revocation>(body).map(drop),
        ObjectKind::PolicyDocument => strict::<PolicyDocument>(body).map(drop),
        ObjectKind::PolicyDecision => strict::<PolicyDecision>(body).map(drop),
        ObjectKind::ExtensionManifest => strict::<ExtensionManifest>(body).map(drop),
        ObjectKind::Candidate => strict::<Candidate>(body).map(drop),
        ObjectKind::Observation => strict::<Observation>(body).map(drop),
        ObjectKind::Evidence => strict::<Evidence>(body).map(drop),
        ObjectKind::VerificationResult => strict::<VerificationResult>(body).map(drop),
        ObjectKind::EvaluationResult => strict::<EvaluationResult>(body).map(drop),
        ObjectKind::PromotedPack => strict::<PromotedPack>(body).map(drop),
        ObjectKind::PromotionRecord => strict::<PromotionRecord>(body).map(drop),
        ObjectKind::Receipt => strict::<Receipt>(body).map(drop),
        ObjectKind::Baseline => strict::<Baseline>(body).map(drop),
        ObjectKind::JournalCheckpoint => strict::<JournalCheckpoint>(body).map(drop),
    }
}

impl ImmutableObject {
    /// Validates and canonically encodes an envelope.
    pub fn build(envelope: ObjectEnvelope) -> Result<Self, ProtocolError> {
        Self::validate(&envelope)?;
        let bytes: Arc<[u8]> = openaevc_canonical::to_canonical(&envelope)?.into();
        let digest = openaevc_crypto::sha256(&bytes);
        Ok(Self {
            envelope,
            bytes,
            digest,
        })
    }

    /// Strictly decodes canonical bytes. When `expected` is given the digest must match
    /// (`DIGEST_MISMATCH`), before any other interpretation of the bytes.
    pub fn from_bytes(bytes: &[u8], expected: Option<Digest>) -> Result<Self, ProtocolError> {
        let digest = openaevc_crypto::sha256(bytes);
        if let Some(exp) = expected {
            if exp != digest {
                return Err(ProtocolError::new(
                    ErrorCode::DigestMismatch,
                    format!("bytes hash to {digest}, expected {exp}"),
                ));
            }
        }
        let envelope: ObjectEnvelope = openaevc_canonical::from_canonical(bytes)?;
        Self::validate(&envelope)?;
        Ok(Self {
            envelope,
            bytes: bytes.into(),
            digest,
        })
    }

    fn validate(env: &ObjectEnvelope) -> Result<(), ProtocolError> {
        if !SUPPORTED_PROTOCOL.contains(env.protocol_version) {
            return Err(ProtocolError::new(
                ErrorCode::ProtocolVersionUnsupported,
                format!(
                    "object protocol version {} is not supported",
                    env.protocol_version
                ),
            ));
        }
        validate_body(env.kind, &env.body)?;
        if !env.signatures.windows(2).all(|w| w[0] < w[1]) {
            return Err(err::encoding("object signatures must be sorted and unique"));
        }
        if !env.signatures.is_empty() {
            let d = signing_digest(env)?;
            for s in &env.signatures {
                openaevc_crypto::verify_entry(s, Domain::Object, d.as_bytes())?;
            }
        }
        Ok(())
    }

    pub fn envelope(&self) -> &ObjectEnvelope {
        &self.envelope
    }

    pub fn kind(&self) -> ObjectKind {
        self.envelope.kind
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// Typed body.
    pub fn body<T: Serialize + DeserializeOwned>(&self) -> Result<T, ProtocolError> {
        strict(&self.envelope.body)
    }

    /// Digests of immutable objects this object requires for validation (its direct closure
    /// edges), deduplicated and sorted.
    pub fn references(&self) -> Result<Vec<Digest>, ProtocolError> {
        let mut out: Vec<Digest> = match self.kind() {
            ObjectKind::Blob
            | ObjectKind::PolicyDocument
            | ObjectKind::ExtensionManifest
            | ObjectKind::Receipt
            | ObjectKind::JournalCheckpoint => vec![],
            ObjectKind::CapabilityGrant => self
                .body::<SignedGrant>()?
                .body
                .parent
                .into_iter()
                .collect(),
            ObjectKind::Revocation => vec![self.body::<Revocation>()?.grant_digest],
            ObjectKind::PolicyDecision => self.body::<PolicyDecision>()?.policies,
            ObjectKind::Candidate => {
                let c: Candidate = self.body()?;
                c.effects
                    .iter()
                    .flat_map(|e| {
                        let p = &e.provenance;
                        p.grants
                            .iter()
                            .chain(&p.inputs)
                            .copied()
                            .chain(p.extension.as_ref().map(|x| x.manifest_digest))
                    })
                    .collect()
            }
            ObjectKind::Observation => {
                let o: Observation = self.body()?;
                let p = o.provenance;
                o.blob
                    .into_iter()
                    .chain(p.grants)
                    .chain(p.inputs)
                    .chain(p.extension.map(|x| x.manifest_digest))
                    .collect()
            }
            ObjectKind::Evidence => {
                let e: Evidence = self.body()?;
                std::iter::once(e.payload)
                    .chain(e.extension.map(|x| x.manifest_digest))
                    .collect()
            }
            ObjectKind::VerificationResult => {
                let v: VerificationResult = self.body()?;
                v.evidence
                    .into_iter()
                    .chain(v.extension.map(|x| x.manifest_digest))
                    .collect()
            }
            ObjectKind::EvaluationResult => {
                let v: EvaluationResult = self.body()?;
                v.inputs
                    .into_iter()
                    .chain(v.extension.map(|x| x.manifest_digest))
                    .collect()
            }
            ObjectKind::PromotionRecord => vec![self.body::<PromotionRecord>()?.policy_decision],
            ObjectKind::PromotedPack => {
                let p: PromotedPack = self.body()?;
                let mut v = vec![p.candidate, p.promotion_record];
                v.extend(p.dependencies);
                v.extend(p.revision.map(|r| r.targets).unwrap_or_default());
                v.extend(p.verifications);
                v.extend(p.evaluations);
                v.extend(p.evidence);
                v.extend(p.policy_decisions);
                v.extend(p.extensions.into_iter().map(|x| x.manifest_digest));
                v
            }
            ObjectKind::Baseline => {
                let b: Baseline = self.body()?;
                b.members.into_iter().chain(b.policies).collect()
            }
        };
        out.sort();
        out.dedup();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaevc_crypto::SigningKey;
    use openaevc_protocol::{ErrorCode, ObjectKind};
    use serde_json::json;

    fn env(kind: ObjectKind, body: serde_json::Value) -> ObjectEnvelope {
        ObjectEnvelope {
            kind,
            protocol_version: openaevc_protocol::PROTOCOL_VERSION,
            namespace: "ns_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            id: None,
            created_seq: 1,
            creator: "pri_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            body,
            signatures: vec![],
        }
    }

    fn blob() -> ObjectEnvelope {
        env(
            ObjectKind::Blob,
            json!({"media_type": "text/plain", "data": "aGk"}),
        )
    }

    #[test]
    fn digest_is_sha256_of_canonical_bytes() {
        let o = ImmutableObject::build(blob()).unwrap();
        assert_eq!(o.digest(), openaevc_crypto::sha256(o.bytes()));
        let again = ImmutableObject::from_bytes(o.bytes(), Some(o.digest())).unwrap();
        assert_eq!(again.envelope(), o.envelope());
    }

    #[test]
    fn from_bytes_rejects_digest_mismatch() {
        let o = ImmutableObject::build(blob()).unwrap();
        let wrong = openaevc_crypto::sha256(b"other");
        assert_eq!(
            ImmutableObject::from_bytes(o.bytes(), Some(wrong))
                .unwrap_err()
                .code,
            ErrorCode::DigestMismatch
        );
    }

    #[test]
    fn body_must_match_kind_schema() {
        let bad = env(ObjectKind::Blob, json!({"media_type": "text/plain"}));
        assert_eq!(
            ImmutableObject::build(bad).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        let extra = env(
            ObjectKind::Blob,
            json!({"media_type": "a", "data": "aGk", "x": 1}),
        );
        assert!(ImmutableObject::build(extra).is_err());
    }

    #[test]
    fn unsupported_protocol_version_rejected() {
        let mut e = blob();
        e.protocol_version = openaevc_protocol::ProtocolVersion::new(9, 0, 0);
        assert_eq!(
            ImmutableObject::build(e).unwrap_err().code,
            ErrorCode::ProtocolVersionUnsupported
        );
    }

    #[test]
    fn signatures_cover_signing_digest_and_are_verified() {
        let key = SigningKey::generate();
        let signed = sign_envelope(blob(), &key).unwrap();
        let o = ImmutableObject::build(signed.clone()).unwrap();
        assert_eq!(o.envelope().signatures.len(), 1);
        assert_eq!(
            signing_digest(o.envelope()).unwrap(),
            signing_digest(&blob()).unwrap()
        );
        // Tamper: signature from another envelope.
        let mut forged = signed;
        forged.created_seq = 2;
        assert_eq!(
            ImmutableObject::build(forged).unwrap_err().code,
            ErrorCode::Unauthorized
        );
    }

    #[test]
    fn tampered_bytes_fail_closed() {
        let o = ImmutableObject::build(blob()).unwrap();
        let mut b = o.bytes().to_vec();
        let last = b.len() - 1;
        b[last] ^= 1;
        assert!(ImmutableObject::from_bytes(&b, None).is_err());
    }

    #[test]
    fn references_follow_kind() {
        let d = openaevc_crypto::sha256(b"x");
        let rec = env(
            ObjectKind::PromotionRecord,
            json!({
                "id": "pro_agjdus24nvyadaareizuivlgo4",
                "pack": "cpk_agjdus24nvyadaareizuivlgo4",
                "generation": 1,
                "candidate": d.to_string(),
                "policy_decision": d.to_string(),
                "promoted_by": "pri_agjdus24nvyadaareizuivlgo4",
                "promoted_at": "2024-01-01T00:00:00.000000000Z",
                "request_id": "req_agjdus24nvyadaareizuivlgo4"
            }),
        );
        let o = ImmutableObject::build(rec).unwrap();
        assert_eq!(o.references().unwrap(), vec![d]);
        assert!(ImmutableObject::build(blob())
            .unwrap()
            .references()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn typed_body_accessor() {
        let o = ImmutableObject::build(blob()).unwrap();
        let b: openaevc_protocol::Blob = o.body().unwrap();
        assert_eq!(b.data, b"hi");
    }
}
