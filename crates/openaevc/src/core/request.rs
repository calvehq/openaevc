//! Signing and verification of request envelopes (spec/transport.md §Envelopes).
//!
//! The signed message is the canonical encoding of the envelope with `signature` omitted, in
//! the `request` signature domain.

use crate::crypto::{Domain, Signer};
use crate::protocol::{err, Digest, Envelope, ProtocolError, PublicKey};
use serde::Serialize;

/// Canonical bytes covered by the envelope signature.
pub fn signing_bytes<T: Serialize>(env: &Envelope<T>) -> Result<Vec<u8>, ProtocolError> {
    let mut v = crate::canonical::to_value(env)?;
    if let Some(m) = v.as_object_mut() {
        m.remove("signature");
    }
    Ok(crate::canonical::encode(&v)?)
}

/// Signs (or re-signs) an envelope.
pub fn sign_request<T: Serialize>(
    mut env: Envelope<T>,
    signer: &dyn Signer,
) -> Result<Envelope<T>, ProtocolError> {
    let msg = signing_bytes(&env)?;
    env.signature = Some(signer.sign(Domain::Request, &msg));
    Ok(env)
}

/// Verifies the envelope signature with `key` (`UNAUTHORIZED` when missing or invalid).
pub fn verify_request<T: Serialize>(
    env: &Envelope<T>,
    key: &PublicKey,
) -> Result<(), ProtocolError> {
    let sig = env
        .signature
        .as_ref()
        .ok_or_else(|| err::unauthorized("request is not signed"))?;
    crate::crypto::verify(key, Domain::Request, &signing_bytes(env)?, sig)
}

/// Digest of the complete signed envelope (idempotency comparison, receipts).
pub fn envelope_digest<T: Serialize>(env: &Envelope<T>) -> Result<Digest, ProtocolError> {
    crate::crypto::digest_of(env)
}
/// A request envelope together with the exact bytes its signature covers.
///
/// Envelopes are verified over the canonical encoding of the envelope value as received (minus
/// `signature`). Parsing is strict (unknown fields rejected), but optional empty fields need not
/// be omitted, so every SDK can sign what it sends without knowing field optionality.
#[derive(Debug, Clone)]
pub struct SignedRequest<T> {
    pub envelope: Envelope<T>,
    signing_bytes: Vec<u8>,
    digest: Digest,
}

impl<T: Serialize + serde::de::DeserializeOwned> SignedRequest<T> {
    /// From a typed envelope (embedded callers).
    pub fn from_envelope(env: Envelope<T>) -> Result<Self, ProtocolError> {
        let v = crate::canonical::to_value(&env)?;
        Self::from_value(v)
    }

    /// From a received JSON-model value (transport callers).
    pub fn from_value(v: serde_json::Value) -> Result<Self, ProtocolError> {
        let digest = crate::crypto::sha256(&crate::canonical::encode(&v)?);
        let mut unsigned = v.clone();
        if let Some(m) = unsigned.as_object_mut() {
            m.remove("signature");
        }
        let signing_bytes = crate::canonical::encode(&unsigned)?;
        let envelope: Envelope<T> = serde_json::from_value(v)
            .map_err(|e| err::invalid(format!("invalid request envelope: {e}")))?;
        Ok(SignedRequest {
            envelope,
            signing_bytes,
            digest,
        })
    }

    /// Verifies the signature with `key` (`UNAUTHORIZED` when missing or invalid).
    pub fn verify(&self, key: &PublicKey) -> Result<(), ProtocolError> {
        let sig = self
            .envelope
            .signature
            .as_ref()
            .ok_or_else(|| err::unauthorized("request is not signed"))?;
        crate::crypto::verify(key, Domain::Request, &self.signing_bytes, sig)
    }

    /// Digest of the envelope as received (idempotency, receipts).
    pub fn digest(&self) -> Digest {
        self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Signer, SigningKey};
    use crate::protocol::{Command, ErrorCode, Query, Timestamp, PROTOCOL_VERSION};

    fn env() -> Envelope<Query> {
        Envelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: "req_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            namespace: None,
            caller: "pri_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            act_as: None,
            nonce: "bm9uY2U".into(),
            issued_at: Timestamp::from_unix_nanos(0),
            expires_at: None,
            body: Query::GetRuntimeInfo {},
            signature: None,
        }
    }

    #[test]
    fn sign_then_verify() {
        let k = SigningKey::generate();
        let e = sign_request(env(), &k).unwrap();
        verify_request(&e, &k.public_key()).unwrap();
    }

    #[test]
    fn tampering_or_missing_signature_fails() {
        let k = SigningKey::generate();
        let mut e = sign_request(env(), &k).unwrap();
        e.nonce = "b3RoZXI".into();
        assert_eq!(
            verify_request(&e, &k.public_key()).unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert_eq!(
            verify_request(&env(), &k.public_key()).unwrap_err().code,
            ErrorCode::Unauthorized
        );
    }

    #[test]
    fn signed_request_accepts_non_minimal_but_valid_encodings() {
        let k = SigningKey::generate();
        // A client that sends an explicit empty optional field signs exactly what it sends.
        let mut v = serde_json::to_value(env()).unwrap();
        v["body"] = serde_json::json!({"type": "ListEvents", "after": 0, "kinds": []});
        v.as_object_mut().unwrap().remove("signature");
        let sig = k.sign(
            crate::crypto::Domain::Request,
            &crate::canonical::encode(&v).unwrap(),
        );
        v["signature"] = serde_json::json!(sig.to_string());
        let r = SignedRequest::<Query>::from_value(v.clone()).unwrap();
        r.verify(&k.public_key()).unwrap();
        // Tampering is still detected; unknown fields are still rejected.
        let mut t = v.clone();
        t["nonce"] = serde_json::json!("b3RoZXI");
        assert!(SignedRequest::<Query>::from_value(t)
            .unwrap()
            .verify(&k.public_key())
            .is_err());
        let mut u = v;
        u["extra"] = serde_json::json!(1);
        assert_eq!(
            SignedRequest::<Query>::from_value(u).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn digest_ignores_nothing_but_is_stable() {
        let k = SigningKey::from_seed([5; 32]);
        let a = sign_request(env(), &k).unwrap();
        let b = sign_request(env(), &k).unwrap();
        assert_eq!(envelope_digest(&a).unwrap(), envelope_digest(&b).unwrap());
        let _ = Command::NAMES;
    }
}
