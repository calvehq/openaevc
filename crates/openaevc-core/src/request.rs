//! Signing and verification of request envelopes (spec/transport.md §Envelopes).
//!
//! The signed message is the canonical encoding of the envelope with `signature` omitted, in
//! the `request` signature domain.

use openaevc_crypto::{Domain, Signer};
use openaevc_protocol::{err, Digest, Envelope, ProtocolError, PublicKey};
use serde::Serialize;

/// Canonical bytes covered by the envelope signature.
pub fn signing_bytes<T: Serialize>(env: &Envelope<T>) -> Result<Vec<u8>, ProtocolError> {
    let mut v = openaevc_canonical::to_value(env)?;
    if let Some(m) = v.as_object_mut() {
        m.remove("signature");
    }
    Ok(openaevc_canonical::encode(&v)?)
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
    openaevc_crypto::verify(key, Domain::Request, &signing_bytes(env)?, sig)
}

/// Digest of the complete signed envelope (idempotency comparison, receipts).
pub fn envelope_digest<T: Serialize>(env: &Envelope<T>) -> Result<Digest, ProtocolError> {
    openaevc_crypto::digest_of(env)
}
#[cfg(test)]
mod tests {
    use super::*;
    use openaevc_crypto::{Signer, SigningKey};
    use openaevc_protocol::{Command, ErrorCode, Query, Timestamp, PROTOCOL_VERSION};

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
    fn digest_ignores_nothing_but_is_stable() {
        let k = SigningKey::from_seed([5; 32]);
        let a = sign_request(env(), &k).unwrap();
        let b = sign_request(env(), &k).unwrap();
        assert_eq!(envelope_digest(&a).unwrap(), envelope_digest(&b).unwrap());
        let _ = Command::NAMES;
    }
}
