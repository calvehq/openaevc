//! SHA-256 digests and Ed25519 signatures with protocol domain separation
//! (spec/identity-and-digests.md). No key storage or key-management UX lives here; hardened
//! deployments supply keys through the [`Signer`] trait.
#![forbid(unsafe_code)]

use ed25519_dalek::Signer as _;
use openaevc_protocol::{err, Digest, ProtocolError, PublicKey, Signature, SignatureEntry};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub fn sha256(bytes: &[u8]) -> Digest {
    Digest::sha256(Sha256::digest(bytes).into())
}

/// Digest of the canonical encoding of a protocol value.
pub fn digest_of<T: Serialize + ?Sized>(v: &T) -> Result<Digest, ProtocolError> {
    Ok(sha256(&openaevc_canonical::to_canonical(v)?))
}

/// Key fingerprint: SHA-256 of the raw 32-byte public key.
pub fn fingerprint(key: &PublicKey) -> Digest {
    sha256(key.as_bytes())
}

/// Signature purposes. The signed message is `"OPENAEVC/1 <domain>\n" || message`, so a
/// signature for one purpose can never be replayed as another. Receipts and journal
/// checkpoints are immutable objects and are signed in the `object` domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    Request,
    Grant,
    Object,
}

impl Domain {
    pub fn tag(&self) -> &'static str {
        match self {
            Domain::Request => "request",
            Domain::Grant => "grant",
            Domain::Object => "object",
        }
    }

    fn message(&self, msg: &[u8]) -> Vec<u8> {
        let mut m = format!("OPENAEVC/1 {}\n", self.tag()).into_bytes();
        m.extend_from_slice(msg);
        m
    }
}

/// Anything that can produce Ed25519 signatures: an in-memory key, an HSM, an OS key store.
pub trait Signer: Send + Sync {
    fn public_key(&self) -> PublicKey;
    fn sign(&self, domain: Domain, msg: &[u8]) -> Signature;
}

/// In-memory Ed25519 key.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({})", self.public_key())
    }
}

impl SigningKey {
    pub fn generate() -> Self {
        SigningKey(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// The 32-byte secret seed. Callers are responsible for protecting it.
    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl Signer for SigningKey {
    fn public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.0.verifying_key().to_bytes())
    }

    fn sign(&self, domain: Domain, msg: &[u8]) -> Signature {
        Signature::from_bytes(self.0.sign(&domain.message(msg)).to_bytes())
    }
}

/// Verifies a signature. Fails closed with `UNAUTHORIZED` on any malformed key or signature.
pub fn verify(
    key: &PublicKey,
    domain: Domain,
    msg: &[u8],
    sig: &Signature,
) -> Result<(), ProtocolError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(key.as_bytes())
        .map_err(|_| err::unauthorized("invalid public key"))?;
    let sig = ed25519_dalek::Signature::from_bytes(sig.as_bytes());
    vk.verify_strict(&domain.message(msg), &sig)
        .map_err(|_| err::unauthorized(format!("invalid {} signature", domain.tag())))?;
    // verify_strict also rejects small-order keys and non-canonical signatures.
    Ok(())
}

pub fn sign_entry(signer: &dyn Signer, domain: Domain, msg: &[u8]) -> SignatureEntry {
    SignatureEntry {
        public_key: signer.public_key(),
        signature: signer.sign(domain, msg),
    }
}

pub fn verify_entry(
    entry: &SignatureEntry,
    domain: Domain,
    msg: &[u8],
) -> Result<(), ProtocolError> {
    verify(&entry.public_key, domain, msg, &entry.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaevc_protocol::ErrorCode;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256(b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn digest_of_uses_canonical_bytes() {
        let a = serde_json::json!({"b": 1, "a": 2});
        let b = serde_json::json!({"a": 2, "b": 1});
        assert_eq!(digest_of(&a).unwrap(), digest_of(&b).unwrap());
    }

    #[test]
    fn rfc8032_test_vector_1_public_key() {
        let seed = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let key = SigningKey::from_seed(seed);
        assert_eq!(
            key.public_key().as_bytes(),
            &hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
    }

    #[test]
    fn sign_and_verify_with_domain_separation() {
        let key = SigningKey::generate();
        let sig = key.sign(Domain::Request, b"payload");
        verify(&key.public_key(), Domain::Request, b"payload", &sig).unwrap();
        let e = verify(&key.public_key(), Domain::Grant, b"payload", &sig).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);
        assert!(verify(&key.public_key(), Domain::Request, b"payloaD", &sig).is_err());
        let other = SigningKey::generate();
        assert!(verify(&other.public_key(), Domain::Request, b"payload", &sig).is_err());
    }

    #[test]
    fn fingerprint_is_digest_of_raw_key() {
        let key = SigningKey::from_seed([1; 32]);
        assert_eq!(
            fingerprint(&key.public_key()),
            sha256(key.public_key().as_bytes())
        );
    }

    #[test]
    fn signer_trait_object_works() {
        let key = SigningKey::generate();
        let signer: &dyn Signer = &key;
        let entry = sign_entry(signer, Domain::Object, b"m");
        verify_entry(&entry, Domain::Object, b"m").unwrap();
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
