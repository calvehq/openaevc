//! Public keys and signatures as protocol data (spec/identity-and-digests.md §Keys).
//!
//! Binary values use unpadded base64url text in both JSON and canonical CBOR.

use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Unpadded base64url helpers (RFC 4648 §5, no `=`).
pub mod b64 {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    pub fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(s)
    }

    /// Serde adapter for `Vec<u8>` fields.
    pub mod serde_bytes {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&super::encode(v))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            let s = std::borrow::Cow::<str>::deserialize(d)?;
            super::decode(&s).map_err(serde::de::Error::custom)
        }
    }
}

macro_rules! fixed_b64 {
    ($name:ident, $len:literal, $prefix:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const fn from_bytes(b: [u8; $len]) -> Self {
                Self(b)
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, b64::encode(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, String> {
                let err = || format!("invalid {}: {s:?}", stringify!($name));
                let body = s.strip_prefix($prefix).ok_or_else(err)?;
                let raw = b64::decode(body).map_err(|_| err())?;
                let arr: [u8; $len] = raw.try_into().map_err(|_| err())?;
                // Reject non-canonical encodings (non-zero trailing bits).
                if b64::encode(&arr) != body {
                    return Err(err());
                }
                Ok(Self(arr))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = std::borrow::Cow::<str>::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

fixed_b64!(PublicKey, 32, "ed25519:");
fixed_b64!(Signature, 64, "");

/// One signature over an object or envelope, with the key that produced it.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub public_key: PublicKey,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_text_form() {
        let k = PublicKey::from_bytes([7; 32]);
        let s = k.to_string();
        assert!(s.starts_with("ed25519:"));
        assert_eq!(s.parse::<PublicKey>().unwrap(), k);
        assert!("ed25519:AAAA".parse::<PublicKey>().is_err());
        assert!(s.replace("ed25519:", "rsa:").parse::<PublicKey>().is_err());
    }

    #[test]
    fn signature_round_trips_as_unpadded_base64url() {
        let sig = Signature::from_bytes([0xfb; 64]);
        let json = serde_json::to_string(&sig).unwrap();
        assert!(!json.contains('=') && !json.contains('+') && !json.contains('/'));
        assert_eq!(serde_json::from_str::<Signature>(&json).unwrap(), sig);
    }

    #[test]
    fn b64_rejects_padding_and_standard_alphabet() {
        assert!(b64::decode("+/8").is_err());
        assert!(b64::decode("AA==").is_err());
        assert_eq!(b64::decode(&b64::encode(b"hi")).unwrap(), b"hi");
    }
}
