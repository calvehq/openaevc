//! Algorithm-tagged content digests: `sha256:<64 lowercase hex>` (spec/identity-and-digests.md).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Digest algorithms. Protocol 0.1 defines only SHA-256; the tag lets a later protocol add
/// algorithms without reinterpreting existing objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestAlgorithm {
    Sha256,
}

impl DigestAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            DigestAlgorithm::Sha256 => "sha256",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest {
    alg: DigestAlgorithm,
    bytes: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid digest {0:?}: expected sha256:<64 lowercase hex>")]
pub struct DigestParseError(pub String);

impl Digest {
    /// All-zero SHA-256 value; the genesis `previous_event_hash` of a journal.
    pub const ZERO: Digest = Digest { alg: DigestAlgorithm::Sha256, bytes: [0; 32] };

    pub const fn sha256(bytes: [u8; 32]) -> Self {
        Self { alg: DigestAlgorithm::Sha256, bytes }
    }

    pub fn algorithm(&self) -> DigestAlgorithm {
        self.alg
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Lowercase hex of the digest bytes (no algorithm tag).
    pub fn hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl FromStr for Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || DigestParseError(s.to_owned());
        let hex = s.strip_prefix("sha256:").ok_or_else(err)?;
        if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(err());
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let h = std::str::from_utf8(chunk).map_err(|_| err())?;
            bytes[i] = u8::from_str_radix(h, 16).map_err(|_| err())?;
        }
        Ok(Digest::sha256(bytes))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.alg.as_str(), self.hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = std::borrow::Cow::<str>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_round_trips() {
        let d = Digest::sha256([0xab; 32]);
        let s = d.to_string();
        assert_eq!(s, format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(s.parse::<Digest>().unwrap(), d);
    }

    #[test]
    fn rejects_uppercase_unknown_alg_and_bad_length() {
        assert!(format!("sha256:{}", "AB".repeat(32)).parse::<Digest>().is_err());
        assert!(format!("sha512:{}", "ab".repeat(32)).parse::<Digest>().is_err());
        assert!(format!("sha256:{}", "ab".repeat(31)).parse::<Digest>().is_err());
        assert!("ab".parse::<Digest>().is_err());
    }

    #[test]
    fn zero_digest_is_genesis() {
        assert_eq!(Digest::ZERO.to_string(), format!("sha256:{}", "0".repeat(64)));
    }
}
