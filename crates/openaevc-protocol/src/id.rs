//! Typed opaque identifiers: `<prefix>_<base32(uuidv7)>` (spec/identity-and-digests.md).
//!
//! The 16 UUIDv7 bytes are encoded with the RFC 4648 base32 alphabet, lowercase, without
//! padding (26 characters; the 2 trailing pad bits MUST be zero). Parsing is case-insensitive;
//! output is always lowercase. Typed IDs are identity, not integrity.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const ENCODED_LEN: usize = 26;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {expected} identifier {input:?}: {reason}")]
pub struct IdParseError {
    pub expected: &'static str,
    pub input: String,
    pub reason: &'static str,
}

fn encode(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(ENCODED_LEN);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn decode(s: &str) -> Result<[u8; 16], &'static str> {
    if s.len() != ENCODED_LEN {
        return Err("expected 26 base32 characters");
    }
    let mut out = [0u8; 16];
    let (mut acc, mut bits, mut i) = (0u32, 0, 0);
    for c in s.bytes() {
        let v = match c.to_ascii_lowercase() {
            c @ b'a'..=b'z' => c - b'a',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return Err("invalid base32 character"),
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[i] = (acc >> bits) as u8;
            i += 1;
        }
    }
    if acc & ((1 << bits) - 1) != 0 {
        return Err("non-zero trailing bits");
    }
    Ok(out)
}

fn check_uuidv7(b: &[u8; 16]) -> Result<(), &'static str> {
    if b[6] >> 4 != 7 {
        return Err("not a UUIDv7");
    }
    if b[8] >> 6 != 0b10 {
        return Err("invalid UUID variant");
    }
    Ok(())
}

macro_rules! typed_ids {
    ($($(#[$doc:meta])* $name:ident => $prefix:literal,)*) => {
        $(
            $(#[$doc])*
            #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name([u8; 16]);

            impl $name {
                pub const PREFIX: &'static str = $prefix;

                /// Builds an ID from raw UUIDv7 bytes, rejecting other UUID versions.
                pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, IdParseError> {
                    check_uuidv7(&bytes).map_err(|reason| IdParseError {
                        expected: $prefix,
                        input: encode(&bytes),
                        reason,
                    })?;
                    Ok(Self(bytes))
                }

                pub fn as_bytes(&self) -> &[u8; 16] {
                    &self.0
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "{}_{}", $prefix, encode(&self.0))
                }
            }

            impl fmt::Debug for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    fmt::Display::fmt(self, f)
                }
            }

            impl FromStr for $name {
                type Err = IdParseError;

                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    let err = |reason| IdParseError { expected: $prefix, input: s.to_owned(), reason };
                    let rest = s
                        .strip_prefix(concat!($prefix, "_"))
                        .ok_or_else(|| err("wrong prefix"))?;
                    let bytes = decode(rest).map_err(err)?;
                    check_uuidv7(&bytes).map_err(err)?;
                    Ok(Self(bytes))
                }
            }

            impl schemars::JsonSchema for $name {
                fn schema_name() -> std::borrow::Cow<'static, str> {
                    stringify!($name).into()
                }

                fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                    schemars::json_schema!({
                        "type": "string",
                        "pattern": concat!("^", $prefix, "_[a-z2-7]{26}$"),
                        "description": concat!("Typed identifier: ", $prefix, "_ + base32(UUIDv7).")
                    })
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
        )*

        /// Any typed identifier, for fields that may reference objects of several kinds.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum AnyId {
            $($name($name),)*
        }

        impl AnyId {
            pub fn prefix(&self) -> &'static str {
                match self {
                    $(AnyId::$name(_) => $prefix,)*
                }
            }
        }

        impl fmt::Display for AnyId {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(AnyId::$name(id) => fmt::Display::fmt(id, f),)*
                }
            }
        }

        impl fmt::Debug for AnyId {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl FromStr for AnyId {
            type Err = IdParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let prefix = s.split('_').next().unwrap_or_default();
                match prefix {
                    $($prefix => s.parse().map(AnyId::$name),)*
                    _ => Err(IdParseError { expected: "typed", input: s.to_owned(), reason: "unknown prefix" }),
                }
            }
        }

        $(
            impl From<$name> for AnyId {
                fn from(id: $name) -> Self {
                    AnyId::$name(id)
                }
            }
        )*

        impl Serialize for AnyId {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for AnyId {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = std::borrow::Cow::<str>::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

typed_ids! {
    /// Top-level isolation scope.
    NamespaceId => "ns",
    /// Authenticated principal.
    PrincipalId => "pri",
    /// Capability grant.
    GrantId => "grt",
    /// ChangePack (pre-promotion mutable work).
    ChangePackId => "cpk",
    /// RevisionPack (change that amends, supersedes or reverts promoted packs).
    RevisionPackId => "rpk",
    /// Execution attempt.
    ExecutionId => "exe",
    /// Observation.
    ObservationId => "obs",
    /// Evidence.
    EvidenceId => "evd",
    /// Verification result.
    VerificationId => "vrf",
    /// Evaluation result.
    EvaluationId => "evl",
    /// Promotion record.
    PromotionId => "pro",
    /// Baseline.
    BaselineId => "bsl",
    /// Journal event.
    EventId => "evt",
    /// Work unit inside a pack.
    WorkUnitId => "wku",
    /// Execution lease.
    LeaseId => "lse",
    /// Command/query request.
    RequestId => "req",
    /// Effect proposal.
    EffectId => "eff",
    /// Runtime instance.
    RuntimeInstanceId => "rti",
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: [u8; 16] = [
        0x01, 0x92, 0x3a, 0x4b, 0x5c, 0x6d, 0x70, 0x01, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77,
    ];

    #[test]
    fn formats_lowercase_base32_with_prefix() {
        let id = ChangePackId::from_bytes(RAW).unwrap();
        let s = id.to_string();
        assert!(s.starts_with("cpk_"));
        assert_eq!(s.len(), 4 + 26);
        assert_eq!(s, s.to_lowercase());
    }

    #[test]
    fn parse_is_case_insensitive_and_round_trips() {
        let id = NamespaceId::from_bytes(RAW).unwrap();
        let upper = id.to_string().to_uppercase().replacen("NS_", "ns_", 1);
        assert_eq!(upper.parse::<NamespaceId>().unwrap(), id);
    }

    #[test]
    fn rejects_wrong_prefix_length_and_non_v7() {
        let id = ChangePackId::from_bytes(RAW).unwrap().to_string();
        assert!(id.replacen("cpk_", "rpk_", 1).parse::<ChangePackId>().is_err());
        assert!(id[..id.len() - 1].parse::<ChangePackId>().is_err());
        let mut v4 = RAW;
        v4[6] = 0x40;
        assert!(ChangePackId::from_bytes(v4).is_err());
        let mut bad_variant = RAW;
        bad_variant[8] = 0x00;
        assert!(ChangePackId::from_bytes(bad_variant).is_err());
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        // 128 bits in 26 base32 chars leaves 2 padding bits that must be zero.
        let id = ChangePackId::from_bytes(RAW).unwrap().to_string();
        let last = id.chars().last().unwrap();
        let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        let pos = alphabet.find(last).unwrap();
        let tweaked = alphabet.chars().nth(pos ^ 1).unwrap();
        let bad = format!("{}{}", &id[..id.len() - 1], tweaked);
        assert!(bad.parse::<ChangePackId>().is_err());
    }

    #[test]
    fn serde_uses_text_form() {
        let id = ExecutionId::from_bytes(RAW).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<ExecutionId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<ExecutionId>("\"exe_zz\"").is_err());
    }

    #[test]
    fn any_id_reports_kind() {
        let id = BaselineId::from_bytes(RAW).unwrap();
        let any: AnyId = id.to_string().parse().unwrap();
        assert_eq!(any.prefix(), "bsl");
    }
}
