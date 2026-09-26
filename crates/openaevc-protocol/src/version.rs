//! Protocol versions and negotiation (spec/versioning.md).

use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The OpenAEVC protocol version implemented by this crate.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(0, 1, 0);

/// Range of protocol versions this implementation accepts.
pub const SUPPORTED_PROTOCOL: VersionRange = VersionRange::new(PROTOCOL_VERSION, PROTOCOL_VERSION);

/// A `MAJOR.MINOR.PATCH` protocol version. Pre-release/build suffixes are not part of the
/// protocol version space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ProtocolVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid protocol version {0:?}: expected MAJOR.MINOR.PATCH")]
pub struct VersionParseError(pub String);

impl FromStr for ProtocolVersion {
    type Err = VersionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || VersionParseError(s.to_owned());
        let mut parts = s.split('.');
        let mut next = || -> Result<u32, VersionParseError> {
            let p = parts.next().ok_or_else(err)?;
            let valid = !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p == "0" || !p.starts_with('0'));
            if !valid {
                return Err(err());
            }
            p.parse().map_err(|_| err())
        };
        let v = ProtocolVersion::new(next()?, next()?, next()?);
        if parts.next().is_some() {
            return Err(err());
        }
        Ok(v)
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Serialize for ProtocolVersion {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Inclusive range of protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    pub min: ProtocolVersion,
    pub max: ProtocolVersion,
}

impl VersionRange {
    pub const fn new(min: ProtocolVersion, max: ProtocolVersion) -> Self {
        Self { min, max }
    }

    pub fn contains(&self, v: ProtocolVersion) -> bool {
        self.min <= v && v <= self.max
    }

    /// Highest version supported by both ranges (spec: AEVC-VER-0003).
    pub fn negotiate(&self, other: &VersionRange) -> Option<ProtocolVersion> {
        let hi = self.max.min(other.max);
        let lo = self.min.max(other.min);
        (lo <= hi).then_some(hi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_semver() {
        let v: ProtocolVersion = "0.1.0".parse().unwrap();
        assert_eq!(v, ProtocolVersion::new(0, 1, 0));
        assert_eq!(v.to_string(), "0.1.0");
        assert!("0.1".parse::<ProtocolVersion>().is_err());
        assert!("01.1.0".parse::<ProtocolVersion>().is_err());
        assert!("0.1.0-rc1".parse::<ProtocolVersion>().is_err());
    }

    #[test]
    fn range_contains_is_inclusive() {
        let r = VersionRange::new(ProtocolVersion::new(0, 1, 0), ProtocolVersion::new(0, 2, 5));
        assert!(r.contains(ProtocolVersion::new(0, 1, 0)));
        assert!(r.contains(ProtocolVersion::new(0, 2, 5)));
        assert!(!r.contains(ProtocolVersion::new(0, 3, 0)));
    }

    #[test]
    fn negotiation_selects_highest_common_version() {
        let a = VersionRange::new(ProtocolVersion::new(0, 1, 0), ProtocolVersion::new(0, 3, 0));
        let b = VersionRange::new(ProtocolVersion::new(0, 2, 0), ProtocolVersion::new(0, 4, 0));
        assert_eq!(a.negotiate(&b), Some(ProtocolVersion::new(0, 3, 0)));
        let c = VersionRange::new(ProtocolVersion::new(1, 0, 0), ProtocolVersion::new(1, 0, 0));
        assert_eq!(a.negotiate(&c), None);
    }

    #[test]
    fn serde_uses_text_form() {
        let v = ProtocolVersion::new(0, 1, 0);
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"0.1.0\"");
        let back: ProtocolVersion = serde_json::from_str("\"0.1.0\"").unwrap();
        assert_eq!(back, v);
    }
}
