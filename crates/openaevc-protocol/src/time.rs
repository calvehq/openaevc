//! UTC timestamps (RFC 3339, nanosecond precision) and sequence numbers.
//!
//! Canonical text form: `YYYY-MM-DDTHH:MM:SS.fffffffffZ` (always nine fraction digits, `Z`).
//! Parsing accepts 0–9 fraction digits and only the `Z` offset. Timestamps are informative;
//! event sequence numbers are the authoritative ordering.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Namespace-local monotonically increasing event sequence number (starts at 1).
pub type Sequence = u64;

const NANOS_PER_SEC: i128 = 1_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i128);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid timestamp {0:?}: expected RFC 3339 UTC (YYYY-MM-DDTHH:MM:SS[.f]Z)")]
pub struct TimestampParseError(pub String);

// Howard Hinnant's civil-date algorithms.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

impl Timestamp {
    pub const UNIX_EPOCH: Timestamp = Timestamp(0);

    pub fn from_unix_nanos(nanos: i128) -> Self {
        Timestamp(nanos)
    }

    pub fn unix_nanos(&self) -> i128 {
        self.0
    }

    pub fn plus_millis(&self, ms: u64) -> Self {
        Timestamp(self.0 + i128::from(ms) * 1_000_000)
    }

    /// Milliseconds from `self` to `later` (negative if `later` is earlier).
    pub fn millis_until(&self, later: Timestamp) -> i128 {
        (later.0 - self.0) / 1_000_000
    }
}

impl FromStr for Timestamp {
    type Err = TimestampParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || TimestampParseError(s.to_owned());
        let b = s.as_bytes();
        if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':'
            || b[16] != b':' || *b.last().ok_or_else(err)? != b'Z'
        {
            return Err(err());
        }
        let num = |r: std::ops::Range<usize>| -> Result<u32, TimestampParseError> {
            let part = &s[r];
            if !part.bytes().all(|c| c.is_ascii_digit()) {
                return Err(err());
            }
            part.parse().map_err(|_| err())
        };
        let (y, mo, d) = (i64::from(num(0..4)?), num(5..7)?, num(8..10)?);
        let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
        let frac = &s[19..s.len() - 1];
        let nanos = if frac.is_empty() {
            0
        } else {
            let digits = frac.strip_prefix('.').ok_or_else(err)?;
            if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return Err(err());
            }
            let n: i128 = digits.parse().map_err(|_| err())?;
            n * 10i128.pow(9 - digits.len() as u32)
        };
        if y < 1970 || !(1..=12).contains(&mo) || d == 0 || d > days_in_month(y, mo) || h > 23
            || mi > 59 || sec > 59
        {
            return Err(err());
        }
        let days = i128::from(days_from_civil(y, mo, d));
        let secs = days * 86_400 + i128::from(h * 3600 + mi * 60 + sec);
        Ok(Timestamp(secs * NANOS_PER_SEC + nanos))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.div_euclid(NANOS_PER_SEC);
        let nanos = self.0.rem_euclid(NANOS_PER_SEC);
        let days = secs.div_euclid(86_400) as i64;
        let sod = secs.rem_euclid(86_400) as u32;
        let (y, m, d) = civil_from_days(days);
        write!(
            f,
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{nanos:09}Z",
            sod / 3600,
            sod / 60 % 60,
            sod % 60
        )
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = std::borrow::Cow::<str>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_has_nine_fraction_digits() {
        let t = Timestamp::from_unix_nanos(1_700_000_000_123_000_000);
        assert_eq!(t.to_string(), "2023-11-14T22:13:20.123000000Z");
    }

    #[test]
    fn parses_rfc3339_utc_variants() {
        let t: Timestamp = "2023-11-14T22:13:20Z".parse().unwrap();
        assert_eq!(t.unix_nanos(), 1_700_000_000_000_000_000);
        let t: Timestamp = "2023-11-14T22:13:20.5Z".parse().unwrap();
        assert_eq!(t.unix_nanos(), 1_700_000_000_500_000_000);
        let t: Timestamp = "1970-01-01T00:00:00Z".parse().unwrap();
        assert_eq!(t.unix_nanos(), 0);
        let t: Timestamp = "2000-02-29T00:00:00Z".parse().unwrap();
        assert_eq!(t.to_string(), "2000-02-29T00:00:00.000000000Z");
    }

    #[test]
    fn rejects_offsets_bad_dates_and_garbage() {
        for bad in [
            "2023-11-14T22:13:20+01:00",
            "2023-02-30T00:00:00Z",
            "2023-11-14 22:13:20Z",
            "2023-11-14T22:13:20.1234567890Z",
            "2023-11-14T24:00:00Z",
            "1969-12-31T23:59:59Z",
            "",
        ] {
            assert!(bad.parse::<Timestamp>().is_err(), "{bad}");
        }
    }

    #[test]
    fn arithmetic_and_ordering() {
        let t = Timestamp::from_unix_nanos(1_000);
        assert!(t.plus_millis(1) > t);
        assert_eq!(t.plus_millis(1).unix_nanos(), 1_001_000);
    }
}
