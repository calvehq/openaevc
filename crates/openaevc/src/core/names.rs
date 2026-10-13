//! Namespaced name validation (spec/namespace.md §Names).
//!
//! A namespaced name is two or more dot-separated lowercase segments, optionally followed by
//! `/`-separated path segments: `kv.entry`, `org.example.kv/size`. Segments use `[a-z0-9]`
//! with inner `-`/`_`, and must start and end alphanumeric. Maximum length 128 bytes.

use crate::protocol::{err, ProtocolError};

pub const MAX_NAME_LEN: usize = 128;

fn segment_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
}

fn path_segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

pub fn is_namespaced(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    let mut parts = name.split('/');
    let head = parts.next().unwrap_or_default();
    let dotted: Vec<&str> = head.split('.').collect();
    dotted.len() >= 2 && dotted.iter().all(|s| segment_ok(s)) && parts.all(path_segment_ok)
}

pub fn validate_namespaced(name: &str) -> Result<(), ProtocolError> {
    if is_namespaced(name) {
        Ok(())
    } else {
        Err(err::invalid(format!(
            "{name:?} is not a namespaced name (e.g. org.example.thing)"
        )))
    }
}

/// Validates every key of a metadata/extension map.
pub fn validate_keys<'a, V: 'a>(
    map: impl IntoIterator<Item = (&'a String, V)>,
) -> Result<(), ProtocolError> {
    map.into_iter()
        .try_for_each(|(k, _)| validate_namespaced(k))
}

/// Reverse-DNS extension identifier: a namespaced name without a path part.
pub fn validate_extension_id(id: &str) -> Result<(), ProtocolError> {
    if !id.contains('/') && is_namespaced(id) {
        Ok(())
    } else {
        Err(err::invalid(format!(
            "{id:?} is not a reverse-DNS extension id"
        )))
    }
}

/// SemVer 2.0 version (pre-release/build allowed).
pub fn validate_semver(v: &str) -> Result<(), ProtocolError> {
    let bad = || err::invalid(format!("{v:?} is not a SemVer version"));
    let core = v.split(['-', '+']).next().ok_or_else(bad)?;
    let rest = &v[core.len()..];
    let nums: Vec<&str> = core.split('.').collect();
    let num_ok = |n: &&str| {
        !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) && (*n == "0" || !n.starts_with('0'))
    };
    if nums.len() != 3 || !nums.iter().all(num_ok) {
        return Err(bad());
    }
    let tail_ok = rest.is_empty()
        || (rest.len() > 1
            && rest[1..]
                .split(['.', '+', '-'])
                .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric())));
    if !tail_ok {
        return Err(bad());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_dotted_lowercase_names() {
        for ok in [
            "kv.entry",
            "org.example.kv/size",
            "verification.kv.expect.status",
            "a.b_c-d",
            "x1.y2",
        ] {
            assert!(validate_namespaced(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn rejects_unqualified_or_malformed_names() {
        for bad in [
            "kv",
            "",
            "Kv.entry",
            ".kv",
            "kv.",
            "kv..entry",
            "kv.entry/",
            "kv entry.x",
            "kv.-x",
            &"a.b".repeat(100),
        ] {
            assert!(validate_namespaced(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reverse_dns_extension_ids() {
        assert!(validate_extension_id("org.openaevc.reference.kv").is_ok());
        assert!(validate_extension_id("org.openaevc/kv").is_err());
        assert!(validate_extension_id("kv").is_err());
    }

    #[test]
    fn semver_versions() {
        assert!(validate_semver("1.2.3").is_ok());
        assert!(validate_semver("1.2.3-rc.1").is_ok());
        assert!(validate_semver("1.2").is_err());
        assert!(validate_semver("01.2.3").is_err());
    }
}
