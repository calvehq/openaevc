//! Deterministic CBOR canonical encoding (spec/canonical-encoding.md).
//!
//! The canonical data model is the JSON data model of a protocol value with these
//! restrictions: no floats, no `null`, integers within ±(2^53 − 1), map keys are text.
//! Values are encoded as RFC 8949 §4.2.1 core deterministic CBOR:
//!
//! * shortest-form integer and length arguments;
//! * definite lengths only;
//! * map keys sorted by the bytewise order of their encodings, no duplicates;
//! * no tags, floats, `null`, `undefined` or byte strings (binary values are carried as
//!   unpadded base64url text, exactly as in JSON).
//!
//! Text is compared and hashed byte-for-byte; no Unicode normalization is applied.
//! Decoding is strict: any input that would not re-encode to the same bytes is rejected.
#![forbid(unsafe_code)]

use crate::protocol::{ErrorCode, ProtocolError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Number, Value};

/// Largest magnitude of an integer in a canonical object (JavaScript safe integer range).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
/// Maximum nesting depth accepted by the decoder.
pub const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    #[error("floating-point values are not permitted in canonical objects")]
    Float,
    #[error("null is not permitted in canonical objects; omit absent optional fields")]
    Null,
    #[error("integer outside the canonical range ±(2^53-1)")]
    IntegerRange,
    #[error("unexpected end of input")]
    Truncated,
    #[error("trailing bytes after canonical value")]
    TrailingBytes,
    #[error("non-shortest encoding of an integer or length")]
    NonShortest,
    #[error("indefinite-length items are not permitted")]
    Indefinite,
    #[error("map keys are not in canonical order or are duplicated")]
    KeyOrder,
    #[error("map keys must be text strings")]
    NonTextKey,
    #[error("CBOR major type or simple value {0:#04x} is not permitted")]
    Unsupported(u8),
    #[error("text string is not valid UTF-8")]
    Utf8,
    #[error("nesting deeper than {MAX_DEPTH} levels")]
    TooDeep,
    #[error("value does not match the expected protocol type: {0}")]
    Schema(String),
    #[error("value is not in canonical form for its protocol type")]
    NotCanonical,
}

impl From<CanonicalError> for ProtocolError {
    fn from(e: CanonicalError) -> Self {
        ProtocolError::new(ErrorCode::CanonicalEncodingError, e.to_string())
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend([m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend((n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend((n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend(n.to_be_bytes());
    }
}

fn encode_into(v: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match v {
        Value::Null => return Err(CanonicalError::Null),
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Number(n) => encode_number(n, out)?,
        Value::String(s) => {
            head(out, 3, s.len() as u64);
            out.extend(s.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out)?;
            }
        }
        Value::Object(map) => {
            let mut entries = Vec::with_capacity(map.len());
            for (k, val) in map {
                let mut key = Vec::with_capacity(k.len() + 2);
                head(&mut key, 3, k.len() as u64);
                key.extend(k.as_bytes());
                entries.push((key, val));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            head(out, 5, entries.len() as u64);
            for (key, val) in entries {
                out.extend(key);
                encode_into(val, out)?;
            }
        }
    }
    Ok(())
}

fn encode_number(n: &Number, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER {
            return Err(CanonicalError::IntegerRange);
        }
        head(out, 0, u);
    } else if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(CanonicalError::IntegerRange);
        }
        head(out, 1, (-1 - i) as u64);
    } else {
        return Err(CanonicalError::Float);
    }
    Ok(())
}

/// Encodes a JSON-model value as deterministic CBOR.
pub fn encode(v: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    encode_into(v, &mut out)?;
    Ok(out)
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CanonicalError> {
        let end = self.pos.checked_add(n).ok_or(CanonicalError::Truncated)?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(CanonicalError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn argument(&mut self, info: u8) -> Result<u64, CanonicalError> {
        let (n, min) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => (
                u64::from(u16::from_be_bytes(
                    self.take(2)?.try_into().unwrap_or_default(),
                )),
                0x100,
            ),
            26 => (
                u64::from(u32::from_be_bytes(
                    self.take(4)?.try_into().unwrap_or_default(),
                )),
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap_or_default()),
                0x1_0000_0000,
            ),
            31 => return Err(CanonicalError::Indefinite),
            _ => return Err(CanonicalError::Unsupported(info)),
        };
        if n < min {
            return Err(CanonicalError::NonShortest);
        }
        Ok(n)
    }

    fn length(&mut self, info: u8) -> Result<usize, CanonicalError> {
        let n = self.argument(info)?;
        // A length can never exceed the remaining input (each item is at least one byte).
        if n > (self.buf.len() - self.pos) as u64 {
            return Err(CanonicalError::Truncated);
        }
        Ok(n as usize)
    }

    fn text(&mut self, info: u8) -> Result<String, CanonicalError> {
        let len = self.length(info)?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CanonicalError::Utf8)
    }

    fn value(&mut self, depth: usize) -> Result<Value, CanonicalError> {
        if depth > MAX_DEPTH {
            return Err(CanonicalError::TooDeep);
        }
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        match major {
            0 => {
                let n = self.argument(info)?;
                if n > MAX_SAFE_INTEGER {
                    return Err(CanonicalError::IntegerRange);
                }
                Ok(Value::from(n))
            }
            1 => {
                let n = self.argument(info)?;
                if n >= MAX_SAFE_INTEGER {
                    return Err(CanonicalError::IntegerRange);
                }
                Ok(Value::from(-1 - n as i64))
            }
            3 => Ok(Value::String(self.text(info)?)),
            4 => {
                let len = self.length(info)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let len = self.length(info)?;
                let mut map = Map::new();
                let mut prev: Option<&[u8]> = None;
                for _ in 0..len {
                    let start = self.pos;
                    let key_initial = self.take(1)?[0];
                    if key_initial >> 5 != 3 {
                        return Err(CanonicalError::NonTextKey);
                    }
                    let key = self.text(key_initial & 0x1f)?;
                    let key_bytes = &self.buf[start..self.pos];
                    if prev.is_some_and(|p| p >= key_bytes) {
                        return Err(CanonicalError::KeyOrder);
                    }
                    prev = Some(key_bytes);
                    let val = self.value(depth + 1)?;
                    map.insert(key, val);
                }
                Ok(Value::Object(map))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Err(CanonicalError::Null),
                25..=27 => Err(CanonicalError::Float),
                31 => Err(CanonicalError::Indefinite),
                _ => Err(CanonicalError::Unsupported(initial)),
            },
            _ if info == 31 => Err(CanonicalError::Indefinite),
            _ => Err(CanonicalError::Unsupported(initial)),
        }
    }
}

/// Strictly decodes canonical CBOR into a JSON-model value.
pub fn decode(bytes: &[u8]) -> Result<Value, CanonicalError> {
    let mut d = Decoder { buf: bytes, pos: 0 };
    let v = d.value(0)?;
    if d.pos != bytes.len() {
        return Err(CanonicalError::TrailingBytes);
    }
    Ok(v)
}

/// Converts a protocol value to its JSON-model form.
pub fn to_value<T: Serialize + ?Sized>(v: &T) -> Result<Value, CanonicalError> {
    serde_json::to_value(v).map_err(|e| CanonicalError::Schema(e.to_string()))
}

/// Canonical bytes of a protocol value.
pub fn to_canonical<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>, CanonicalError> {
    encode(&to_value(v)?)
}

/// Decodes canonical bytes into a protocol type. The decoded value is re-encoded and must
/// reproduce the input exactly, so fields a type would ignore or default can never hide
/// inside a digest.
pub fn from_canonical<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T, CanonicalError> {
    let v: T = from_value(decode(bytes)?)?;
    if to_canonical(&v)? != bytes {
        return Err(CanonicalError::NotCanonical);
    }
    Ok(v)
}

/// Decodes a JSON-model value into a protocol type, requiring that it re-serializes to the
/// same value (same rule as [`from_canonical`], for JSON transport input).
pub fn from_value<T: Serialize + DeserializeOwned>(v: Value) -> Result<T, CanonicalError> {
    let t: T =
        serde_json::from_value(v.clone()).map_err(|e| CanonicalError::Schema(e.to_string()))?;
    if encode(&to_value(&t)?)? != encode(&v)? {
        return Err(CanonicalError::NotCanonical);
    }
    Ok(t)
}

/// Canonical JSON text of a value: keys sorted in canonical (CBOR key) order, no whitespace.
/// Diagnostic only; digests are always computed over CBOR.
pub fn canonical_json(v: &Value) -> Result<String, CanonicalError> {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
                Value::Object(keys.into_iter().map(|k| (k.clone(), sort(&m[k]))).collect())
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    encode(v)?;
    serde_json::to_string(&sort(v)).map_err(|e| CanonicalError::Schema(e.to_string()))
}
