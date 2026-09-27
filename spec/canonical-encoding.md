# Canonical Encoding

## Data model

Every protocol value has one JSON representation (defined by `schemas/json/openaevc.schema.json`) and one canonical binary representation. Both share the same data model:

- maps with text keys, arrays, text strings, booleans and integers;
- binary values are unpadded base64url text (RFC 4648 §5);
- digests, identifiers, keys, versions and timestamps use their textual forms.

**AEVC-ENC-0001** Canonical objects MUST NOT contain floating-point numbers, `null`, `undefined`, byte strings, tags or non-text map keys.

**AEVC-ENC-0002** Integers in canonical objects MUST lie within ±(2^53 − 1). Implementations MUST reject values outside this range on encode and decode.

**AEVC-ENC-0003** Absent optional fields MUST be omitted, never encoded as `null`. Empty optional collections that a schema marks as optional MUST be omitted.

## Deterministic CBOR

**AEVC-ENC-0004** The canonical encoding of a value MUST be RFC 8949 §4.2.1 core deterministic CBOR of its data-model form:

- integers and lengths use the shortest possible argument;
- all items have definite length;
- map entries are sorted by the bytewise lexicographic order of their encoded keys (for text keys this is shorter-key-first, then bytewise), with no duplicate keys.

**AEVC-ENC-0005** Decoders MUST reject any input that is not in canonical form, including non-shortest arguments, indefinite lengths, unsorted or duplicate keys, trailing bytes, invalid UTF-8, and nesting deeper than 128 levels.

**AEVC-ENC-0006** Text MUST be valid UTF-8 and is compared and hashed byte-for-byte. Implementations MUST NOT apply Unicode normalization.

**AEVC-ENC-0007** Decoding a canonical object into a protocol type MUST fail when re-encoding the decoded value does not reproduce the input bytes exactly. Unknown fields in signed or canonical objects are therefore rejected unless a schema declares a namespaced extension map.

Namespaced extension maps (`metadata`, `intent`, `annotations`) are explicitly part of the canonical encoding; their keys MUST be namespaced names (namespace.md).

## JSON representation

JSON is a transport and diagnostic representation, never the digest representation.

**AEVC-ENC-0008** A JSON value is converted to canonical bytes by applying this document's data model rules to it directly. Two JSON documents that differ only in key order or whitespace MUST produce identical canonical bytes.

Diagnostic canonical JSON (used by `openaevc-inspect canonicalize`) orders keys the same way as CBOR and contains no insignificant whitespace.

## Schemas and fixtures

`schemas/json/openaevc.schema.json` (JSON Schema 2020-12) and `schemas/cddl/openaevc.cddl` (RFC 8610) are generated from the reference types and checked in. `fixtures/canonical/` contains golden values: source JSON, canonical CBOR hex, SHA-256 digest, and invalid encodings. Every SDK tests against these files.
