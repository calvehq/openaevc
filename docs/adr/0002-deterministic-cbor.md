# 0002. Deterministic CBOR of the JSON data model

- Status: accepted
- Date: 2026-09-26

## Context

Digests and signatures need one byte-exact encoding that independent implementations reproduce.

## Decision

The canonical encoding is RFC 8949 §4.2.1 core deterministic CBOR of the value's JSON data model. Binary data is base64url text in both forms; floats, null, tags and byte strings are excluded; integers are limited to ±(2^53−1). Decoders are strict and a typed decode must re-encode to the identical bytes.

## Consequences

Every SDK computes digests with a ~100-line generic JSON→CBOR encoder, with no per-type schema knowledge. Binary payloads cost ~33% more bytes than native CBOR byte strings; changing this later requires a new protocol version.
