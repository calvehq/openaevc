# Identity and Digests

## Typed identifiers

A typed identifier is `<prefix>_<base32>` where `<base32>` is the RFC 4648 base32 encoding (alphabet `a–z2–7`, lowercase, no padding, 26 characters) of the 16 bytes of a UUIDv7.

| Prefix | Identifies          | Prefix | Identifies        |
| ------ | ------------------- | ------ | ----------------- |
| `ns`   | Namespace           | `evl`  | Evaluation result |
| `pri`  | Principal           | `pro`  | Promotion record  |
| `grt`  | Capability grant    | `bsl`  | Baseline          |
| `cpk`  | ChangePack          | `evt`  | Journal event     |
| `rpk`  | RevisionPack        | `wku`  | WorkUnit          |
| `exe`  | Execution           | `lse`  | Execution lease   |
| `obs`  | Observation         | `req`  | Request           |
| `evd`  | Evidence            | `eff`  | Applied effect    |
| `vrf`  | Verification result | `rti`  | Runtime instance  |

Extensions are identified by reverse-DNS names (`org.example.kv`), not typed IDs.

**AEVC-ID-0001** Parsers MUST accept identifiers case-insensitively and MUST emit lowercase.

**AEVC-ID-0002** Parsers MUST reject identifiers with an unknown or wrong prefix, a wrong length, non-zero trailing pad bits, or bytes that are not a UUIDv7 (version nibble 7, RFC 9562 variant).

Typed identifiers carry identity, not integrity.

## Digests

**AEVC-ID-0003** Protocol 0.1 digests are SHA-256, written `sha256:<64 lowercase hex>`. Uppercase hex and unknown algorithm tags MUST be rejected. The algorithm tag allows later algorithms without reinterpreting existing objects.

**AEVC-ID-0004** The digest of an immutable object is SHA-256 of its exact canonical bytes (object-model.md), never of storage framing or compression.

## Keys and signatures

Public keys are Ed25519, written `ed25519:<unpadded base64url of 32 bytes>`; signatures are the unpadded base64url of 64 bytes. A key fingerprint is SHA-256 of the raw 32-byte key.

**AEVC-ID-0005** Every signature is computed over `"OPENAEVC/1 " || domain || "\n" || message` where `domain` is one of `request`, `grant`, `object`, `checkpoint`, `receipt`. A signature MUST NOT verify under a different domain.

**AEVC-ID-0006** Verifiers MUST use strict Ed25519 verification (reject non-canonical signatures and small-order keys) and fail closed on malformed keys or signatures.

## Timestamps and ordering

Timestamps are RFC 3339 UTC with a `Z` suffix and 0–9 fraction digits; the canonical output form has exactly nine fraction digits. Offsets other than `Z` and dates before 1970 are invalid.

**AEVC-ID-0008** Timestamps inside canonical or signed values (objects and request envelopes) MUST
use the canonical nine-fraction-digit form; other spellings do not re-encode identically and are
rejected.

**AEVC-ID-0007** Timestamps MUST NOT be the sole ordering authority. Per-Namespace event sequence numbers (events.md) are authoritative.
