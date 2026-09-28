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

**AEVC-ID-0001** Parsers MUST accept identifiers case-insensitively (ASCII case folding only: any non-ASCII character is invalid) and MUST emit lowercase. Inside canonical objects only the lowercase form re-encodes identically, so an uppercase identifier there is rejected by AEVC-ENC-0007.

**AEVC-ID-0002** Parsers MUST reject identifiers with an unknown or wrong prefix, a wrong length, non-zero trailing pad bits, or bytes that are not a UUIDv7 (version nibble 7, RFC 9562 variant).

Typed identifiers carry identity, not integrity.

## Digests

**AEVC-ID-0003** Protocol 0.1 digests are SHA-256, written `sha256:<64 lowercase hex>`. Uppercase hex and unknown algorithm tags MUST be rejected. The algorithm tag allows later algorithms without reinterpreting existing objects.

**AEVC-ID-0004** The digest of an immutable object is SHA-256 of its exact canonical bytes (object-model.md), never of storage framing or compression.

### Digest roles

Protocol 0.1 has exactly two digests over an immutable object. There is no separate "body
digest": the body is hashed only as part of the envelope.

| Name | Preimage | Used for |
| --- | --- | --- |
| **object digest** | canonical bytes of the complete envelope, `signatures` included | object identity, CAS key, every reference from another object, event, Baseline, promotion record or API field typed `Digest`, object exchange (`GetObject`, `PUT /v1/objects/{digest}`), closure and inventory queries, SDK `digestOf(envelope)`, and the `digest` field of `fixtures/canonical/objects.json` |
| **signing digest** | canonical bytes of the envelope with `signatures` omitted | the message every object signature covers (SDK `signingDigest(envelope)`); never used as a reference |

Consequences:

- Adding, removing or replacing a signature produces a *different object* with a different
  object digest. Accepted bytes never change, so an accepted object's signature set is final.
- Every signature covers the same signing digest, independent of the other signatures, so a
  signature set has no circular dependency and signing order is irrelevant: the list has one
  canonical order (AEVC-OBJ-0006).
- Two objects with equal signing digests carry the same signed content; consumers that need
  signer-independent comparison compare signing digests, but references always name an object
  digest.

A grant digest (`parent`, revocations, authorization chains) is the object digest of the
`capability_grant` object holding the signed grant (capabilities.md). The remaining digests in
the protocol are digests *of* a value, not object identities: request-envelope digests
(idempotency, transport.md), Baseline graph digests (composition.md), event hashes (events.md),
key fingerprints, and extension artifact
digests (SHA-256 of the executable file).

## Keys and signatures

Public keys are Ed25519, written `ed25519:<unpadded base64url of 32 bytes>`; signatures are the unpadded base64url of 64 bytes. A key fingerprint is SHA-256 of the raw 32-byte key.

**AEVC-ID-0005** Every signature is computed over `"OPENAEVC/1 " || domain || "\n" || message` where `domain` is one of `request`, `grant`, `object`. A signature MUST NOT verify under a different domain. For `request` and `grant`, `message` is the canonical encoding of the unsigned value; for `object`, `message` is the 32 raw bytes of the signing digest (object-model.md). Receipts and journal checkpoints are immutable objects and are signed in the `object` domain.

**AEVC-ID-0006** Verifiers MUST use strict Ed25519 verification (reject non-canonical signatures and small-order keys) and fail closed on malformed keys or signatures.

## Timestamps and ordering

Timestamps are RFC 3339 UTC with a `Z` suffix and 0–9 fraction digits; the canonical output form has exactly nine fraction digits. Offsets other than `Z` and dates before 1970 are invalid.

**AEVC-ID-0008** Timestamps inside immutable objects MUST use the canonical nine-fraction-digit
form; objects with other spellings do not re-encode identically and are rejected. (Request
envelopes are verified over the value as transmitted, transport.md.)

**AEVC-ID-0007** Timestamps MUST NOT be the sole ordering authority. Per-Namespace event sequence numbers (events.md) are authoritative.
