# 0011. Object digest over the full envelope; signatures over a signing digest

- Status: accepted
- Date: 2026-09-28

## Context

The plan (§8.3) lists a "canonical body digest" among an immutable object's properties and says the digest is "calculated from the canonical protocol body". The implementation hashes the complete envelope (kind, version, namespace, id, sequence, creator, body and signatures) and has signatures cover the envelope without `signatures`. The two readings disagree on what is hashed, what is referenced and what is signed, and an independent implementation cannot tell which is normative.

A body-only digest cannot be the identity: two objects with equal bodies but different kinds, namespaces, creators or signatures would collide, and references would not commit to who created an object or under which protocol version. An identity that excludes signatures would let the same identity name different byte strings, breaking "accepted bytes never change" and byte-exact exchange.

## Decision

Protocol 0.1 has exactly two object digests (spec/identity-and-digests.md, "Digest roles"):

- **object digest** — SHA-256 of the canonical bytes of the complete envelope, signatures included. It is the object's identity, its CAS key, the only digest any object, event, API field or exchange operation references, and the digest SDKs compute with `digestOf(envelope)` and fixtures record as `digest`.
- **signing digest** — SHA-256 of the canonical envelope with `signatures` omitted. Each object signature is Ed25519 over `"OPENAEVC/1 object\n" || <32 raw signing-digest bytes>`. It is never used as a reference.

There is no separate body digest. `signatures` is sorted by strictly ascending raw public key (one signature per key, AEVC-OBJ-0006), so signing order cannot change the bytes. Adding or removing a signature produces a different object; since each signature covers only the signing digest, there is no circularity. Grant references (`parent`, revocations, authorization chains) are object digests of `capability_grant` objects. The unused `checkpoint` and `receipt` signature domains are removed: receipts and journal checkpoints are objects signed in the `object` domain.

## Consequences

Plan §8.3's "canonical body digest" is superseded by this ADR. Fixtures carry `signing_digest` for signed objects, an `object`-domain signature case, and negative cases for unsorted signatures, a repeated signer, a signature over the unhashed bytes and a signature in the wrong domain; every SDK checks them. Consumers that want to compare signed content independently of who signed it compare signing digests, but must still reference objects by object digest.
