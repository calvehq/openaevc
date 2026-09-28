# Object Model

OpenAEVC keeps three state layers that MUST NOT collapse into one another:

1. **Immutable Object Store** — canonical immutable protocol objects (this document).
2. **Accepted Composition** — immutable Baselines referencing promoted objects (baseline.md).
3. **Active Change Graph** — mutable work in progress (active-change-graph.md).

## Envelope

Every immutable object is an envelope:

| Field              | Meaning                                                    |
| ------------------ | ---------------------------------------------------------- |
| `kind`             | Object kind (table below).                                 |
| `protocol_version` | Protocol version the object was created under.             |
| `namespace`        | Namespace that created the object.                         |
| `id`               | Optional logical typed ID.                                 |
| `created_seq`      | Namespace event sequence of the creating event.            |
| `creator`          | Principal that created the object.                         |
| `body`             | Kind-specific body.                                        |
| `signatures`       | Optional sorted, unique list of `{public_key, signature}`. |

**AEVC-OBJ-0001** An object's canonical bytes are the canonical encoding of the complete envelope, including signatures. Once created, those bytes MUST never change. The _object digest_ (SHA-256 of those bytes) is the object's identity and the only digest by which anything references it (identity-and-digests.md, "Digest roles").

**AEVC-OBJ-0002** Object signatures cover the _signing digest_: SHA-256 of the canonical envelope with `signatures` omitted. Each signature is Ed25519 over `"OPENAEVC/1 object\n" || <32 raw signing-digest bytes>`. Every present signature MUST verify before the object is accepted.

**AEVC-OBJ-0006** `signatures` MUST be sorted by strictly ascending raw 32-byte public key, so it holds at most one signature per key. An implementation MUST reject an unsorted list or a repeated key (`CANONICAL_ENCODING_ERROR`); this check precedes signature verification. An empty list is omitted.

**AEVC-OBJ-0003** An implementation MUST reject an object whose body does not decode strictly into the schema of its `kind`, whose kind is unknown, or whose `protocol_version` it does not support (`PROTOCOL_VERSION_UNSUPPORTED`).

Rejection codes for object bytes, checked in this order: bytes that do not hash to the claimed digest, `DIGEST_MISMATCH`; bytes that are not canonical CBOR, or an envelope with an unknown field, a missing field or an unknown `kind` (the envelope is part of the canonical form), `CANONICAL_ENCODING_ERROR`; an unsupported `protocol_version`, `PROTOCOL_VERSION_UNSUPPORTED`; a body that does not decode strictly into its kind's schema (including unknown body fields and non-canonical timestamps), `INVALID_ARGUMENT`; an unsorted or repeated-key signature list, `CANONICAL_ENCODING_ERROR` (AEVC-OBJ-0006); a signature that does not verify, `UNAUTHORIZED`.

## Kinds

| Kind | Body | Direct references (closure edges) |
| --- | --- | --- |
| `blob` | `media_type`, base64url `data` | — |
| `capability_grant` | signed grant | parent grant |
| `revocation` | revoked grant | grant |
| `policy_document` | rules | — |
| `policy_decision` | evaluated gates | policies |
| `extension_manifest` | manifest | — |
| `candidate` | frozen applied effects | grants, inputs and extension manifests in provenance |
| `observation` | execution observation | blob, provenance grants/inputs/manifest |
| `evidence` | candidate-bound evidence | payload blob, extension manifest |
| `verification_result` | verifier result | evidence, extension manifest |
| `evaluation_result` | evaluator result | inputs, extension manifest |
| `promoted_pack` | accepted snapshot | candidate, promotion record, dependencies, revision targets, verifications, evaluations, evidence, policy decisions, extension manifests |
| `promotion_record` | promotion facts | policy decision |
| `receipt` | command receipt (runtime-signed) | — |
| `baseline` | composition commitment | members, policies |
| `journal_checkpoint` | signed journal head | — |

**AEVC-OBJ-0004** The closure of an object is the transitive set of its references. Every object in the closure MUST be present and valid for the root object to validate.

**AEVC-OBJ-0005** Accepted objects are immutable. Later change MUST be represented by new objects and explicit relationships, never by editing an existing object.
