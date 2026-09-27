# Evidence

Evidence is an immutable, content-addressed `evidence` object: ID, namespaced kind, producer,
pack, generation, candidate digest, payload (digest of a `blob` object), media type, optional
schema reference, source nodes, optional extension reference and creation time.

Evidence enters through `RegisterEvidence` (action `evidence.append`) or as attachments produced
by a verifier during `RunVerification`.

**AEVC-EVD-0001** Evidence MUST bind to the pack's current sealed generation and candidate digest.
Registering evidence for any other generation or candidate fails with `EVIDENCE_INVALID`.

**AEVC-EVD-0002** Evidence produced for an earlier generation is historical only; it never
contributes facts to, and can never be an input to, qualification of a later generation.

Evidence of kind `k` bound to the current subject contributes the fact `evidence.<k>.count`.
