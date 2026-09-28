# Baselines

Accepted state is a set of immutable Baselines. A Baseline is a small commitment to a validated
composition graph of promoted packs; it never copies pack payloads.

`CreateBaseline{members, edges, policies, metadata}` (action `baseline.create`) creates a
`baseline` object: ID, sorted member PromotedPack digests, sorted canonical edges, lineage heads,
policy digests, composition facts, graph digest and namespaced metadata. The creating event
sequence, creator and protocol version are recorded in the object envelope.

**AEVC-BSL-0001** Existing Baselines MUST never be mutated. Each `CreateBaseline` writes one new
immutable object; Baselines have no parent relation and may share members freely, sharing their
objects by digest.

**AEVC-BSL-0002** Baseline creation MUST validate: every member is a promoted pack visible in the
Namespace (`NOT_FOUND`, or `INVALID_ARGUMENT` for other object kinds) and verifies by digest, and
was promoted by `PromoteChangePack` in this Namespace (`INVALID_ARGUMENT`; an imported
`promoted_pack` is inert data, object-exchange.md); every Baseline policy was registered with
`RegisterPolicy` in this Namespace (`INVALID_ARGUMENT`); the
composition rules of composition.md; every registered extension composition validator relevant to
the members; and the Baseline's own policies over the composition facts (`POLICY_DENIED`).

**AEVC-BSL-0003** `ValidateBaseline{digest}` MUST re-derive the canonical graph from the immutable
member objects alone and report whether it matches the stored members, edges, heads and graph
digest, plus composition validator outcomes (`passed`, `failed`, or `skipped` when the
extension is not registered locally). A Baseline whose closure (object-model.md, AEVC-OBJ-0004)
is incomplete, or whose stored graph does not match, MUST be reported `valid: false`.
`ValidateBaseline` checks structure and integrity only: it works on imported Baselines and does
not assert that their members were promoted by this runtime.

Composition facts: `composition.members`, `composition.edges`, `composition.heads` plus namespaced
facts returned by validators.
