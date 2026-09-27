# Revisions

A RevisionPack (`rpk_`) is a new change whose purpose is to amend, supersede or reverse effects of
one or more promoted packs. It has the ChangePack lifecycle and generations.

`CreateRevisionPack{relation, targets, spec}` where `relation` is `AMENDS`, `SUPERSEDES` or
`REVERTS` and `targets` are PromotedPack digests.

**AEVC-REV-0001** A RevisionPack MUST name at least one target and every target MUST be a promoted
pack visible in the Namespace (`NOT_FOUND` otherwise). The runtime records `REVISION_OF` edges.

**AEVC-REV-0002** The relation describes history; it does not generate inverse effects. The domain
extension produces and validates the actual effects (for example `kv.delete` to revert a
`kv.set`).

**AEVC-REV-0003** Promoting a RevisionPack creates a new PromotedPack carrying the relation and
targets. Target objects are never modified or removed.

Composition (composition.md) interprets revision relations when Baselines include both a
revision and its targets.
