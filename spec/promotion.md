# Promotion

Promotion turns qualified mutable work into an immutable accepted object.
`PromoteChangePack{pack, generation}` (action `changepack.promote`).

**AEVC-PRO-0001** Within one transaction the runtime MUST check: the caller holds
`changepack.promote`; the pack is `QUALIFIED` (`NOT_QUALIFIED` for `OPEN`/`SEALED`,
`IMMUTABLE_OBJECT` once promoted, `QUARANTINED`, `INVALID_TRANSITION` if abandoned); the generation
matches the sealed and qualified generation (`STALE_GENERATION`); the qualification's candidate is
the sealed candidate; every candidate effect has complete provenance for that generation; the gate
policies (Namespace mandatory, then pack) still allow over the current facts (`POLICY_DENIED`); all
qualification inputs exist and verify; all extension manifests referenced by the candidate are
resolvable by digest; every pack this pack depends on is already promoted
(`DEPENDENCY_MISSING`).

**AEVC-PRO-0002** The same transaction MUST write the `promotion_record` object, the `promoted_pack`
object, the state change to `PROMOTED`, the `changepack.promoted` event and the signed receipt. If
any step fails none of them becomes visible, and a crash at any point leaves the pack either
unpromoted and retryable or fully promoted with every object and audit record present.

## PromotedPack

Fields: pack ID, final generation, candidate digest, effect summaries, resources, dependency
promoted-pack digests, declared conflicts, revision relation (for RevisionPacks), verification,
evaluation and evidence digests used, policy decision digests (qualification and promotion),
promotion record digest, extension references, intent, metadata, and `provenance_root` (digest of
the candidate effects' provenance list).

**AEVC-PRO-0003** A promoted pack's snapshot is immutable forever. Every later command addressed to a
promoted pack fails with `IMMUTABLE_OBJECT`; the historical mutable aggregate remains readable.

**AEVC-PRO-0004** A PromotedPack validates solely from immutable objects: its closure (candidate,
promotion record, decisions, results, evidence, manifests, dependencies, revision targets) is
present in the Namespace.
