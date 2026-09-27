# ChangePack Lifecycle

A ChangePack (`cpk_`) is mutable pre-promotion work under a stable identity. RevisionPacks (`rpk_`, revisions.md) follow the same lifecycle.

## Generations

Every structural mutation (`UpdateChangePack`, `AddWorkUnit`, `UpdateWorkUnit`, `AddActiveDependency`, `RemoveActiveDependency`, `ReopenChangePack`) creates a new generation. Creation yields generation 1. Every generation's state remains queryable (`GetChangePack{generation}`).

**AEVC-LIFE-0001** Every structural mutation MUST name `expected_generation`; if it differs from the pack's current generation the request MUST fail with `STALE_GENERATION` (reporting expected and actual generations) and change nothing.

Effects accepted from executions are added to the candidate of the current generation without creating a new generation (execution.md).

## States

```text
OPEN ──seal──▶ SEALED ──qualify──▶ QUALIFIED ──promote──▶ PROMOTED
  ▲              │                     │
  └────reopen────┴─────────────────────┘
OPEN | SEALED | QUALIFIED ──▶ ABANDONED
OPEN | SEALED | QUALIFIED ──▶ QUARANTINED ──release──▶ previous state
```

**AEVC-LIFE-0002** Only an `OPEN` pack accepts structural mutations and effects. Mutating a `SEALED` or `QUALIFIED` pack MUST fail with `INVALID_TRANSITION`; the caller must `ReopenChangePack` first.

**AEVC-LIFE-0003** `SealChangePack` freezes the current generation: it writes an immutable `candidate` object of the generation's applied effects and records its digest. Sealing fails with `CONFLICT` while any work unit of the pack has an active execution.

**AEVC-LIFE-0004** `ReopenChangePack` moves `SEALED`/`QUALIFIED` to `OPEN`, increments the generation and clears seal and qualification. All verification, evaluation, evidence and policy decisions bound to earlier generations become historical and can never qualify the pack again.

**AEVC-LIFE-0005** `PROMOTED` and `ABANDONED` are terminal. Any command changing a promoted pack MUST fail with `IMMUTABLE_OBJECT`; one changing an abandoned pack MUST fail with `INVALID_TRANSITION`. An abandoned pack can never be promoted.

**AEVC-LIFE-0006** `QuarantineChangePack` (action `quarantine.manage`) records the previous state. While quarantined, lifecycle commands fail with `QUARANTINED`. `ReleaseQuarantine` restores exactly the previous state. Quarantine never bypasses authority.

**AEVC-LIFE-0007** Promotion requires `QUALIFIED` (`NOT_QUALIFIED` otherwise; promotion.md).

Consumer review workflows (reviewing, approved, rejected, submitted) are not protocol states. A consumer may require review before granting the capability or policy fact that promotion needs.
