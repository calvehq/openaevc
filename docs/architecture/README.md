# Architecture

Explanatory and non-normative; `spec/` is the authority. Crate names refer to the Rust reference implementation.

## Three state layers

```text
Active Change Graph             Accepted Composition           Immutable Object Store
(mutable, versioned)            (append-only)                  (content-addressed)
ChangePacks + generations       PromotedPacks, Baselines  ───► canonical CBOR, sha256 digests,
WorkUnits, Executions,          composition graphs             Ed25519 signatures
leases, dependency edges                ▲                              ▲
        │──promotion (one transaction) ─┘                              │
        └──────── every accepted fact is an object ────────────────────┘
```

Mutable records carry an optimistic version (the generation for packs); immutable objects never change. Events are an append-only, hash-chained journal per Namespace with signed checkpoints.

## Command admission

```text
envelope ─► protocol version ─► signature (domain "request") ─► caller principal active
        ─► freshness window ─► replay (request_id, nonce) / idempotency ─► per-command authority
        ─► handler (Tx overlay) ─► one atomic WriteBatch ─► signed receipt + events
```

Every entry point — embedded `Runtime::execute`, HTTP, object upload, subscriptions — passes the same path (`openaevc-runtime`). Denials are audited as events. Authority is the caller's capability grants, checked for the exact action, Namespace and resource scope (`openaevc-authority`).

## Execution

```text
StartExecution ─► admission (pack generation, readiness, provider, effect kinds, scope authority)
               ─► lease {id, expires_at}
worker: Heartbeat · SubmitEffectProposal (validate_effect → apply_effect via extension)
        · AppendObservation · CompleteExecution | FailExecution
lease expiry (tick or lazily on next command) ─► LOST ─► retry with DERIVED_FROM lineage
```

Only the lease holder can act. A structural change to the pack bumps its generation and makes later effects from the execution stale.

## Extension host

```text
runtime ──spawn (cleared env, cwd = extension dir)──► extension process
        ──hello{protocol, contract}──────────────────►
        ◄─hello{manifest}────────────────────────────  (digest re-checked before every spawn)
        ──invoke{operation, granted, deadline}───────►
        ◄─host_call{resource.read …} ─ checked against grants and scope
        ◄─result | error ────────────────────────────  (frames: u32 length + canonical CBOR)
```

One process per invocation, killed on deadline, oversize or malformed frames (`openaevc-extension-contract`).

## Verification and evaluation

```text
Sealed candidate ─► RunVerification(kind) ─► VerificationResult {status, findings, facts}
                 ─► RunEvaluation(kind)   ─► EvaluationResult {verdict, metrics}
                 ─► RegisterEvidence      ─► Evidence bound to (pack, generation, candidate)
RefreshQualification: facts from the latest results ─► policies (closed expression language)
                     ─► PolicyDecision object ─► QUALIFIED | stays SEALED
```

Policy decisions never grant authority; promotion still needs `changepack.promote`.

## Promotion

```text
PromoteChangePack(pack, generation)
  in one transaction: re-check state QUALIFIED, gates, dependencies promoted
                      ─► PromotedPack (snapshot) + PromotionRecord + changepack.promoted event
```

A crash at any point leaves either nothing or all of it (`spec/recovery.md`).

## Baseline composition

```text
members (promoted digests) + caller edges (ORDERS_AFTER)
  + derived edges (DEPENDS_ON, REVERTS, SUPERSEDES, conflicts)
  ─► validation (membership, cycles, conflicts, lineage, extension validators, policies)
  ─► canonical graph (sorted members/edges, graph_digest, heads) ─► Baseline object
```

Baselines are immutable; a new composition is a new Baseline (`openaevc-composition`).

## Recovery

```text
startup: schema version ─► discard tmp/ staged writes ─► committed objects present
       ─► per-Namespace journal verified from latest signed checkpoint ─► expired leases LOST
failure anywhere ─► STORAGE_INTEGRITY_ERROR (never auto-repair)
commit: CAS bytes written+fsynced+renamed ─► SQLite transaction (records, index, events)
```

## Object exchange

```text
sender:   GetBaselineClosure / GetPackClosure ─► digests
receiver: ComputeMissingObjects(digests) ─► missing
sender:   GetObject(d) for each missing  ─► canonical bytes
receiver: PutImmutableObject(d, bytes)   ─► verify digest, canonical form, schema, signatures
receiver: ValidateBaseline               ─► independent validation
```

Imported grants, principals and manifests are inert data on the receiver.
