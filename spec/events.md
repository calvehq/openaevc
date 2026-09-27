# Events and the Audit Journal

Every Namespace has one append-only, hash-chained journal of immutable events.

| Field                    | Meaning                                                            |
| ------------------------ | ------------------------------------------------------------------ |
| `id`                     | `evt_` identifier.                                                 |
| `namespace`              | Owning Namespace.                                                  |
| `sequence`               | Per-Namespace sequence, starting at 1, incremented by exactly 1.   |
| `runtime_instance`       | Runtime instance that wrote the event.                             |
| `request_id` / `actor`   | Originating request and effective principal, when applicable.      |
| `kind`                   | Dotted event kind, e.g. `changepack.sealed`.                       |
| `body`                   | Kind-specific canonical body.                                      |
| `subjects`               | Typed IDs and digests the event concerns (subscription filtering). |
| `timestamp`              | Informative wall-clock time.                                       |
| `previous_hash` / `hash` | Hash-chain links.                                                  |

**AEVC-EVT-0001** Every successful state-changing command MUST append at least one event, and the state change and its events MUST become visible atomically (one transaction).

**AEVC-EVT-0002** Event sequences MUST be strictly monotonic per Namespace with no gaps; sequence, not timestamp, is the authoritative order.

**AEVC-EVT-0003** `hash = SHA-256(canonical(event with "hash" omitted) || previous_hash)` where `previous_hash` contributes its 32 raw bytes. The first event of a Namespace uses the all-zero SHA-256 value as `previous_hash`. Any modification, removal, reordering or relinking of events MUST be detectable by recomputing the chain.

**AEVC-EVT-0004** Whenever a commit's events include a sequence that is a multiple of `checkpoint_interval` (reference default 1000), the runtime writes, in the same transaction, a `journal_checkpoint` object signed by its runtime key committing to that sequence and its event hash. `GetJournalCheckpoint` returns the latest one.

## Event kinds

`namespace.created`, `principal.registered`, `grant.issued`, `grant.revoked`, `policy.registered`, `extension.registered`, `extension.unregistered`, `provider.registered`, `changepack.created`, `changepack.updated`, `workunit.added`, `workunit.updated`, `dependency.added`, `dependency.removed`, `changepack.sealed`, `changepack.reopened`, `changepack.abandoned`, `changepack.quarantined`, `changepack.released`, `changepack.qualified`, `changepack.disqualified`, `changepack.promoted`, `execution.admitted`, `execution.running`, `execution.heartbeat`, `execution.succeeded`, `execution.failed`, `execution.cancelled`, `execution.lost`, `effect.applied`, `effect.rejected`, `observation.appended`, `evidence.registered`, `verification.completed`, `evaluation.completed`, `qualification.evaluated`, `baseline.created`, `object.imported`, `authorization.denied`, `checkpoint.created`.

## Subscriptions

Consumers subscribe with a filter (Namespace, `after` cursor, kinds, subjects). Delivery is at-least-once in sequence order; consumers deduplicate by sequence. A consumer resumes by passing the last sequence it processed as `after` (over SSE: `Last-Event-ID`), without replaying earlier events.

**AEVC-EVT-0005** A subscription resumed with cursor `n` MUST deliver exactly the matching events with sequence greater than `n`, in order.
