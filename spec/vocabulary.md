# Vocabulary

Informative definitions of protocol terms. Normative behavior is defined in the referenced files.

| Term | Meaning |
|------|---------|
| **Namespace** | Top-level isolation scope for identifiers, authority roots, packs, Baselines, execution state, events, policies and extensions (namespace.md). Not a product "project". |
| **Principal** | An authenticated identity: `KEY`, `RUNTIME`, `SERVICE` (with an Ed25519 key) or `ACTOR` (linked to a key principal). |
| **Capability grant** | Signed statement allowing a subject principal to perform actions on resources within a Namespace (capabilities.md). |
| **ChangePack** | Mutable pre-promotion unit of change under a stable `cpk_` identity, evolving through generations (changepack.md). |
| **RevisionPack** | A pack (`rpk_`) that amends, supersedes or reverts promoted packs (revisions.md). |
| **Generation** | Monotonic counter of a pack's structural state. Every structural mutation creates a new generation. |
| **WorkUnit** | Generic unit of work inside a pack. |
| **Active Change Graph** | Mutable graph of packs, work units, executions, observations, candidates and results (active-change-graph.md). |
| **Resource / Effect** | Domain-owned addressable thing / structured proposed change, interpreted by an extension. |
| **Execution** | One attempt by a provider's worker, coordinated by a harness, to perform a WorkUnit (execution.md). |
| **Provider / Worker / Harness** | Supplier of workers / the concrete process, service or agent doing the work / the structured protocol coordinating the worker. |
| **Observation** | Immutable record of something learned or produced during execution (observations.md). |
| **Candidate** | The accepted effects of a pack generation; frozen as an immutable Candidate object at seal. |
| **Evidence** | Immutable, content-addressed artifact bound to one sealed candidate (evidence.md). |
| **Verification** | Checks whether declared conditions hold for a candidate: `PASS`/`FAIL`/`INCONCLUSIVE`/`ERROR` (verification.md). |
| **Evaluation** | Interprets facts/evidence relative to a policy dimension: `ALLOW`/`WARN`/`DENY`/`UNKNOWN` (evaluation.md). |
| **Policy** | Deterministic boolean gates over normalized facts (policy.md). |
| **Qualification** | The state in which a sealed generation satisfies all required policies. |
| **Promotion** | The atomic transition from qualified mutable work to immutable PromotedPack (promotion.md). |
| **Baseline** | Immutable commitment to a validated composition graph of promoted packs (baseline.md). |
| **Extension** | Out-of-process domain implementation speaking the Extension Contract (extensions.md). |
| **Receipt** | Runtime-signed canonical record of a successful command. |
| **Journal** | Per-Namespace hash-chained audit event log (events.md). |
