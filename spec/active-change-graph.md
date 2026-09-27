# Active Change Graph

The Active Change Graph models live work separately from accepted composition.

Nodes: packs, work units, executions, observations, candidates (by digest), verification and evaluation results. Edges:

| Edge                     | Meaning                                       | Created by |
| ------------------------ | --------------------------------------------- | ---------- |
| `DEPENDS_ON` a→b         | a waits on b                                  | clients    |
| `BLOCKS` a→b             | b waits on a                                  | clients    |
| `PRODUCES`               | execution produced an observation/effect      | runtime    |
| `CONSUMES`               | execution consumed a context object           | runtime    |
| `DERIVED_FROM`           | retry attempt derived from an earlier attempt | runtime    |
| `VERIFIES` / `EVALUATES` | result about a candidate                      | runtime    |
| `REVISION_OF`            | RevisionPack targets a promoted pack          | runtime    |

Work units are generic (`kind` is as namespaced name); consumers may present them as tasks, jobs, actions or assignments.

**AEVC-ACG-0001** Clients may only add or remove `DEPENDS_ON` and `BLOCKS` edges; other edge kinds are runtime-owned (`INVALID_ARGUMENT`). Both endpoints must be existing packs or work units in the Namespace (`DEPENDENCY_MISSING`), and the waiting endpoint must belong to the pack named in the command, whose generation increments.

**AEVC-ACG-0002** Dependencies may cross packs. Adding an edge that would close a cycle in the wait graph MUST fail with `DEPENDENCY_CYCLE`, reporting the minimal cycle through the new edge.

**AEVC-ACG-0003** A dependency on a work unit is satisfied when it is `COMPLETED`; on a pack when the pack is `SEALED`, `QUALIFIED` or `PROMOTED`. A work unit is _ready_ when it is `OPEN`, its pack is `OPEN`, it has no active execution, and every node it or its pack waits on is satisfied. `GetBlockedWork` reports each unsatisfied node with a reason.

Queries: `GetActiveChangeGraph` (whole Namespace or one pack's subgraph), `GetNode`, `GetDependencyClosure` (transitive dependencies, or dependents with `reverse`), `GetAffectedNodes` (everything downstream), `GetReadyWork`, `GetBlockedWork`.
