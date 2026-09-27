# Composition

The canonical graph of a Baseline is `{members, edges}`: members are sorted PromotedPack digests;
edges are sorted, deduplicated `CompositionEdge {from, to, kind, relation?}` values. Its graph
digest is SHA-256 of the canonical encoding of that pair.

Edges:

| Kind | Origin | Meaning |
|------|--------|---------|
| `REQUIRES` | member dependencies, or caller | `from` requires `to` |
| `ORDERS_AFTER` | caller | `from` is ordered after `to` |
| `REVISION_RELATION` | member revision info | `from` amends/supersedes/reverts `to` |
| `CONFLICTS_WITH` | — | never valid inside a Baseline |

**AEVC-CMP-0001** Every dependency of a member MUST be a member (`DEPENDENCY_MISSING`); members must
be unique and non-empty; caller edges MUST be `REQUIRES` or `ORDERS_AFTER` between members
(`COMPOSITION_INVALID`).

**AEVC-CMP-0002** `REQUIRES`, `ORDERS_AFTER` and `REVISION_RELATION` edges together MUST be acyclic
(`DEPENDENCY_CYCLE` with a cycle).

**AEVC-CMP-0003** Explicitly conflicting members (a member's `conflicts_with` naming another member)
MUST NOT be composed together (`COMPOSITION_INVALID`).

**AEVC-CMP-0004** Revision lineage MUST be unambiguous: an `AMENDS` or `REVERTS` revision requires
its targets to be members; a `SUPERSEDES` target may be absent; two members superseding the same
target are ambiguous (`COMPOSITION_INVALID`). Heads are the members not superseded by another
member.

**AEVC-CMP-0005** Graph canonicalization MUST be deterministic: the same members and edges in any
order produce identical members, edges, heads and graph digest.

Extensions add domain rules through composition validators (for example `kv.terminal-values`:
two members not ordered relative to each other must not leave a key in different terminal
states). Validators return conflicts and facts; they never modify Baselines.
