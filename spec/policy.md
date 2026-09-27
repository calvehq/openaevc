# Policy

Authority asks *may this actor attempt this operation?* Policy asks *does the current protocol
evidence satisfy the gates required for this transition?* Policy never grants authority.

## PolicyDocument

An immutable `policy_document` object: a namespaced `name`, optional `description`, and a
non-empty list of rules with unique IDs. Every rule is a boolean expression; a document allows
only if all of its rules hold.

Expressions (JSON: an object with exactly one operator key):

| Operator | Holds when |
|----------|-----------|
| `all: [e...]` / `any: [e...]` / `not: e` | boolean combination (`all: []` is true, `any: []` false) |
| `eq` / `ne: {fact, value}` | fact present and equal / not (`ne` is exactly `not eq`) |
| `lt` `le` `gt` `ge: {fact, value}` | fact is an integer and compares as stated |
| `in: {fact, values}` | fact present and equal to one of `values` |
| `contains: {fact, value}` | fact is a set containing `value` |
| `exists: {fact}` | fact present |
| `verifier: {kind, status}` | fact `verification.<kind>.status` equals `status` |
| `evaluator: {kind, verdict}` | fact `evaluation.<kind>.verdict` equals `verdict` |
| `evidence: {kind}` | fact `evidence.<kind>.count` ≥ 1 |

Extension-provided facts use namespaced names and are tested with the generic operators.

**AEVC-POL-0001** Fact names and kinds in expressions MUST be namespaced names; nesting deeper than 64
levels, empty rule lists and duplicate rule IDs are invalid (`INVALID_ARGUMENT`).

**AEVC-POL-0002** Policy evaluation MUST be deterministic and side-effect free: it reads only the
policy documents and the canonical fact map (no network, filesystem, clock or randomness), so the
same inputs always produce the same decision.

**AEVC-POL-0003** No scripting language or externally defined operator is permitted in protocol
0.1; unknown operators fail to decode.

## Gates and decisions

Each Namespace has mandatory policies (`RegisterPolicy{mandatory: true}`). A pack may add
`required_policies`. Qualification evaluates the union of both.

**AEVC-POL-0004** A pack's policies can only add gates: mandatory Namespace policies are always
evaluated, and protocol 0.1 defines no override.

**AEVC-POL-0005** Each qualification attempt records an immutable `policy_decision` object: subject
(pack, generation, candidate), the evaluated policy digests, the complete fact map, the outcome
(`ALLOW`/`DENY`) and every rule result. A pack with no applicable policies is allowed.

**AEVC-POL-0006** Policy decisions cannot authorize anything; promotion additionally requires
`changepack.promote` authority.
