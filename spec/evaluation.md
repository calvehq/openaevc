# Evaluation

Evaluation interprets verified facts or evidence relative to a policy dimension.
`RunEvaluation{pack, generation, evaluator, config?, inputs}` (action `evaluation.run`) invokes the
extension providing the evaluator kind with the current normalized facts and candidate effects.
Inputs must be evidence, verification or evaluation objects bound to the same candidate
(`EVIDENCE_INVALID`).

**AEVC-EVL-0001** The result is an immutable `evaluation_result` object with verdict `ALLOW`, `WARN`,
`DENY` or `UNKNOWN`, namespaced integer metrics, namespaced facts, inputs, timestamps and
provenance. The latest bound result per evaluator kind provides `evaluation.<kind>.verdict`.

**AEVC-EVL-0002** Evaluators produce facts only. They cannot grant authority, change lifecycle state
or promote anything; only policy (over facts) and authority (over grants) gate transitions.

OpenAEVC defines no product risk labels; consumers map verdicts and metrics to their own
presentation.
