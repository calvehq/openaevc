# Verification

Verification answers whether declared conditions hold for a sealed candidate.
`RunVerification{pack, generation, verifier, config?, evidence}` (action `verification.run`)
invokes the extension providing the verifier kind with the frozen candidate effects, the evidence
inputs and the configuration.

**AEVC-VRF-0001** Verification requires a `SEALED` or `QUALIFIED` pack at the named generation
(`INVALID_TRANSITION` for an open pack, `STALE_GENERATION` otherwise); evidence inputs must be
bound to the same candidate (`EVIDENCE_INVALID`).

**AEVC-VRF-0002** The result is an immutable `verification_result` object: status `PASS`, `FAIL`,
`INCONCLUSIVE` or `ERROR`, verifier kind, extension reference, configuration, evidence digests
(inputs and attachments), findings, normalized facts, timestamps and provenance. A rerun creates
a new object; results are never modified.

**AEVC-VRF-0003** Only results bound to the current sealed generation and candidate count. For each
verifier kind the latest such result provides the fact `verification.<kind>.status` and its
namespaced facts.

**AEVC-VRF-0004** Any new evidence, verification or evaluation for a `QUALIFIED` pack returns it to
`SEALED` (`changepack.disqualified`) until qualification is refreshed.

## Qualification

`RefreshQualification{pack, generation}` evaluates the Namespace mandatory policies followed by the
pack's `required_policies` over the normalized facts, and records an immutable `policy_decision`.

**AEVC-VRF-0005** A pack becomes `QUALIFIED` only when that decision is `ALLOW` for its exact sealed
generation and candidate; a `DENY` decision leaves (or returns) it `SEALED`. The decision is
recorded either way.
