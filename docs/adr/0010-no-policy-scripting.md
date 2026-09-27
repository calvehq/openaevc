# 0010. No arbitrary scripting in policy

- Status: accepted
- Date: 2026-09-26

## Decision

Policy is a closed expression language (`all`, `any`, `not`, comparisons, membership, existence, verifier/evaluator/evidence conditions) over normalized facts, evaluated with no I/O and an explicit timestamp. Namespace mandatory policies are always ANDed with pack policies, so a pack can only make gates stricter.

## Consequences

Policy results are deterministic and reproducible from stored facts. Complex domain logic belongs in verifiers/evaluators, which produce facts.
