# Observations and Provenance

`AppendObservation{execution, lease, kind, payload? | blob?, related_resources,
related_effects}` (actions `observation.append` and the execution rules of execution.md) records
an immutable `observation` object: ID, execution, pack, generation, work unit, producer, time,
namespaced kind, inline payload (≤ 64 KiB canonical) or a digest of a `blob` object, related
resources and effects (which must be effects of the same execution), and provenance. A `PRODUCES`
edge links the execution to the observation.

## Provenance

Every execution-affecting artifact carries provenance: actor principal, calling principal,
provider, worker identity (when known), harness, extension ID/version/manifest digest, grant
digests, request ID, pack and generation, execution, runtime instance, and input (context) object
digests.

**AEVC-OBS-0001** Every applied effect MUST carry complete minimum provenance (provider, harness,
extension reference and pack generation); an effect without it MUST NOT contribute to a candidate.

**AEVC-OBS-0002** Observations and applied effects MUST identify the exact pack generation they were
produced for.
