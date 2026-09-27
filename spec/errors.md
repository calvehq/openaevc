# Errors

Errors are structured protocol data. The `message` is diagnostic only.

| Field | Meaning |
| --- | --- |
| `code` | Stable error code (below). |
| `category` | `REQUEST`, `AUTHORITY`, `LIFECYCLE`, `GRAPH`, `EXECUTION`, `EXTENSION`, `QUALIFICATION`, `CONFLICT`, `INTEGRITY`, `INTERNAL`. |
| `message` | Human-readable diagnostic. |
| `retryable` | Whether retrying the identical request may succeed. |
| `object_ids` | Optional IDs/digests involved. |
| `expected_generation` / `actual_generation` | For `STALE_GENERATION`. |
| `missing_action` | For `FORBIDDEN`: the action no valid capability allows. |
| `transition` | For lifecycle errors: `{from, to}`. |
| `extension_error` | Nested `{extension_id, code, message}`. |
| `cycle` | For `DEPENDENCY_CYCLE`: the minimal cycle, first node repeated last. |

Codes: `INVALID_ARGUMENT`, `NOT_FOUND`, `ALREADY_EXISTS`, `UNAUTHORIZED`, `FORBIDDEN`, `CAPABILITY_EXPIRED`, `CAPABILITY_REVOKED`, `REPLAY_DETECTED`, `STALE_GENERATION`, `INVALID_TRANSITION`, `IMMUTABLE_OBJECT`, `QUARANTINED`, `DEPENDENCY_CYCLE`, `DEPENDENCY_MISSING`, `EXECUTION_NOT_READY`, `EXECUTION_LOST`, `EXTENSION_INCOMPATIBLE`, `EXTENSION_FAILED`, `EVIDENCE_INVALID`, `VERIFICATION_FAILED`, `POLICY_DENIED`, `NOT_QUALIFIED`, `COMPOSITION_INVALID`, `CONFLICT`, `DIGEST_MISMATCH`, `CANONICAL_ENCODING_ERROR`, `PROTOCOL_VERSION_UNSUPPORTED`, `STORAGE_INTEGRITY_ERROR`, `RECOVERY_REQUIRED`, `INTERNAL`.

Retryable codes: `EXECUTION_NOT_READY`, `EXTENSION_FAILED`, `CONFLICT`, `INTERNAL`.

**AEVC-ERR-0001** Every failed command or query MUST return a structured error with one of the codes above. A failed command MUST leave no partial state change visible.

**AEVC-ERR-0002** Errors MUST NOT expose SQL, filesystem paths, secrets or private keys.

**AEVC-ERR-0003** Unauthenticated requests fail with `UNAUTHORIZED`; authenticated requests lacking authority fail with `FORBIDDEN` (or `CAPABILITY_EXPIRED` / `CAPABILITY_REVOKED` when the only matching grant is expired or revoked), naming the `missing_action`.
