# Versioning

Four versions are tracked separately: the **protocol** version (this spec, `0.1.0`), the **extension contract** version (`0.1.0`), the **conformance suite** version, and package versions.

Protocol versions are SemVer `MAJOR.MINOR.PATCH`. Before 1.0 a breaking change increments the minor version. After 1.0: patch = clarification with no wire break; minor = backward-compatible addition; major = incompatible change.

**AEVC-VER-0001** `GET /v1/info` and `GetRuntimeInfo` MUST return the supported protocol range and extension contract range. The extension handshake MUST exchange both ranges.

**AEVC-VER-0002** Every request envelope carries `protocol_version`. A runtime MUST reject a request whose version is outside its supported range with `PROTOCOL_VERSION_UNSUPPORTED`.

**AEVC-VER-0003** Negotiation selects the highest version contained in both parties' ranges; if the ranges do not intersect, negotiation fails.

**AEVC-VER-0004** Immutable objects are never reinterpreted: an incompatible change to an object introduces a new object kind or schema version. Signed/canonical objects never accept unknown fields (canonical-encoding.md, AEVC-ENC-0007).
