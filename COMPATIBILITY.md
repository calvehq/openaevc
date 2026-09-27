# Compatibility

| Package version | Protocol | Extension contract | Conformance suite | Data root schema |
| --------------- | -------- | ------------------ | ----------------- | ---------------- |
| 0.1.0           | 0.1.0    | 0.1.0              | 0.1.0             | 1                |

Pre-1.0, breaking protocol changes increment the minor version. After 1.0: patch = clarification with no wire break, minor = backward-compatible addition, major = incompatible.

Storage: migrations are forward-only and numbered. Release N opens data roots written by N-1. Downgrades are not supported; an older runtime refuses a newer schema version instead of modifying it.

Immutable objects are never reinterpreted: an incompatible object change introduces a new object kind or schema version.
