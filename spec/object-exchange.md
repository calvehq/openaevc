# Object Exchange and Reachability

OpenAEVC supports content-deduplicated exchange of immutable objects between implementations
without defining a hosted synchronization product.

## Reachability

`GetObjectClosure{digest}`, `GetPackClosure{digest}` and `GetBaselineClosure{baseline}` (action
`object.read`) return `{root, objects, missing}`: every object transitively referenced from the
root (object-model.md) that is visible in the Namespace, plus referenced digests not present.

**AEVC-XCH-0001** A closure MUST contain every object required to validate its root and nothing that
is not reachable from it.

## Inventory

`ListObjectDigests{kind?, after?, limit?}` pages through the Namespace index in digest order
(`next` is the cursor for the following page). `HasObject{digests}` and
`ComputeMissingObjects{digests}` answer which digests are not visible locally, so a receiver
requests only what it lacks.

## Transfer

Fetch: `GetObject{digest}` (JSON with the canonical bytes, base64url) or `GET
/v1/objects/{digest}` (raw canonical CBOR). Submit: `PutImmutableObject{digest, bytes}` (action
`object.exchange`) or `PUT /v1/objects/{digest}`.

**AEVC-XCH-0002** On import the runtime MUST verify, before indexing: the SHA-256 of the bytes equals
the claimed digest (`DIGEST_MISMATCH`), the bytes are canonical, the envelope and body match the
schema of the object kind, the protocol version is supported, and all signatures verify. Original
signatures and provenance are preserved byte-for-byte.

**AEVC-XCH-0003** Importing objects MUST NOT confer authority or trust: imported grants, principals
and extension manifests are inert data. Principals, grants and extensions become effective only
through the Namespace's own `RegisterPrincipal`, `IssueCapabilityGrant` and `RegisterExtension`.

**AEVC-XCH-0004** Identical objects are stored once per physical store; logical visibility is
per Namespace index. Re-importing a present object is a no-op that still records an
`object.imported` event.

A receiving runtime can therefore obtain a Baseline's closure, request only missing objects, and
validate the Baseline independently with `ValidateBaseline`.
