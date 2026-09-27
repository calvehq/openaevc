# Transport

The same command/query/event semantics are available embedded (in-process) and through the
reference daemon `openaevcd`. There is no privileged embedded path.

## Envelopes

Every command and query is an `Envelope{protocol_version, request_id, namespace?, caller,
act_as?, nonce, issued_at, expires_at?, body, signature}`. The signature is Ed25519 by the
caller's key over the canonical encoding of the envelope with `signature` omitted, in the
`request` domain (identity-and-digests.md).

**AEVC-TRN-0001** Implementations MUST authenticate and authorize every envelope identically
regardless of transport; the daemon MUST NOT make authorization decisions of its own.

**AEVC-TRN-0002** Envelopes MUST be in canonical form: absent and empty optional fields omitted.
Envelopes that decode but do not re-encode identically are rejected (`INVALID_ARGUMENT`).

## HTTP v1

| Method & path | Body / auth | Response |
|---------------|-------------|----------|
| `GET /v1/info` | none | `RuntimeInfo` (supported protocol and contract ranges) |
| `POST /v1/commands` | `CommandEnvelope` (JSON or `application/cbor`) | `CommandReceipt` |
| `POST /v1/queries` | `QueryEnvelope` | query result |
| `GET /v1/events` | `openaevc-envelope` header: signed `ListEvents`; optional `subject` params; `Last-Event-ID` | `text/event-stream` |
| `GET /v1/objects/{digest}` | `openaevc-envelope`: signed `GetObject{digest}` | canonical CBOR bytes |
| `PUT /v1/objects/{digest}` | `openaevc-envelope`: signed `PutImmutableObject{digest, bytes: ""}`; body = canonical bytes | `CommandReceipt` |
| `GET /v1/openapi.json` | none | OpenAPI 3.1 |
| `GET /v1/health/live`, `/v1/health/ready` | none | 200 / 503 |
| `GET /v1/metrics` | none | Prometheus text |

The `openaevc-envelope` header is the unpadded base64url of the envelope's canonical CBOR.
Responses honour `Accept: application/cbor`. Errors are `ProtocolError` bodies with HTTP status
400 (request/encoding), 401, 403, 404, 409 (lifecycle/conflict), 422 (extension incompatible),
500, 502 (extension failure) or 503 (integrity/recovery).

**AEVC-TRN-0003** `PUT /v1/objects/{digest}` MUST verify the body bytes against the signed digest;
the object bytes travel outside the signature, whose digest commits to them.

## Events

Server-sent events carry `id: <sequence>`, `event: <kind>` and `data: <Event JSON>`. A subscription
is authenticated once from its envelope and `namespace.read` is re-authorized on every delivery,
so revocation ends it with an `event: error` carrying the protocol error.

**AEVC-TRN-0004** Delivery is at-least-once in sequence order; resuming with `Last-Event-ID: n`
delivers exactly the matching events after `n`. A subscriber whose bounded buffer stays full
beyond the slow-consumer timeout is disconnected; memory stays bounded.

## Listeners

The reference daemon listens on a Unix-domain socket by default, optionally on loopback TCP, and
on TLS for any remote address.

**AEVC-TRN-0005** Non-loopback TCP MUST use TLS; the daemon refuses such configurations otherwise.

## Version negotiation

Clients read `GET /v1/info` and select the highest version in both ranges (versioning.md).
