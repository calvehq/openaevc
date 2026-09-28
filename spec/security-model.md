# Security model

This document is informative: it names the threats OpenAEVC is designed against and points to
the normative requirements that address them. It adds no requirements of its own.

## Trust boundaries

The runtime is the only authority. Everything that reaches it — consumers, providers, workers,
extensions, imported objects and remote peers — is untrusted input. Embedding the runtime as a
library does not make the caller trusted: embedded and remote callers pass the same admission
path (AEVC-AUTH-0004, AEVC-TRN-0001).

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Malicious or compromised consumer | Every request is signed and verified before any authority is consulted (AEVC-AUTH-0001); unauthenticated requests are refused. Default deny: every command needs a valid capability for its exact action and Namespace (AEVC-AUTH-0003, AEVC-NS-0002). Denials are audited (AEVC-AUTH-0007). |
| Malicious extension | Extensions run out of process with a cleared environment and are given no storage paths, handles or credentials (AEVC-EXT-0007); they get only granted host calls (AEVC-EXT-0005, AEVC-EXT-0009) and hard deadline, frame and call limits (AEVC-EXT-0006). Their outputs are validated and recorded by the runtime. **This is protocol authorization, not OS confinement**: the process keeps the OS privileges of the identity that launched it (see "Extension trust boundary"). |
| Malicious provider or worker | Executions are bounded by leases and exact scope: effects outside the admitted resources or effect kinds are refused (AEVC-EXE-0002, AEVC-EXE-0007); only the lease holder can act (AEVC-EXE-0004); expired leases make executions `LOST` (AEVC-EXE-0005). Every applied effect carries complete provenance (AEVC-EXE-0008). |
| Replayed commands | Request IDs and nonces are recorded within the freshness window; replays fail with `REPLAY_DETECTED` (AEVC-AUTH-0005); retried commands with the same idempotency identity return the original result (AEVC-AUTH-0006). |
| Forged capability grants | Grants are signed by their issuer, rooted in a Namespace root, bounded by the parent in a delegation chain, and must be submitted by their issuer (AEVC-CAP-0001 to AEVC-CAP-0004). Revocation takes effect for every later request (AEVC-CAP-0005). |
| Stale-generation writes | Every mutable write names the exact expected generation (AEVC-LIFE-0001); reopening invalidates earlier evidence and results (AEVC-LIFE-0004). |
| Object tampering | Objects are content-addressed canonical bytes with signatures over the signing digest; imports verify digest, canonical form, schema, version and signatures before indexing (AEVC-OBJ-0002, AEVC-XCH-0002). Accepted objects are immutable (AEVC-OBJ-0005). |
| Event-journal tampering | Events are hash-chained and periodically committed by signed checkpoints (AEVC-EVT-0002, AEVC-EVT-0003); startup verifies the chain and fails closed on mismatch (AEVC-REC-0001, AEVC-REC-0002). |
| Privilege escalation through host calls | Host calls are checked against the intersection of manifest requests, registration approvals and the operation's allowance; out-of-scope resource reads terminate the invocation (AEVC-EXT-0005). |
| Confused deputy | Authority is always the caller's own; acting for another principal requires an explicit `act_as` grant (AEVC-AUTH-0002). Execution admission checks the caller's authority over the requested scope, not the provider's (AEVC-EXE-0002). Policy decisions never grant authority (AEVC-POL-0006). Imported grants and principals are inert (AEVC-XCH-0003). |
| TOCTOU around sealing and promotion | Sealing freezes a candidate object (AEVC-LIFE-0002); promotion re-checks qualification and gates inside one transaction (AEVC-PRO-0001, AEVC-PRO-0002). |
| Interrupted writes | Immutable bytes are written and verified before the transaction that references them; state changes are atomic with their events; a pack is never visible as promoted without its snapshot, record and events (AEVC-REC-0003, AEVC-REC-0004). |
| Transport interception | Remote listeners on non-loopback addresses require TLS; every request is signed end to end, so an intermediary cannot alter a request without detection (AEVC-TRN-0002 to AEVC-TRN-0005). |
| Denial of service | Request size, request timeout, event buffers, slow-consumer disconnection, page sizes and extension limits are bounded by configuration. Extension failures leave the runtime available (AEVC-EXT-0006). Resource exhaustion by an authorized principal is an operational concern (rate limiting belongs in front of the transport). |

## Extension trust boundary

OpenAEVC v1 host capabilities govern OpenAEVC-mediated privileged operations; an extension
executable is still subject only to the privileges of the operating-system identity that launched
it. The reference host does not sandbox extension processes. A locally installed, registered
extension is trusted code in the OS sense: if it runs as the daemon's user it can read the data
root and the runtime signing key and write the database directly, and no protocol mechanism can
prevent that. The guarantees in spec/extensions.md ("Trust boundary") are what the protocol
enforces; OS containment (a separate user, container or sandbox for extension processes) is a
deployment responsibility described in docs/operations.md.

## Known limitations of v1

- Queries are not nonce-tracked and can be replayed within the freshness window
  (AEVC-AUTH-0005); set a short `expires_at` on envelopes that may be logged.
- The runtime signing key cannot be rotated in place: startup requires the latest checkpoint to
  be signed by the configured key (AEVC-REC-0001).
- There is no command to retire a compromised principal key; revoke its grants (a root key is
  retired only by creating a new Namespace).
- Extension digests are checked before spawn, not atomically with exec (spec/extensions.md).

## Security invariants of the reference implementation

- Default deny; signature verification precedes any use of authority.
- Exact generation checks on every mutable write.
- Digest and signature verification of every imported object.
- Promotion is a single atomic transaction.
- Extensions are never given database handles, storage paths or credentials through the
  protocol, and no third-party code is loaded into the runtime process. (OS-level access is
  governed by the OS identity the extension runs as; see above.)
- Remote transport requires TLS except on loopback and Unix sockets.
- Secret material never enters events, errors or logs; errors never expose SQL, filesystem paths
  or keys.
- Private keys are written with owner-only permissions. Runtime signing goes through the
  `Signer` trait, so deployments can keep keys in an HSM or OS key store.
