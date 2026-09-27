# Authority

Authority answers **may this principal attempt this operation?** It is decided only by the runtime, the same way for embedded and daemon callers. Policy (policy.md) is a separate question and can never grant authority.

## Principals

| Kind | Authenticates | Notes |
| --- | --- | --- |
| `KEY` | Ed25519 key | General principal. |
| `RUNTIME` | Ed25519 key | A runtime instance identity (signs receipts and checkpoints). |
| `SERVICE` | Ed25519 key | A service identity. |
| `ACTOR` | — | Linked to one key principal (`linked_to`); carries consumer-defined namespaced attributes (for example human vs agent). |

The protocol does not distinguish humans from agents for authorization.

**AEVC-AUTH-0001** Every command and query MUST be carried in an envelope signed by the calling principal's key in the `request` domain (transport.md). Requests with an unknown caller, a caller without a key, an ACTOR caller, or an invalid signature MUST fail with `UNAUTHORIZED`.

**AEVC-AUTH-0002** A request MAY name `act_as`: an ACTOR linked to the caller. Authorization is then evaluated for the actor. Naming an actor not linked to the caller MUST fail with `FORBIDDEN`.

## Default deny

**AEVC-AUTH-0003** Any protected action not explicitly allowed by a valid capability chain MUST be denied (`FORBIDDEN`, `missing_action` set). The Namespace's root principals (named at `CreateNamespace`) hold every action in their Namespace; they are the trust roots of all chains.

**AEVC-AUTH-0004** Every protected state mutation and every read MUST pass through runtime authorization. Linking the runtime into a process MUST NOT confer additional authority.

## Actions

Core actions: `namespace.read`, `changepack.create`, `changepack.mutate`, `changepack.seal`, `changepack.reopen`, `changepack.abandon`, `execution.start`, `execution.cancel`, `observation.append`, `evidence.append`, `verification.run`, `evaluation.run`, `changepack.promote`, `baseline.create`, `object.read`, `object.exchange`, `extension.register`, `extension.invoke`, `provider.register`, `principal.register`, `policy.register`, `grant.issue`, `grant.revoke`, `quarantine.manage`. Extensions may define additional namespaced actions (for example `kv.write`), which are required through their effect declarations.

| Command | Action | Command | Action |
| --- | --- | --- | --- |
| CreateNamespace | runtime administrator | StartExecution | `execution.start` (+ resource scope) |
| RegisterPrincipal | `principal.register` | HeartbeatExecution, CompleteExecution, FailExecution | `execution.start` |
| IssueCapabilityGrant | `grant.issue` | CancelExecution | `execution.cancel` |
| RevokeCapabilityGrant | `grant.revoke` | SubmitEffectProposal | effect's `required_actions` on target |
| RegisterPolicy | `policy.register` | AppendObservation | `observation.append` |
| Register/UnregisterExtension | `extension.register` | RegisterEvidence | `evidence.append` |
| RegisterProvider | `provider.register` | RunVerification | `verification.run` |
| CreateChangePack/RevisionPack | `changepack.create` | RunEvaluation | `evaluation.run` |
| Update*/Add*/Remove\* | `changepack.mutate` | RefreshQualification | `verification.run` |
| SealChangePack | `changepack.seal` | PromoteChangePack | `changepack.promote` |
| ReopenChangePack | `changepack.reopen` | CreateBaseline | `baseline.create` |
| AbandonChangePack | `changepack.abandon` | PutImmutableObject | `object.exchange` |
| Quarantine/ReleaseQuarantine | `quarantine.manage` | queries | `namespace.read`; object queries `object.read` |

## Replay protection

**AEVC-AUTH-0005** A runtime MUST reject (`REPLAY_DETECTED`) a request whose `issued_at` differs from its clock by more than the replay window (default 300 s), whose `expires_at` has passed, or whose nonce was already used by the same caller within the window.

**AEVC-AUTH-0006** A command retried with the same `request_id` and an identical envelope MUST return the original receipt without re-executing. Reusing a `request_id` with a different envelope MUST fail with `REPLAY_DETECTED`.

## Audit

**AEVC-AUTH-0007** Authorization denials of authenticated requests in an existing Namespace MUST be recorded as `authorization.denied` journal events (actor, action, error code), in a transaction separate from the rejected command.
