# Capabilities

A capability grant is a `SignedGrant`: a `GrantBody` plus the issuer's Ed25519 signature over
`canonical(body)` in the `grant` domain.

| Field | Meaning |
|-------|---------|
| `id` | `grt_` identifier chosen by the issuer. |
| `namespace` | Namespace the grant is valid in. |
| `issuer` / `subject` | Issuing principal / receiving principal (may be an ACTOR). |
| `actions` | Set of action patterns: exact (`changepack.seal`), `prefix.*`, or `*`. |
| `resources` | Resource selectors `{kind, locator_prefix?}`; `kind` is exact, `prefix.*` or `*`. Empty means all resources. |
| `constraints` | Namespaced constraint map. Protocol 0.1 defines no core constraints; delegation must preserve them. |
| `not_before` / `expires_at` | Validity window `[not_before, expires_at)`. |
| `delegation_depth` | How many further delegation levels are allowed. |
| `parent` | Digest of the parent grant object, for delegated grants. |
| `nonce` | Issuer-chosen uniqueness value. |

A pattern `p.*` matches any action or kind with prefix `p.` (at least one more segment).

## Validity

**AEVC-CAP-0001** A grant MUST be rejected unless its signature verifies with the issuer's registered
key, its namespace matches, and `not_before <= now < expires_at` (`CAPABILITY_EXPIRED` after
expiry).

**AEVC-CAP-0002** A grant without `parent` is valid only when its issuer is a root principal of the
Namespace. Unknown issuers and unknown parents fail closed.

**AEVC-CAP-0003** A delegated grant is valid only when: its parent is valid; the parent's `subject`
is the child's `issuer`; the parent's `delegation_depth` > 0 and the child's depth is strictly
lower; the child neither outlives nor predates the parent; every child action pattern is covered
by a parent pattern; every child resource selector is covered by a parent selector (a child with
no selectors is only covered by a parent with none); and every parent constraint appears unchanged
in the child.

**AEVC-CAP-0004** `IssueCapabilityGrant` MUST be called by the grant's issuer, who must hold
`grant.issue`. The runtime validates the whole chain at issue time and again at every use.

## Revocation

**AEVC-CAP-0005** `RevokeCapabilityGrant` records an immutable `revocation` object and adds the grant
to the Namespace revocation registry. A revoked grant and every grant delegated from it (directly
or transitively) MUST fail with `CAPABILITY_REVOKED` from that point on. Revocation cannot be
undone; issue a new grant instead. The revoker must hold `grant.revoke` and be the grant's issuer
or a root principal.

## Matching

To authorize `(principal, action, resource?)` the runtime considers the principal's grants whose
action patterns match and whose selectors match the resource (or any grant, when the action is not
resource-scoped), and succeeds with the first one whose chain is valid. The decision records the
chain's grant digests (leaf first) as provenance.

`fixtures/authority/matrix.json` is the normative authorization test matrix.
