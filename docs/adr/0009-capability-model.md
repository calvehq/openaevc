# 0009. Signed capability grants with default deny

- Status: accepted
- Date: 2026-09-26

## Decision

Authority is expressed as issuer-signed capability grants (actions × resource selectors × validity window × delegation depth) rooted at a Namespace's root principals. Delegated grants must be subsets of their parent, cannot outlive it and decrement depth; revoking a grant invalidates all descendants. Anything not allowed by a valid chain is denied. Actors act through a linked key principal and are authorized by their own grants.

## Consequences

Authorization is fully offline-verifiable from grant objects and the revocation registry.
