# 0008. Immutable, independent Baselines

- Status: accepted
- Date: 2026-09-26

## Decision

Accepted state is a set of immutable Baselines, each committing to a canonical composition graph (members + edges) of promoted pack digests. Baselines never mutate and have no parent relation; overlapping Baselines share promoted objects by digest.

## Consequences

There is no mutable "current" tree; consumers choose which Baseline they consider current.
