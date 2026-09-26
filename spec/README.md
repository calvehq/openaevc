# OpenAEVC Protocol Specification

Protocol version **0.1.0**. This directory is the normative definition of OpenAEVC. The Rust
reference implementation follows the spec; where they disagree the spec wins and the
implementation is a bug.

## Conventions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are to be
interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all
capitals.

Every normative requirement carries a stable identifier of the form `AEVC-<AREA>-<NNNN>`,
written in bold at the start of the requirement, for example:

> **AEVC-ENC-0001** Canonical objects MUST be encoded as deterministic CBOR.

Identifiers are never reused or renumbered. A withdrawn requirement keeps its ID with the text
"Withdrawn in <version>". Every requirement ID containing MUST or MUST NOT is covered by at least
one conformance case (`spec/conformance.md`); `tooling/release-check/coverage.py` enforces this.

| Area | File | Area | File |
|------|------|------|------|
| VOC | vocabulary.md | EVD | evidence.md |
| OBJ | object-model.md | VRF | verification.md |
| ENC | canonical-encoding.md | EVL | evaluation.md |
| ID  | identity-and-digests.md | POL | policy.md |
| NS  | namespace.md | PRO | promotion.md |
| AUTH | authority.md | REV | revisions.md |
| CAP | capabilities.md | BSL | baseline.md |
| ACG | active-change-graph.md | CMP | composition.md |
| LIFE | changepack.md | EXT | extensions.md |
| EXE | execution.md | EVT | events.md |
| OBS | observations.md | TRN | transport.md |
| XCH | object-exchange.md | REC | recovery.md |
| ERR | errors.md | VER | versioning.md |
| SEC | security-model.md | CONF | conformance.md |

## Architectural principles (informative summary)

1. **Domain neutrality.** Nothing in the protocol assumes source code, files, repositories or
   any particular product. Domains are added through extensions.
2. **Single authority.** Lifecycle, authorization, qualification, promotion and composition
   decisions are made only by the runtime.
3. **Immutable history.** Accepted objects never change. Later change is new objects plus
   explicit relationships.
4. **Mutable work, immutable acceptance.** ChangePacks evolve through numbered generations until
   promotion freezes a snapshot.
5. **Explicit composition.** Accepted state is a set of independent immutable Baselines.
6. **Three state layers.** Immutable Object Store, Accepted Composition, Active Change Graph.
7. **Library boundary is not a trust boundary.** Embedded and daemon callers pass through the
   same admission and authorization path.
