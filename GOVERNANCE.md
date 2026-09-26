# Governance

## Roles

- **Maintainers** own releases, security response and final review of protocol, runtime and
  security-sensitive paths (see `.github/CODEOWNERS`). Maintainers triage issues, keep CI green
  and uphold the architectural principles in `spec/README.md`.
- **Reviewers** may approve changes outside CODEOWNERS-protected paths.
- **Contributors** are everyone who opens issues or pull requests.

## Review requirements

- One maintainer approval for any change; a CODEOWNER approval for `spec/`, `schemas/`,
  `crates/openaevc-protocol`, `crates/openaevc-canonical`, `crates/openaevc-crypto`,
  `crates/openaevc-authority`, `crates/openaevc-runtime` and `crates/openaevc-store`.
- All required CI checks green, no unresolved conversations. History is squash-merged.

## Release authority

Any two maintainers may cut a release following `RELEASES.md`.

## Security response authority

Maintainers handle reports per `SECURITY.md`, may prepare fixes privately, and coordinate
disclosure. A single maintainer may ship an emergency security release; a second maintainer
reviews it after the fact.

## Protocol change process

Any normative change (anything marked MUST/SHOULD/MAY in `spec/`) requires:

1. an issue or RFC (`docs/adr/` for decisions with lasting architectural impact);
2. the spec change, with requirement IDs;
3. the schema change if applicable;
4. the implementation change;
5. the conformance test change;
6. a compatibility assessment in `COMPATIBILITY.md`;
7. a `CHANGELOG.md` entry.

## ADRs

Architecture Decision Records live in `docs/adr/NNNN-title.md` using the template in
`docs/adr/0000-template.md`. An ADR is accepted when merged with maintainer approval, and is
superseded (never edited in substance) by a later ADR.

## Becoming a maintainer

Sustained, high-quality contributions and reviews over several months; nominated by a maintainer
and approved by a majority of maintainers with no maintainer objection after one week.

## Conflicts of interest

Maintainers disclose affiliations relevant to a decision and recuse themselves from approving
changes that primarily benefit a product they work on. OpenAEVC must never gain a dependency on
any consumer product.
