# Releases

Versions tracked independently (see `COMPATIBILITY.md`): protocol, extension contract, conformance suite, and crate/package versions.

## Cutting a release

1. Update `CHANGELOG.md` and `COMPATIBILITY.md`; bump `workspace.package.version` and SDK package versions.
2. Check locally: `cargo publish --workspace --dry-run`, `python3 tooling/release-check/check.py --markers`, `python3 tooling/release-check/coverage.py`, and the generators with `--check`.
3. Create a signed tag `vX.Y.Z` on the release commit. The `release.yml` workflow tests the workspace, runs Scenario K (FULL conformance against the release daemon), builds `openaevcd`, `openaevc-conformance` and `openaevc-inspect` for Linux, macOS and Windows with `--locked` on the pinned toolchain, and produces the source tarball, schemas, conformance fixtures, an SPDX SBOM, `SHA256SUMS`, Sigstore keyless signatures and build-provenance attestations. Publication of crates, the npm package and the PyPI package runs as a dry run; making it real, and tagging the Go module (`sdk/go/vX.Y.Z`), is a deliberate maintainer step.

## Verifying artifacts

Pin the exact repository, workflow and tag: a pattern that admits any owner or ref would accept a signature minted by a fork's copy of the workflow.

```sh
sha256sum -c SHA256SUMS
f=openaevcd-x86_64-unknown-linux-gnu    # each artifact has <f>.sig and <f>.pem beside it
cosign verify-blob --certificate "$f.pem" --signature "$f.sig" \
  --certificate-identity "https://github.com/calvehq/OpenAEVC/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$f"
gh attestation verify "$f" --repo calvehq/OpenAEVC
```

No release has been published yet; every publish step in `release.yml` is a dry run.
