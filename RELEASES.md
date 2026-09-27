# Releases

Versions tracked independently (see `COMPATIBILITY.md`): protocol, extension contract, conformance suite, and crate/package versions.

## Cutting a release

1. Update `CHANGELOG.md` and `COMPATIBILITY.md`; bump `workspace.package.version` and SDK package versions.
2. Run the release check locally: `python3 tooling/release-check/release.py --dry-run`.
3. Create a signed tag `vX.Y.Z` on the release commit. The `release.yml` workflow builds with `--locked` on the pinned toolchain, runs FULL conformance against the packaged daemon, produces SBOMs and checksums, signs artifacts with Sigstore keyless signing, and publishes crates, npm, PyPI, the Go module tag and the optional GHCR image.

## Verifying artifacts

```sh
sha256sum -c SHA256SUMS
cosign verify-blob --certificate openaevcd.pem --signature openaevcd.sig \
  --certificate-identity-regexp 'https://github.com/.*/OpenAEVC/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com openaevcd
```
