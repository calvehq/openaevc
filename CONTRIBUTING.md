# Contributing to OpenAEVC

Thanks for helping build OpenAEVC. All development happens in public issues and pull requests.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by:` trailer (`git commit -s`) certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/). There is no CLA.

## Before opening a pull request

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 tooling/release-check/check.py --markers
cargo run -p openaevc-conformance-cli -- --profile full
```

Generated artifacts (schemas, SDK models, fixtures) are checked in. If you change a protocol type, regenerate them (`cargo run -p generate-schemas`, `cargo run -p generate-sdks`, `cargo run -p fixture-builder`) and commit the result; CI fails on any diff.

## Protocol changes

Normative changes follow `GOVERNANCE.md` §Protocol change process: issue/RFC → spec change → schema change → implementation → conformance test → compatibility assessment → changelog entry, all in the same pull request series. A runtime change can never silently redefine protocol law.

## Architecture rules

`tooling/release-check/check.py` enforces the module layering of the `openaevc` crate (table in `crates/openaevc/src/lib.rs`) and its feature gates. Project-owned crates use `#![forbid(unsafe_code)]`; an exception needs an ADR, a dedicated crate, a safety-invariant document and CODEOWNERS approval.

Keep pull requests small enough that reviewers can verify invariants.
