# Generated copies — do not edit

`values.json`, `objects.json` and `signatures.json` are byte-identical copies of
`fixtures/canonical/*.json`, written by `cargo run -p fixture-builder` in the same run as the
originals, so the published `openaevc-conformance` crate is self-contained (`include_str!` cannot
reach outside the package). `cargo run -p fixture-builder -- --check` (CI and release) fails if
either copy differs from what the generator produces.
