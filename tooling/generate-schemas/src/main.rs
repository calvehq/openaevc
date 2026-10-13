//! `cargo run -p generate-schemas [-- --check]`
//!
//! Writes `schemas/json/openaevc.schema.json`, `schemas/cddl/openaevc.cddl` and
//! `schemas/openapi/openapi.json` (plus the copy embedded by `openaevc-inspect`). With `--check`, fails if the checked-in files differ.

use generate_schemas::{cddl, json_schema, root};

fn main() {
    let check = std::env::args().any(|a| a == "--check");
    let schema = json_schema();
    let json = serde_json::to_string_pretty(&schema).unwrap() + "\n";
    let files = [
        ("schemas/json/openaevc.schema.json", json.clone()),
        // Package-local copy so the published `openaevc-inspect` crate is self-contained.
        ("bins/openaevc-inspect/openaevc.schema.json", json),
        ("schemas/cddl/openaevc.cddl", cddl(&schema)),
        (
            "schemas/openapi/openapi.json",
            serde_json::to_string_pretty(&openaevc::transport::openapi::document()).unwrap() + "\n",
        ),
    ];
    let mut stale = false;
    for (rel, content) in files {
        let path = root().join(rel);
        if check {
            if std::fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
                eprintln!("{rel} is out of date; run `cargo run -p generate-schemas`");
                stale = true;
            }
        } else {
            std::fs::write(&path, content).unwrap_or_else(|e| panic!("writing {rel}: {e}"));
            println!("wrote {rel}");
        }
    }
    if stale {
        std::process::exit(1);
    }
}
