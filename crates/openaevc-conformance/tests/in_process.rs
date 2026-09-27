//! The reference runtime passes every profile of its own conformance suite.

use openaevc_conformance::{run, Profile, Target};
use openaevc_testkit::Extensions;

#[tokio::test(flavor = "multi_thread")]
async fn reference_runtime_is_fully_conformant() {
    let ext = Extensions::install();
    let target = Target::in_process(Some(ext.dir.path().to_path_buf()), true).unwrap();
    let report = run(
        target,
        Profile::Full,
        std::env::var("CONFORMANCE_FILTER").ok().as_deref(),
    )
    .await;
    println!("{}", report.summary());
    assert!(report.conformant(), "{}", report.summary());
}

#[tokio::test(flavor = "multi_thread")]
async fn extension_executables_pass_the_extension_checks() {
    let ext = Extensions::install();
    for name in [
        "openaevc-ext-reference-kv",
        "openaevc-ext-reference-null",
        "conformance-fixture-well-behaved",
    ] {
        let report = openaevc_conformance::extension_target::check(&ext.path(name));
        assert!(report.conformant(), "{name}: {}", report.summary());
    }
    let report = openaevc_conformance::extension_target::check(
        &ext.path("conformance-fixture-wrong-digest"),
    );
    assert!(!report.conformant(), "a wrong manifest digest must fail");
}
