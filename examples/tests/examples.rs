//! Runs every example flow so the examples stay correct.

use openaevc::protocol::ErrorCode;
use openaevc_testkit::Extensions;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn embedded_runtime_example() {
    let d = tempfile::tempdir().unwrap();
    let s = rt()
        .block_on(openaevc_examples::embedded_runtime::run(d.path()))
        .unwrap();
    assert!(s.valid);
}

#[test]
fn authority_flow_example() {
    let d = tempfile::tempdir().unwrap();
    let o = rt()
        .block_on(openaevc_examples::authority_flow::run(d.path()))
        .unwrap();
    assert!(o.bob_before);
    assert_eq!(o.bob_other_action, ErrorCode::Forbidden);
    assert_eq!(o.bob_after, ErrorCode::CapabilityRevoked);
}

#[test]
fn execute_verify_promote_example() {
    let ext = Extensions::install();
    let d = tempfile::tempdir().unwrap();
    let o = rt()
        .block_on(openaevc_examples::execute_verify_promote::run(
            d.path(),
            ext.dir.path(),
        ))
        .unwrap();
    assert_eq!(
        (o.verification.as_str(), o.qualification.as_str()),
        ("PASS", "QUALIFIED")
    );
}

#[test]
fn baseline_composition_example() {
    let ext = Extensions::install();
    let d = tempfile::tempdir().unwrap();
    let o = rt()
        .block_on(openaevc_examples::baseline_composition::run(
            d.path(),
            ext.dir.path(),
        ))
        .unwrap();
    assert_eq!(o.unordered_conflict, ErrorCode::CompositionInvalid);
    assert_eq!(o.independent.len(), 2);
}

#[test]
fn custom_rust_extension_example() {
    let ext = tempfile::tempdir().unwrap();
    let name = format!(
        "openaevc-example-counter-extension{}",
        std::env::consts::EXE_SUFFIX
    );
    std::fs::copy(
        env!("CARGO_BIN_EXE_openaevc-example-counter-extension"),
        ext.path().join(&name),
    )
    .unwrap();
    let d = tempfile::tempdir().unwrap();
    let status = rt()
        .block_on(openaevc_examples::custom_extension::run_counter(
            d.path(),
            ext.path(),
            &name,
        ))
        .unwrap();
    assert_eq!(status, "PASS");
}

#[cfg(unix)]
#[test]
fn custom_python_extension_example() {
    let ext = tempfile::tempdir().unwrap();
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    std::fs::copy(
        root.join("custom-extension-python/extension.py"),
        ext.path().join("extension.py"),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        ext.path().join("extension.py"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let pkg = ext.path().join("openaevc");
    std::fs::create_dir(&pkg).unwrap();
    for f in std::fs::read_dir(root.join("../sdk/python/openaevc")).unwrap() {
        let f = f.unwrap().path();
        if f.extension().is_some_and(|e| e == "py") {
            std::fs::copy(&f, pkg.join(f.file_name().unwrap())).unwrap();
        }
    }
    let d = tempfile::tempdir().unwrap();
    let status = rt()
        .block_on(openaevc_examples::custom_extension::run_python_tally(
            d.path(),
            ext.path(),
        ))
        .unwrap();
    assert_eq!(status, "PASS");
}
