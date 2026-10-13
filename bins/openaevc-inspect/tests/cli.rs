//! openaevc-inspect behaviour against golden fixtures and live stores/daemons.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_openaevc-inspect");

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/canonical")
}

fn run(args: &[&str]) -> (bool, String, String) {
    let o = Command::new(BIN).args(args).output().unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn object_fixture(dir: &Path) -> (PathBuf, String, String) {
    let f: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("objects.json")).unwrap())
            .unwrap();
    let c = &f["valid"][0];
    let hex = c["cbor_hex"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let p = dir.join("object.cbor");
    std::fs::write(&p, bytes).unwrap();
    (
        p,
        c["digest"].as_str().unwrap().to_owned(),
        c["kind"].as_str().unwrap().to_owned(),
    )
}

#[test]
fn decode_digest_and_verify_object() {
    let dir = tempfile::tempdir().unwrap();
    let (p, digest, kind) = object_fixture(dir.path());
    let path = p.to_str().unwrap();
    let (ok, out, _) = run(&["decode", path]);
    assert!(ok);
    assert!(out.contains(&format!("\"kind\": \"{kind}\"")), "{out}");
    let (ok, out, _) = run(&["digest", path]);
    assert!(ok && out.trim() == digest, "{out}");
    let (ok, out, _) = run(&["verify-object", path]);
    assert!(
        ok && out.contains("valid") && out.contains(&digest),
        "{out}"
    );
    // Tampered object fails.
    let mut b = std::fs::read(&p).unwrap();
    let n = b.len();
    b[n - 1] ^= 1;
    std::fs::write(&p, b).unwrap();
    let (ok, _, err) = run(&["verify-object", path]);
    assert!(!ok, "{err}");
}

#[test]
fn canonicalize_json() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("v.json");
    std::fs::write(&p, r#"{ "b": 2, "a": [true, "x"], "aa": 1 }"#).unwrap();
    let (ok, out, _) = run(&["canonicalize", p.to_str().unwrap()]);
    assert!(ok);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], r#"{"a":[true,"x"],"b":2,"aa":1}"#);
    assert!(lines[1].starts_with("cbor "));
    assert!(lines[2].starts_with("digest sha256:"));
    std::fs::write(&p, r#"{"x": 1.5}"#).unwrap();
    let (ok, _, err) = run(&["canonicalize", p.to_str().unwrap()]);
    assert!(!ok && err.contains("floating"), "{err}");
}

#[test]
fn schema_lookup() {
    let (ok, out, _) = run(&["schema", "CommandEnvelope"]);
    assert!(ok && out.contains("\"signature\""), "{out}");
    let (ok, out, _) = run(&["schema", "list"]);
    assert!(ok && out.lines().any(|l| l == "PromotedPack"));
    assert!(!run(&["schema", "Nope"]).0);
}

#[test]
fn verify_journal_on_a_data_root() {
    let dir = tempfile::tempdir().unwrap();
    {
        let h = openaevc_testkit::Harness::sqlite(dir.path());
        let root = openaevc_testkit::Identity::generate();
        h.create_namespace(&root);
    }
    let (ok, out, _) = run(&["verify-journal", dir.path().to_str().unwrap()]);
    assert!(ok && out.contains("ok"), "{out}");
}

#[test]
fn compatibility_against_a_live_daemon() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let h = openaevc_testkit::Harness::new();
    let addr = rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let (stop, rx) = tokio::sync::watch::channel(false);
        std::mem::forget(stop);
        let app = openaevc::transport::server::router(
            h.rt.clone(),
            Default::default(),
            std::sync::Arc::new(openaevc::transport::server::Health::ready()),
        );
        tokio::spawn(openaevc::transport::server::serve(
            openaevc::transport::server::Listener::Tcp(l),
            app,
            rx,
        ));
        addr
    });
    let (ok, out, err) = run(&["compatibility", &addr]);
    assert!(ok, "{err}");
    assert!(out.contains("negotiated protocol 0.1.0"), "{out}");
    drop(rt);
}
