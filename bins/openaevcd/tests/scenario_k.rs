//! Scenario K: `openaevcd`, started from a clean data root, passes FULL conformance over the v1
//! transport — including real crash/restart recovery, driven through the harness-owned daemon
//! lifecycle. CI runs this against the release build (`cargo test --release`).
//!
//! Set `OPENAEVC_CONFORMANCE_REPORT_DIR` to keep the JSON and JUnit reports as release evidence.

use std::process::Command;
use std::sync::Arc;

use openaevc::crypto::SigningKey;
use openaevc::protocol::PrincipalId;
use openaevc::transport::client::Endpoint;
use openaevc_conformance::lifecycle::ReferenceDaemon;
use openaevc_conformance::{run, Profile, Target};
use openaevc_testkit::Extensions;

const BIN: &str = env!("CARGO_BIN_EXE_openaevcd");

#[tokio::test(flavor = "multi_thread")]
async fn scenario_k_daemon_passes_full_conformance_remotely() {
    let ext = Extensions::install();
    let dir = tempfile::tempdir().unwrap();
    let (config, admin, data) = (
        dir.path().join("openaevcd.toml"),
        dir.path().join("admin.json"),
        dir.path().join("data"),
    );
    let out = Command::new(BIN)
        .args(["init", "--data-root"])
        .arg(&data)
        .arg("--config-out")
        .arg(&config)
        .arg("--admin-key-out")
        .arg(&admin)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Short intervals so checkpoint and lease-expiry cases finish quickly; extension limits
    // below the misbehaving fixtures' 30 s sleep and 8 MiB output.
    let text: String = std::fs::read_to_string(&config)
        .unwrap()
        .replace("[listen]", "[listen]\ntcp = \"127.0.0.1:0\"")
        .replace(
            "[extensions]\ndirectories = []",
            &format!(
                "[extensions]\ndirectories = [{:?}]",
                ext.dir.path().display().to_string()
            ),
        )
        .lines()
        .map(|l| match l.split(" = ").next() {
            Some("checkpoint_interval") => "checkpoint_interval = 10".to_owned(),
            Some("lease_ms") => "lease_ms = 10000".to_owned(),
            Some("heartbeat_interval_ms") => "heartbeat_interval_ms = 2000".to_owned(),
            Some("tick_interval_ms") => "tick_interval_ms = 200".to_owned(),
            Some("deadline_ms") => "deadline_ms = 10000".to_owned(),
            Some("max_frame_bytes") => "max_frame_bytes = 1048576".to_owned(),
            _ => l.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&config, text + "\n").unwrap();

    let daemon = Arc::new(ReferenceDaemon::new(BIN.into(), config, data));
    let addr = daemon.launch().unwrap();

    let a: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&admin).unwrap()).unwrap();
    let seed = a["seed"].as_str().unwrap();
    let seed: [u8; 32] = (0..32)
        .map(|i| u8::from_str_radix(&seed[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let admin_id: PrincipalId = a["id"].as_str().unwrap().parse().unwrap();
    let target = Target::remote(
        Endpoint::Tcp(addr),
        Arc::new(SigningKey::from_seed(seed)),
        admin_id,
        Some(ext.dir.path().to_path_buf()),
        10,
    )
    .with_lifecycle(daemon.clone());
    let report = run(target, Profile::Full, None).await;
    println!("{}", report.summary());
    if let Some(out) = std::env::var_os("OPENAEVC_CONFORMANCE_REPORT_DIR") {
        let out = std::path::PathBuf::from(out);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("scenario-k-full-remote.json"), report.json()).unwrap();
        std::fs::write(out.join("scenario-k-full-remote.xml"), report.junit()).unwrap();
    }
    assert!(report.conformant(), "{}", report.summary());
    assert!(
        report
            .cases
            .iter()
            .any(|c| c.id == "full.recovery" && c.status == openaevc_conformance::Status::Passed),
        "the daemon restart recovery case must run and pass"
    );
}
