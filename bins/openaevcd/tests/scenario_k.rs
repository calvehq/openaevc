//! Scenario K: `openaevcd`, started from a clean data root, passes FULL conformance over the v1
//! transport. CI runs this against the release build (`cargo test --release`).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use openaevc_conformance::{run, Profile, Target};
use openaevc_crypto::SigningKey;
use openaevc_protocol::PrincipalId;
use openaevc_testkit::Extensions;
use openaevc_transport::client::Endpoint;

const BIN: &str = env!("CARGO_BIN_EXE_openaevcd");

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn scenario_k_daemon_passes_full_conformance_remotely() {
    let ext = Extensions::install();
    let dir = tempfile::tempdir().unwrap();
    let (config, admin) = (
        dir.path().join("openaevcd.toml"),
        dir.path().join("admin.json"),
    );
    let out = Command::new(BIN)
        .args(["init", "--data-root"])
        .arg(dir.path().join("data"))
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
    // Short intervals so checkpoint and lease-expiry cases finish quickly.
    let text = std::fs::read_to_string(&config)
        .unwrap()
        .replace("[listen]", "[listen]\ntcp = \"127.0.0.1:0\"")
        .replace("checkpoint_interval = 1000", "checkpoint_interval = 10")
        .replace("lease_ms = 30000", "lease_ms = 10000")
        .replace(
            "heartbeat_interval_ms = 10000",
            "heartbeat_interval_ms = 2000",
        )
        .replace("tick_interval_ms = 1000", "tick_interval_ms = 200")
        .replace(
            "[extensions]\ndirectories = []",
            &format!(
                "[extensions]\ndirectories = [{:?}]",
                ext.dir.path().display().to_string()
            ),
        );
    std::fs::write(&config, text).unwrap();
    let mut child = Command::new(BIN)
        .args(["run", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let daemon = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(30);
    let addr = loop {
        assert!(Instant::now() < deadline, "daemon did not start");
        let line = lines.next().expect("daemon exited").unwrap();
        if let Some(addr) = line.split("listening tcp ").nth(1) {
            break addr.trim().to_owned();
        }
    };
    std::thread::spawn(move || for _ in lines {});

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
    );
    let report = run(target, Profile::Full, None).await;
    println!("{}", report.summary());
    assert!(report.conformant(), "{}", report.summary());
    drop(daemon);
}
