//! Scenario J: the same flow from the Rust, TypeScript, Python and Go SDKs against one packaged
//! `openaevcd`. A missing language toolchain fails the test unless
//! `OPENAEVC_ALLOW_MISSING_TOOLCHAINS=1`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use openaevc_crypto::SigningKey;
use openaevc_protocol::*;
use openaevc_sdk::{OpenAevcClient, RemoteClient, Session, TypedClient};
use openaevc_testkit::Extensions;
use openaevc_transport::client::Endpoint;
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_openaevcd");

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn start_daemon(dir: &Path, ext_dir: &Path) -> (Daemon, String, PathBuf) {
    let config = dir.join("openaevcd.toml");
    let admin = dir.join("admin.json");
    let out = Command::new(BIN)
        .args(["init", "--data-root"])
        .arg(dir.join("data"))
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
    let text = std::fs::read_to_string(&config)
        .unwrap()
        .replace("[listen]", "[listen]\ntcp = \"127.0.0.1:0\"")
        .replace(
            "[extensions]\ndirectories = []",
            &format!(
                "[extensions]\ndirectories = [{:?}]",
                ext_dir.display().to_string()
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
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match lines.next() {
            Some(Ok(line)) => {
                if let Some(addr) = line.split("listening tcp ").nth(1) {
                    std::thread::spawn(move || for _ in lines {});
                    return (Daemon(child), addr.trim().to_owned(), admin);
                }
            }
            _ => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("daemon did not start");
}

fn allow_missing() -> bool {
    std::env::var("OPENAEVC_ALLOW_MISSING_TOOLCHAINS").as_deref() == Ok("1")
}

fn find(tool: &str, extra: &[PathBuf]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(extra.iter().cloned())
        .flat_map(|d| {
            [
                d.join(tool),
                d.join(format!("{tool}{}", std::env::consts::EXE_SUFFIX)),
            ]
        })
        .find(|p| p.is_file())
}

fn run_sdk(name: &str, mut cmd: Command, env: &[(&str, String)]) {
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(
        out.status.success(),
        "{name} e2e failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

async fn rust_flow(addr: &str, admin: &Path, kv: &str, kv_digest: Digest) {
    let a: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(admin).unwrap()).unwrap();
    let seed: [u8; 32] = (0..32)
        .map(|i| u8::from_str_radix(&a["seed"].as_str().unwrap()[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let admin_id: PrincipalId = a["id"].as_str().unwrap().parse().unwrap();
    let ep = Endpoint::Tcp(addr.to_owned());
    let ac = RemoteClient::connect(
        ep.clone(),
        Session::new(Arc::new(SigningKey::from_seed(seed)), admin_id, None),
    )
    .await
    .unwrap();
    let root = Arc::new(SigningKey::generate());
    use openaevc_crypto::Signer;
    let (ns, roots) = ac
        .create_namespace(vec![NewPrincipal {
            kind: PrincipalKind::Key,
            public_key: Some(root.public_key()),
            linked_to: None,
            attributes: Default::default(),
        }])
        .await
        .unwrap();
    let c = RemoteClient::new(ep, Session::new(root, roots[0], Some(ns)));
    c.register_extension(kv, kv_digest, vec![HostCapability::ResourceRead])
        .await
        .unwrap();
    c.command(openaevc_protocol::Command::RegisterProvider {
        provider: openaevc_testkit::provider_descriptor(roots[0], false),
    })
    .await
    .unwrap();
    let pack = c.create_change_pack(PackSpec::default()).await.unwrap();
    let wu = c.add_work_unit(pack, 1, "org.example.task").await.unwrap();
    let mut req = openaevc_testkit::Harness::new().execution_request(pack, 2, wu);
    req.allowed_effects = vec!["kv.set".into()];
    let (_, lease) = c.start_execution(req).await.unwrap();
    c.heartbeat(&lease).await.unwrap();
    assert!(c
        .submit_effect(&lease, openaevc_testkit::kv_set("lang", "rust"))
        .await
        .unwrap());
    c.complete_execution(&lease).await.unwrap();
    let candidate = c.seal(pack, 2).await.unwrap();
    assert_eq!(
        c.run_verification(
            pack,
            2,
            "kv.expect",
            json!({"key": "lang", "value": "rust"})
        )
        .await
        .unwrap()
        .result
        .state
        .as_deref(),
        Some("PASS")
    );
    assert_eq!(
        c.refresh_qualification(pack, 2)
            .await
            .unwrap()
            .result
            .state
            .as_deref(),
        Some("QUALIFIED")
    );
    let promoted = c.promote(pack, 2).await.unwrap();
    let (_, baseline) = c.create_baseline(vec![promoted], vec![]).await.unwrap();
    assert_eq!(
        c.query(Query::ValidateBaseline { digest: baseline })
            .await
            .unwrap()["valid"],
        true
    );
    assert_eq!(c.get_object(candidate).await.unwrap().digest(), candidate);
}

#[test]
fn scenario_j_all_sdks_against_one_daemon() {
    let ext = Extensions::install();
    let dir = tempfile::tempdir().unwrap();
    let (_daemon, addr, admin) = start_daemon(dir.path(), ext.dir.path());
    let kv = Extensions::entrypoint("openaevc-ext-reference-kv");
    let kv_digest = ext.digest("openaevc-ext-reference-kv");
    // Rust.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(rust_flow(&addr, &admin, &kv, kv_digest));
    let env = [
        ("OPENAEVC_ENDPOINT", addr.clone()),
        ("OPENAEVC_ADMIN_KEY", admin.display().to_string()),
        ("OPENAEVC_KV_ENTRYPOINT", kv.clone()),
        ("OPENAEVC_KV_DIGEST", kv_digest.to_string()),
    ];
    let root = repo();
    let home_go = PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/go/bin");
    let mut missing = Vec::new();
    // TypeScript.
    match find("node", &[]) {
        Some(node) => {
            let mut c = Command::new(node);
            c.current_dir(root.join("sdk/typescript")).args([
                "--experimental-strip-types",
                "--no-warnings",
                "test/e2e.ts",
            ]);
            run_sdk("typescript", c, &env);
        }
        None => missing.push("node"),
    }
    // Python.
    match find("python3", &[]).or_else(|| find("python", &[])) {
        Some(py) => {
            let mut c = Command::new(py);
            c.current_dir(root.join("sdk/python")).arg("tests/e2e.py");
            run_sdk("python", c, &env);
        }
        None => missing.push("python3"),
    }
    // Go.
    match find("go", &[home_go]) {
        Some(go) => {
            let mut c = Command::new(go);
            c.current_dir(root.join("sdk/go"))
                .args(["test", "-count=1", "-run", "TestE2E", "./..."]);
            run_sdk("go", c, &env);
        }
        None => missing.push("go"),
    }
    assert!(
        missing.is_empty() || allow_missing(),
        "missing SDK toolchains: {missing:?}"
    );
}
