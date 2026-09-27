//! End-to-end tests of the packaged daemon binary.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_openaevcd");

fn init(dir: &Path) -> (PathBuf, PathBuf) {
    let config = dir.join("openaevcd.toml");
    let admin = dir.join("admin.key");
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
    (config, admin)
}

#[test]
fn init_creates_protected_keys_and_refuses_to_reinitialize() {
    let dir = tempfile::tempdir().unwrap();
    let (config, admin) = init(dir.path());
    assert!(config.exists() && admin.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in [
            admin.clone(),
            dir.path().join("data/runtime-key/ed25519.seed"),
        ] {
            assert_eq!(
                std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o600,
                "{f:?}"
            );
        }
    }
    let again = Command::new(BIN)
        .args(["init", "--data-root"])
        .arg(dir.path().join("data"))
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already initialized"));
}

#[test]
fn config_validation_and_effective_config() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = init(dir.path());
    let ok = Command::new(BIN)
        .args(["check-config", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    // Remote TCP without TLS is refused.
    let bad = dir.path().join("bad.toml");
    let text = std::fs::read_to_string(&config)
        .unwrap()
        .replace("[listen]", "[listen]\ntcp = \"0.0.0.0:7878\"");
    std::fs::write(&bad, text).unwrap();
    let out = Command::new(BIN)
        .args(["check-config", "--config"])
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("TLS"));
    // Environment overrides are reflected in the effective configuration.
    let out = Command::new(BIN)
        .args(["print-effective-config", "--config"])
        .arg(&config)
        .env("OPENAEVCD_LOG_LEVEL", "debug")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("log_level = \"debug\""), "{text}");
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(config: &Path) -> (Daemon, String) {
    let mut child = Command::new(BIN)
        .args(["run", "--config"])
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let Some(Ok(line)) = lines.next() else { break };
        if let Some(addr) = line.split("listening tcp ").nth(1) {
            std::thread::spawn(move || for _ in lines {});
            return (Daemon(child), addr.trim().to_owned());
        }
    }
    let mut err = String::new();
    let _ = std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err);
    panic!("daemon did not start: {err}");
}

fn with_tcp(config: &Path) {
    let text = std::fs::read_to_string(config)
        .unwrap()
        .replace("[listen]", "[listen]\ntcp = \"127.0.0.1:0\"");
    std::fs::write(config, text).unwrap();
}

fn http_get(addr: &str, path: &str) -> (u16, String) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).unwrap();
    let status = buf.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, buf)
}

#[test]
fn runs_serves_and_shuts_down_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = init(dir.path());
    with_tcp(&config);
    let (mut d, addr) = start(&config);
    assert_eq!(http_get(&addr, "/v1/health/ready").0, 200);
    let (status, body) = http_get(&addr, "/v1/info");
    assert_eq!(status, 200);
    assert!(body.contains("\"protocol\""));
    // A second daemon on the same data root is refused (single writer).
    let second = Command::new(BIN)
        .args(["run", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("in use"));
    #[cfg(unix)]
    {
        let pid = d.0.id().to_string();
        assert!(Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = d.0.try_wait().unwrap() {
                assert!(status.success(), "{status:?}");
                break;
            }
            assert!(Instant::now() < deadline, "daemon did not stop on SIGTERM");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[test]
fn refuses_to_run_without_initialization() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = init(dir.path());
    std::fs::remove_file(dir.path().join("data/runtime-key/ed25519.seed")).unwrap();
    let out = Command::new(BIN)
        .args(["run", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("openaevcd init"));
}
