//! Controlled lifecycle of a target under test. This is conformance test infrastructure, not part
//! of the OpenAEVC protocol: it lets FULL recovery cases restart an implementation and inspect its
//! data root. Remote targets without a lifecycle report those cases as `NOT_EXERCISED`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub trait Lifecycle: Send + Sync {
    /// Stops the implementation abruptly: from its point of view, a crash.
    fn stop(&self) -> Result<(), String>;
    /// Starts it again on the same data root and endpoint and waits until it serves. `Err`
    /// explains why it did not come up (for example, a fail-closed integrity check).
    fn start(&self) -> Result<(), String>;
    /// The data root the implementation persists to (owned by the test).
    fn data_root(&self) -> &Path;
}

/// The reference daemon `openaevcd run --config <config>`, launched and owned by the harness.
/// The first start pins the TCP address it bound into the configuration, so restarts serve on
/// the same endpoint.
#[derive(Debug)]
pub struct ReferenceDaemon {
    program: PathBuf,
    config: PathBuf,
    data_root: PathBuf,
    child: Mutex<Option<Child>>,
    addr: Mutex<Option<String>>,
}

impl ReferenceDaemon {
    pub fn new(program: PathBuf, config: PathBuf, data_root: PathBuf) -> Self {
        ReferenceDaemon {
            program,
            config,
            data_root,
            child: Mutex::new(None),
            addr: Mutex::new(None),
        }
    }

    /// Starts the daemon and returns the TCP address it listens on.
    pub fn launch(&self) -> Result<String, String> {
        let mut child = Command::new(&self.program)
            .args(["run", "--config"])
            .arg(&self.config)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start {}: {e}", self.program.display()))?;
        let stdout = child.stdout.take().ok_or("daemon has no stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut sent = false;
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let (false, Some(addr)) = (sent, line.split("listening tcp ").nth(1)) {
                    let _ = tx.send(addr.trim().to_owned());
                    sent = true;
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(60);
        let addr = loop {
            if let Ok(a) = rx.recv_timeout(Duration::from_millis(50)) {
                break a;
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("daemon exited during startup ({status})"));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("daemon did not start within 60 s".into());
            }
        };
        *self.child.lock().map_err(|_| "lock")? = Some(child);
        let mut pinned = self.addr.lock().map_err(|_| "lock")?;
        if pinned.is_none() {
            let text = std::fs::read_to_string(&self.config).map_err(|e| e.to_string())?;
            let text = text.replace("tcp = \"127.0.0.1:0\"", &format!("tcp = {addr:?}"));
            std::fs::write(&self.config, text).map_err(|e| e.to_string())?;
            *pinned = Some(addr.clone());
        }
        Ok(addr)
    }
}

impl Lifecycle for ReferenceDaemon {
    fn stop(&self) -> Result<(), String> {
        if let Some(mut c) = self.child.lock().map_err(|_| "lock")?.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        Ok(())
    }

    fn start(&self) -> Result<(), String> {
        self.launch().map(drop)
    }

    fn data_root(&self) -> &Path {
        &self.data_root
    }
}

impl Drop for ReferenceDaemon {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
