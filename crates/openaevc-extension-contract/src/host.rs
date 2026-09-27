//! Reference out-of-process extension host (spec/extensions.md §Process contract).
//!
//! Each invocation spawns the extension executable with a cleared environment, performs the
//! handshake, sends one `invoke`, services host calls, and waits for the result. The host
//! enforces a deadline for the whole exchange, a maximum frame size, a host-call budget and
//! per-invocation capability grants; any violation kills the process and fails closed.
//! Extensions never receive storage paths, database handles or runtime credentials.

use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use openaevc_protocol::{
    err, ErrorCode, ExtensionErrorInfo, ExtensionManifest, HostCapability, ProtocolError,
    ProtocolVersion, SUPPORTED_CONTRACT, SUPPORTED_PROTOCOL,
};
use serde_json::Value;

use crate::wire::{
    read_frame, write_frame, ExtensionMessage, FrameError, HostCall, HostMessage, Operation,
    WireError,
};

#[derive(Debug, Clone)]
pub struct HostLimits {
    pub max_frame: usize,
    pub deadline: Duration,
    pub max_host_calls: u32,
    pub max_stderr: usize,
}

impl Default for HostLimits {
    fn default() -> Self {
        HostLimits {
            max_frame: 4 * 1024 * 1024,
            deadline: Duration::from_secs(10),
            max_host_calls: 1024,
            max_stderr: 64 * 1024,
        }
    }
}

/// Resolved executable and arguments.
#[derive(Debug, Clone)]
pub struct Entrypoint {
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// Outcome of servicing one host call.
#[derive(Debug)]
pub enum CallError {
    /// Recoverable failure reported back to the extension.
    Failed(WireError),
    /// Privilege violation: the invocation is terminated and fails closed.
    Denied(String),
}

pub trait HostCallHandler {
    fn handle(&mut self, call: &HostCall) -> Result<Value, CallError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    Spawn(String),
    Incompatible(String),
    Protocol(String),
    Deadline,
    Denied(String),
    Extension(WireError),
}

impl HostError {
    pub fn into_protocol(self, extension_id: &str) -> ProtocolError {
        let (code, message, ext_code) = match self {
            HostError::Spawn(m) => (
                ErrorCode::ExtensionFailed,
                format!("extension could not be started: {m}"),
                "spawn",
            ),
            HostError::Incompatible(m) => (ErrorCode::ExtensionIncompatible, m, "incompatible"),
            HostError::Protocol(m) => (
                ErrorCode::ExtensionFailed,
                format!("extension protocol violation: {m}"),
                "protocol",
            ),
            HostError::Deadline => (
                ErrorCode::ExtensionFailed,
                "extension exceeded its deadline".into(),
                "deadline",
            ),
            HostError::Denied(m) => (
                ErrorCode::ExtensionFailed,
                format!("extension attempted a privileged operation it was not granted: {m}"),
                "denied",
            ),
            HostError::Extension(w) => {
                let info = ExtensionErrorInfo {
                    extension_id: extension_id.into(),
                    code: w.code.clone(),
                    message: w.message.clone(),
                };
                return ProtocolError::new(
                    ErrorCode::ExtensionFailed,
                    format!("extension {extension_id} reported {}", w.code),
                )
                .with_extension_error(info);
            }
        };
        ProtocolError::new(code, message.clone()).with_extension_error(ExtensionErrorInfo {
            extension_id: extension_id.into(),
            code: ext_code.into(),
            message,
        })
    }
}

enum Incoming {
    Msg(ExtensionMessage),
    Bad(String),
    Eof,
}

struct Session {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Incoming>,
    started: Instant,
    limits: HostLimits,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

impl Session {
    fn spawn(ep: &Entrypoint, limits: &HostLimits) -> Result<Self, HostError> {
        let mut cmd = Command::new(&ep.program);
        cmd.args(&ep.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        if let Some(dir) = ep.program.parent() {
            cmd.current_dir(dir);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| HostError::Spawn(e.kind().to_string()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| HostError::Spawn("no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| HostError::Spawn("no stdout".into()))?;
        let stderr = child.stderr.take();
        let (tx, rx) = mpsc::channel();
        let max = limits.max_frame;
        thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            loop {
                let item = match read_frame::<ExtensionMessage, _>(&mut r, max) {
                    Ok(Some(m)) => Incoming::Msg(m),
                    Ok(None) => Incoming::Eof,
                    Err(FrameError::TooLarge(n)) => {
                        Incoming::Bad(format!("frame of {n} bytes exceeds the {max}-byte limit"))
                    }
                    Err(e) => Incoming::Bad(e.to_string()),
                };
                let stop = !matches!(item, Incoming::Msg(_));
                if tx.send(item).is_err() || stop {
                    return;
                }
            }
        });
        let max_err = limits.max_stderr;
        let stderr = stderr.map(|mut s| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while let Ok(n) = s.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    if buf.len() < max_err {
                        buf.extend_from_slice(&chunk[..n.min(max_err - buf.len())]);
                    }
                }
                buf
            })
        });
        Ok(Session {
            child,
            stdin,
            rx,
            started: Instant::now(),
            limits: limits.clone(),
            stderr,
        })
    }

    fn send(&mut self, msg: &HostMessage) -> Result<(), HostError> {
        write_frame(&mut self.stdin, msg)
            .map_err(|e| HostError::Protocol(format!("write failed: {}", e.kind())))
    }

    fn recv(&mut self) -> Result<ExtensionMessage, HostError> {
        let remaining = self
            .limits
            .deadline
            .checked_sub(self.started.elapsed())
            .ok_or(HostError::Deadline)?;
        match self.rx.recv_timeout(remaining) {
            Ok(Incoming::Msg(m)) => Ok(m),
            Ok(Incoming::Bad(m)) => Err(HostError::Protocol(m)),
            Ok(Incoming::Eof) | Err(RecvTimeoutError::Disconnected) => {
                Err(HostError::Protocol("extension closed its output".into()))
            }
            Err(RecvTimeoutError::Timeout) => Err(HostError::Deadline),
        }
    }

    fn remaining_ms(&self) -> u64 {
        self.limits
            .deadline
            .saturating_sub(self.started.elapsed())
            .as_millis() as u64
    }

    fn handshake(&mut self) -> Result<(ExtensionManifest, ProtocolVersion), HostError> {
        self.send(&HostMessage::Hello {
            protocol: SUPPORTED_PROTOCOL,
            contract: SUPPORTED_CONTRACT,
        })?;
        match self.recv()? {
            ExtensionMessage::Hello {
                manifest,
                protocol,
                contract,
            } => {
                let version = SUPPORTED_PROTOCOL.negotiate(&protocol).ok_or_else(|| {
                    HostError::Incompatible(format!(
                        "no common protocol version (extension supports {}..={})",
                        protocol.min, protocol.max
                    ))
                })?;
                SUPPORTED_CONTRACT.negotiate(&contract).ok_or_else(|| {
                    HostError::Incompatible(format!(
                        "no common contract version (extension supports {}..={})",
                        contract.min, contract.max
                    ))
                })?;
                if manifest.protocol != protocol || manifest.contract != contract {
                    return Err(HostError::Incompatible(
                        "handshake ranges differ from the manifest".into(),
                    ));
                }
                Ok((manifest, version))
            }
            _ => Err(HostError::Protocol("expected hello".into())),
        }
    }

    /// Ends the session; kills the process if it does not exit promptly.
    fn close(mut self, graceful: bool) -> Vec<u8> {
        if graceful {
            let _ = self.send(&HostMessage::Shutdown {});
            let until = Instant::now() + Duration::from_millis(500);
            while Instant::now() < until {
                if let Ok(Some(_)) = self.child.try_wait() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stderr
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_default()
    }
}

/// Performs only the handshake, returning the manifest and negotiated protocol version.
pub fn handshake(
    ep: &Entrypoint,
    limits: &HostLimits,
) -> Result<(ExtensionManifest, ProtocolVersion), HostError> {
    let mut s = Session::spawn(ep, limits)?;
    let r = s.handshake();
    s.close(r.is_ok());
    r
}

/// Result of one invocation plus diagnostics.
#[derive(Debug, Clone)]
pub struct InvocationResult {
    pub output: Value,
    pub stderr: Vec<u8>,
}

/// Runs one operation on a fresh extension process.
pub fn invoke(
    ep: &Entrypoint,
    limits: &HostLimits,
    expected_manifest: &ExtensionManifest,
    operation: Operation,
    granted: Vec<HostCapability>,
    handler: &mut dyn HostCallHandler,
) -> Result<InvocationResult, HostError> {
    let mut s = Session::spawn(ep, limits)?;
    let r = run(&mut s, expected_manifest, operation, granted, handler);
    let ok = r.is_ok();
    let stderr = s.close(ok);
    r.map(|output| InvocationResult { output, stderr })
}

fn run(
    s: &mut Session,
    expected: &ExtensionManifest,
    operation: Operation,
    granted: Vec<HostCapability>,
    handler: &mut dyn HostCallHandler,
) -> Result<Value, HostError> {
    let (manifest, _) = s.handshake()?;
    if &manifest != expected {
        return Err(HostError::Incompatible(
            "extension manifest changed since registration".into(),
        ));
    }
    let id = 1;
    let deadline_ms = s.remaining_ms();
    s.send(&HostMessage::Invoke {
        id,
        deadline_ms,
        granted: granted.clone(),
        operation,
    })?;
    let mut calls = 0u32;
    loop {
        match s.recv()? {
            ExtensionMessage::Result { id: rid, output } if rid == id => return Ok(output),
            ExtensionMessage::Error { id: rid, error } if rid == id => {
                return Err(HostError::Extension(error))
            }
            ExtensionMessage::HostCall {
                invocation,
                call,
                request,
            } if invocation == id => {
                calls += 1;
                if calls > s.limits.max_host_calls {
                    return Err(HostError::Protocol("host call budget exhausted".into()));
                }
                if let Some(cap) = request.required_capability() {
                    if !granted.contains(&cap) {
                        return Err(HostError::Denied(format!("{cap:?}")));
                    }
                }
                let reply = match handler.handle(&request) {
                    Ok(v) => HostMessage::HostResult {
                        invocation,
                        call,
                        ok: Some(v),
                        error: None,
                    },
                    Err(CallError::Failed(e)) => HostMessage::HostResult {
                        invocation,
                        call,
                        ok: None,
                        error: Some(e),
                    },
                    Err(CallError::Denied(why)) => return Err(HostError::Denied(why)),
                };
                s.send(&reply)?;
            }
            _ => return Err(HostError::Protocol("unexpected message".into())),
        }
    }
}

/// Runs a program for a `process.execute` host call: no shell, cleared environment, bounded
/// output, killed at the timeout.
pub fn run_process(
    program: &str,
    args: &[String],
    timeout: Duration,
    max_output: usize,
) -> Result<Value, WireError> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| WireError::new("spawn_failed", e.kind().to_string()))?;
    let collect = |r: Option<Box<dyn Read + Send>>| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let _ = r.by_ref().take(max_output as u64).read_to_end(&mut buf);
            }
            buf
        })
    };
    let out = collect(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let errs = collect(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child
            .try_wait()
            .map_err(|e| WireError::new("wait_failed", e.kind().to_string()))?
        {
            break Some(st);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = errs.join().unwrap_or_default();
    let Some(status) = status else {
        return Err(WireError::new("timeout", "process exceeded its timeout"));
    };
    Ok(serde_json::json!({
        "exit_code": status.code().unwrap_or(-1),
        "stdout": openaevc_protocol::b64::encode(&stdout),
        "stderr": openaevc_protocol::b64::encode(&stderr),
    }))
}

/// SHA-256 of an extension artifact on disk.
pub fn artifact_digest(path: &std::path::Path) -> Result<openaevc_protocol::Digest, ProtocolError> {
    let bytes =
        std::fs::read(path).map_err(|_| err::not_found("extension artifact not readable"))?;
    Ok(openaevc_crypto::sha256(&bytes))
}
