//! Extension-side helper: implement [`Extension`] and call [`serve`] from `main`.

use std::io::{BufReader, Read, Write};

use openaevc_protocol::{Digest, ExtensionManifest, HostCapability};
use serde_json::Value;

use crate::wire::{
    read_frame, write_frame, ExtensionMessage, HostCall, HostMessage, Operation, WireError,
};

/// Maximum frame an extension built with this helper accepts from the host.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

pub trait Extension {
    fn manifest(&self) -> ExtensionManifest;
    fn handle(&mut self, op: Operation, host: &mut HostContext<'_>) -> Result<Value, WireError>;
}

/// Handle for making host calls during one invocation.
pub struct HostContext<'a> {
    invocation: u64,
    next_call: u64,
    granted: Vec<HostCapability>,
    input: &'a mut dyn Read,
    output: &'a mut dyn Write,
}

impl std::fmt::Debug for HostContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostContext")
            .field("invocation", &self.invocation)
            .finish()
    }
}

impl HostContext<'_> {
    pub fn granted(&self) -> &[HostCapability] {
        &self.granted
    }

    /// Sends a host call and waits for its result.
    pub fn call(&mut self, request: HostCall) -> Result<Value, WireError> {
        self.next_call += 1;
        let call = self.next_call;
        write_frame(
            self.output,
            &ExtensionMessage::HostCall {
                invocation: self.invocation,
                call,
                request,
            },
        )
        .map_err(|e| WireError::new("io", e.to_string()))?;
        match read_frame::<HostMessage, _>(self.input, MAX_FRAME) {
            Ok(Some(HostMessage::HostResult {
                invocation,
                call: c,
                ok,
                error,
            })) if invocation == self.invocation && c == call => match (ok, error) {
                (Some(v), None) => Ok(v),
                (_, Some(e)) => Err(e),
                (None, None) => Err(WireError::new("protocol", "empty host result")),
            },
            _ => Err(WireError::new("protocol", "unexpected host message")),
        }
    }
}

/// SHA-256 of the running executable (for `ExtensionManifest::artifact_digest`).
pub fn self_artifact_digest() -> Digest {
    std::env::current_exe()
        .and_then(std::fs::read)
        .map(|b| openaevc_crypto::sha256(&b))
        .unwrap_or(Digest::ZERO)
}

/// Runs the extension protocol on stdin/stdout until shutdown or end of input.
pub fn serve(mut ext: impl Extension) -> std::process::ExitCode {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = stdout.lock();
    match serve_on(&mut ext, &mut input, &mut output) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("extension protocol error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Protocol loop over arbitrary streams (testable without a process).
pub fn serve_on(
    ext: &mut dyn Extension,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), String> {
    match read_frame::<HostMessage, _>(input, MAX_FRAME).map_err(|e| e.to_string())? {
        Some(HostMessage::Hello { .. }) => {}
        None => return Ok(()),
        _ => return Err("expected hello".into()),
    }
    let manifest = ext.manifest();
    let (protocol, contract) = (manifest.protocol, manifest.contract);
    write_frame(
        output,
        &ExtensionMessage::Hello {
            manifest,
            protocol,
            contract,
        },
    )
    .map_err(|e| e.to_string())?;
    loop {
        match read_frame::<HostMessage, _>(input, MAX_FRAME).map_err(|e| e.to_string())? {
            None | Some(HostMessage::Shutdown {}) => return Ok(()),
            Some(HostMessage::Invoke {
                id,
                granted,
                operation,
                ..
            }) => {
                let mut host = HostContext {
                    invocation: id,
                    next_call: 0,
                    granted,
                    input: &mut *input,
                    output: &mut *output,
                };
                let reply = match ext.handle(operation, &mut host) {
                    Ok(v) => ExtensionMessage::Result { id, output: v },
                    Err(e) => ExtensionMessage::Error { id, error: e },
                };
                write_frame(output, &reply).map_err(|e| e.to_string())?;
            }
            Some(HostMessage::Cancel { .. }) => {}
            Some(_) => return Err("unexpected host message".into()),
        }
    }
}
