//! Deliberately misbehaving extension for conformance and security tests. The behaviour is
//! selected by the executable's file name: `conformance-fixture-<mode>`.
//!
//! Modes: `well-behaved`, `undeclared-resource`, `undeclared-process`, `oversized`,
//! `invalid-frame`, `wrong-digest`, `slow`, `incompatible`, `crash`, `probe`,
//! `kind-thief` (another extension claiming `well-behaved`'s kinds), `upgrade` (version 0.2.0 of
//! `well-behaved`), `wants-unsupported` (requests host capabilities the reference host cannot grant),
//! `detached-child` (leaves a descendant holding stderr open), `no-read` (floods host calls
//! without reading the replies, so the host's writes would block).
#![forbid(unsafe_code)]

use std::io::Write;

use openaevc_extension_contract::server::{self_artifact_digest, serve, Extension, HostContext};
use openaevc_extension_contract::wire::{HostCall, Operation, VerifyOutput, WireError};
use openaevc_protocol::*;
use serde_json::Value;

struct Fixture {
    mode: String,
}

impl Fixture {
    /// `kind-thief` and `upgrade` claim the kinds of `well-behaved`.
    fn kind_owner(&self) -> &str {
        match self.mode.as_str() {
            "kind-thief" | "upgrade" => "well-behaved",
            m => m,
        }
    }

    fn kind(&self, suffix: &str) -> String {
        format!("fixture.{}.{suffix}", self.kind_owner())
    }
}

impl Extension for Fixture {
    fn manifest(&self) -> ExtensionManifest {
        let mode = self.mode.as_str();
        let contract = if mode == "incompatible" {
            VersionRange::new(ProtocolVersion::new(9, 0, 0), ProtocolVersion::new(9, 0, 0))
        } else {
            SUPPORTED_CONTRACT
        };
        ExtensionManifest {
            // `upgrade` is a newer version of `well-behaved`; `kind-thief` is another
            // extension (at a different version) claiming the same kinds.
            id: format!(
                "org.openaevc.conformance.{}",
                if mode == "upgrade" {
                    "well-behaved"
                } else {
                    mode
                }
            ),
            version: if matches!(mode, "upgrade" | "kind-thief") {
                "0.2.0"
            } else {
                "0.1.0"
            }
            .into(),
            protocol: SUPPORTED_PROTOCOL,
            contract,
            publisher: None,
            artifact_digest: if mode == "wrong-digest" {
                Digest::sha256([0xee; 32])
            } else {
                self_artifact_digest()
            },
            resource_kinds: vec![ResourceKindDecl {
                kind: self.kind("item"),
                description: None,
            }],
            effect_kinds: vec![],
            verifier_kinds: vec![self.kind("check")],
            evaluator_kinds: vec![],
            composition_validators: vec![],
            // Requests resource reads only; never process execution. `wants-unsupported`
            // also requests the capabilities the reference host implements no call for.
            host_capabilities: if mode == "wants-unsupported" {
                vec![
                    HostCapability::ResourceRead,
                    HostCapability::ResourceWrite,
                    HostCapability::NetworkConnect,
                    HostCapability::SecretRead,
                ]
            } else {
                vec![HostCapability::ResourceRead]
            },
            schemas: Default::default(),
            execution_modes: vec!["subprocess".into()],
            entrypoint: Entrypoint {
                command: format!("conformance-fixture-{mode}"),
                args: vec![],
            },
        }
    }

    fn handle(&mut self, op: Operation, host: &mut HostContext<'_>) -> Result<Value, WireError> {
        let pass = || {
            serde_json::to_value(VerifyOutput {
                status: VerificationStatus::Pass,
                findings: vec![],
                facts: Default::default(),
            })
            .map_err(|e| WireError::new("encode", e.to_string()))
        };
        match self.mode.as_str() {
            "undeclared-resource" => {
                let resource = ResourceRef {
                    kind: "secret.store".into(),
                    locator: "/etc/shadow".into(),
                    version: None,
                    extension: "org.evil.x".into(),
                };
                host.call(HostCall::ResourceRead { resource })?;
                pass()
            }
            "undeclared-process" => {
                host.call(HostCall::ProcessExecute {
                    program: "/bin/sh".into(),
                    args: vec!["-c".into(), "id".into()],
                    timeout_ms: 1000,
                })?;
                pass()
            }
            "oversized" => Ok(Value::String("x".repeat(8 * 1024 * 1024))),
            "invalid-frame" => {
                let mut out = std::io::stdout();
                let _ = out.write_all(&[0, 0, 0, 3, 0xff, 0xff, 0xff]);
                let _ = out.flush();
                std::thread::sleep(std::time::Duration::from_secs(5));
                pass()
            }
            "slow" => {
                // Well past any deadline a test target configures (10 s), so enforcement is
                // observable without making ordinary invocations race a tight deadline.
                std::thread::sleep(std::time::Duration::from_secs(30));
                pass()
            }
            "crash" => std::process::exit(3),
            "detached-child" => {
                // The descendant inherits stderr and outlives this process.
                let _ = std::process::Command::new("sleep")
                    .arg("30")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .spawn();
                pass()
            }
            "no-read" => {
                // Pipelined host calls whose replies are never read: the replies fill the
                // host's pipe to this process.
                let mut out = std::io::stdout().lock();
                for call in 1..=1000u64 {
                    let msg = openaevc_extension_contract::wire::ExtensionMessage::HostCall {
                        invocation: 1,
                        call,
                        request: HostCall::ConfigResolve {
                            key: format!("missing-key-with-a-long-name-{call:08}"),
                        },
                    };
                    if openaevc_extension_contract::wire::write_frame(&mut out, &msg).is_err() {
                        break;
                    }
                }
                let _ = out.flush();
                std::thread::sleep(std::time::Duration::from_secs(30));
                pass()
            }
            "probe" => {
                // Reports what the process can see: environment variable names and cwd.
                let env: std::collections::BTreeSet<String> = std::env::vars_os()
                    .map(|(k, _)| k.to_string_lossy().into_owned())
                    .collect();
                let cwd = std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                let mut facts = Facts::new();
                facts.insert("fixture.probe.env".into(), FactValue::Set(env));
                facts.insert("fixture.probe.cwd".into(), FactValue::Text(cwd));
                serde_json::to_value(VerifyOutput {
                    status: VerificationStatus::Pass,
                    findings: vec![],
                    facts,
                })
                .map_err(|e| WireError::new("encode", e.to_string()))
            }
            _ => match op {
                Operation::Verify { kind, .. } if kind == self.kind("check") => pass(),
                other => Err(WireError::new("unsupported", other.name())),
            },
        }
    }
}

fn main() -> std::process::ExitCode {
    let exe = std::env::current_exe().ok();
    let name = exe
        .as_ref()
        .and_then(|p| p.file_stem())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mode = name
        .strip_prefix("conformance-fixture-")
        .unwrap_or("well-behaved")
        .to_owned();
    serve(Fixture { mode })
}
