//! `reference-null`: one inert resource kind, one no-op effect, a deterministic verifier that
//! emits deterministic evidence. Used for protocol smoke tests.
#![forbid(unsafe_code)]

use openaevc::extension::server::{self_artifact_digest, serve, Extension, HostContext};
use openaevc::extension::wire::{
    ApplyOutput, HostCall, Operation, ValidateOutput, VerifyOutput, WireError,
};
use openaevc::protocol::*;
use serde_json::{json, Value};

pub const ID: &str = "org.openaevc.reference.null";

struct Null;

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, WireError> {
    serde_json::to_value(v).map_err(|e| WireError::new("encode", e.to_string()))
}

impl Extension for Null {
    fn manifest(&self) -> ExtensionManifest {
        ExtensionManifest {
            id: ID.into(),
            version: "0.1.0".into(),
            protocol: SUPPORTED_PROTOCOL,
            contract: SUPPORTED_CONTRACT,
            publisher: None,
            artifact_digest: self_artifact_digest(),
            resource_kinds: vec![ResourceKindDecl {
                kind: "null.item".into(),
                description: Some("Inert resource".into()),
            }],
            effect_kinds: vec![EffectKindDecl {
                kind: "null.noop".into(),
                resource_kind: "null.item".into(),
                required_actions: vec!["null.write".into()],
            }],
            verifier_kinds: vec!["null.pass".into()],
            evaluator_kinds: vec![],
            composition_validators: vec![],
            host_capabilities: vec![],
            schemas: Default::default(),
            execution_modes: vec!["subprocess".into()],
            entrypoint: Entrypoint {
                command: "openaevc-ext-reference-null".into(),
                args: vec![],
            },
        }
    }

    fn handle(&mut self, op: Operation, host: &mut HostContext<'_>) -> Result<Value, WireError> {
        match op {
            Operation::ValidateEffect { effect, .. } => to_value(ValidateOutput {
                valid: effect.kind == "null.noop" && effect.payload == json!({}),
                reason: (effect.kind != "null.noop" || effect.payload != json!({}))
                    .then(|| "null.noop takes an empty payload".into()),
            }),
            Operation::ApplyEffect { .. } => to_value(ApplyOutput {
                outcome: json!({"applied": true}),
            }),
            Operation::Verify {
                kind, candidate, ..
            } if kind == "null.pass" => {
                host.call(HostCall::EvidenceAttach {
                    kind: "null.receipt".into(),
                    media_type: "application/json".into(),
                    data: format!("{{\"candidate\":\"{candidate}\"}}").into_bytes(),
                })?;
                to_value(VerifyOutput {
                    status: VerificationStatus::Pass,
                    findings: vec![],
                    facts: Default::default(),
                })
            }
            other => Err(WireError::new(
                "unsupported",
                format!("{} is not supported", other.name()),
            )),
        }
    }
}

fn main() -> std::process::ExitCode {
    serve(Null)
}
