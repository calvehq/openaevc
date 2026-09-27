//! `reference-kv` extension executable.
#![forbid(unsafe_code)]

use openaevc_ext_reference_kv as kv;
use openaevc_extension_contract::server::{self_artifact_digest, serve, Extension, HostContext};
use openaevc_extension_contract::wire::{
    ApplyOutput, HostCall, Operation, ValidateOutput, WireError,
};
use openaevc_protocol::*;
use serde_json::{json, Value};

struct Kv;

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, WireError> {
    serde_json::to_value(v).map_err(|e| WireError::new("encode", e.to_string()))
}

fn bad_config(m: String) -> WireError {
    WireError::new("invalid_config", m)
}

impl Extension for Kv {
    fn manifest(&self) -> ExtensionManifest {
        ExtensionManifest {
            id: kv::ID.into(),
            version: "0.1.0".into(),
            protocol: SUPPORTED_PROTOCOL,
            contract: SUPPORTED_CONTRACT,
            publisher: None,
            artifact_digest: self_artifact_digest(),
            resource_kinds: vec![ResourceKindDecl {
                kind: "kv.entry".into(),
                description: Some("A key; locator is the key".into()),
            }],
            effect_kinds: vec![
                EffectKindDecl {
                    kind: "kv.set".into(),
                    resource_kind: "kv.entry".into(),
                    required_actions: vec!["kv.write".into()],
                },
                EffectKindDecl {
                    kind: "kv.delete".into(),
                    resource_kind: "kv.entry".into(),
                    required_actions: vec!["kv.write".into()],
                },
            ],
            verifier_kinds: vec!["kv.expect".into()],
            evaluator_kinds: vec!["kv.size".into()],
            composition_validators: vec!["kv.terminal-values".into()],
            host_capabilities: vec![HostCapability::ResourceRead],
            schemas: Default::default(),
            execution_modes: vec!["subprocess".into()],
            entrypoint: Entrypoint {
                command: "openaevc-ext-reference-kv".into(),
                args: vec![],
            },
        }
    }

    fn handle(&mut self, op: Operation, host: &mut HostContext<'_>) -> Result<Value, WireError> {
        match op {
            Operation::ValidateEffect { effect, prior } => {
                let r = kv::validate(&effect, &prior);
                to_value(ValidateOutput {
                    valid: r.is_ok(),
                    reason: r.err(),
                })
            }
            Operation::ApplyEffect { effect, prior } => {
                kv::validate(&effect, &prior).map_err(|m| WireError::new("invalid_effect", m))?;
                to_value(ApplyOutput {
                    outcome: kv::outcome(&effect, &prior),
                })
            }
            Operation::Verify {
                kind,
                config,
                effects,
                ..
            } if kind == "kv.expect" => {
                let config = config.unwrap_or(Value::Null);
                // Exercise the structured host path: read the expected key through the host.
                if let Some(key) = config.get("key").and_then(Value::as_str) {
                    let resource = ResourceRef {
                        kind: "kv.entry".into(),
                        locator: key.into(),
                        version: None,
                        extension: kv::ID.into(),
                    };
                    host.call(HostCall::ResourceRead { resource })?;
                }
                let out = kv::expect(&effects, &config).map_err(bad_config)?;
                let snapshot: Value = kv::terminal(&effects)
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            v.map_or(json!({"deleted": true}), |v| json!({"value": v})),
                        )
                    })
                    .collect::<serde_json::Map<_, _>>()
                    .into();
                host.call(HostCall::EvidenceAttach {
                    kind: "kv.snapshot".into(),
                    media_type: "application/json".into(),
                    data: serde_json::to_vec(&snapshot)
                        .map_err(|e| WireError::new("encode", e.to_string()))?,
                })?;
                to_value(out)
            }
            Operation::Evaluate {
                kind,
                config,
                effects,
                ..
            } if kind == "kv.size" => {
                to_value(kv::size(&effects, &config.unwrap_or(Value::Null)).map_err(bad_config)?)
            }
            Operation::Compose {
                validator,
                members,
                edges,
                ..
            } if validator == "kv.terminal-values" => to_value(kv::compose(&members, &edges)),
            other => Err(WireError::new(
                "unsupported",
                format!("{} is not supported for this kind", other.name()),
            )),
        }
    }
}

fn main() -> std::process::ExitCode {
    serve(Kv)
}
