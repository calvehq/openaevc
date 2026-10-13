//! A complete custom domain in ~100 lines: counters. Resource `counter.value`, effect
//! `counter.increment {by}`, verifier `counter.at-least {name, min}`. No OpenAEVC core changes are
//! needed to add it — only the Extension Contract.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use openaevc::extension::server::{self_artifact_digest, serve, Extension, HostContext};
use openaevc::extension::wire::{ApplyOutput, Operation, ValidateOutput, VerifyOutput, WireError};
use openaevc::protocol::*;
use serde_json::{json, Value};

const ID: &str = "org.example.counter";

struct Counter;

fn by(payload: &Value) -> Option<i64> {
    payload
        .as_object()
        .filter(|m| m.len() == 1)
        .and_then(|m| m.get("by"))
        .and_then(Value::as_i64)
        .filter(|n| *n > 0)
}

fn totals(effects: &[AppliedEffect]) -> BTreeMap<String, i64> {
    let mut t = BTreeMap::new();
    for e in effects.iter().filter(|e| e.kind == "counter.increment") {
        *t.entry(e.target.locator.clone()).or_default() += by(&e.payload).unwrap_or(0);
    }
    t
}

fn out<T: serde::Serialize>(v: T) -> Result<Value, WireError> {
    serde_json::to_value(v).map_err(|e| WireError::new("encode", e.to_string()))
}

impl Extension for Counter {
    fn manifest(&self) -> ExtensionManifest {
        ExtensionManifest {
            id: ID.into(),
            version: "1.0.0".into(),
            protocol: SUPPORTED_PROTOCOL,
            contract: SUPPORTED_CONTRACT,
            publisher: None,
            artifact_digest: self_artifact_digest(),
            resource_kinds: vec![ResourceKindDecl {
                kind: "counter.value".into(),
                description: Some("A named counter".into()),
            }],
            effect_kinds: vec![EffectKindDecl {
                kind: "counter.increment".into(),
                resource_kind: "counter.value".into(),
                required_actions: vec!["counter.write".into()],
            }],
            verifier_kinds: vec!["counter.at-least".into()],
            evaluator_kinds: vec![],
            composition_validators: vec![],
            host_capabilities: vec![],
            schemas: Default::default(),
            execution_modes: vec!["subprocess".into()],
            entrypoint: Entrypoint {
                command: "openaevc-example-counter-extension".into(),
                args: vec![],
            },
        }
    }

    fn handle(&mut self, op: Operation, _host: &mut HostContext<'_>) -> Result<Value, WireError> {
        match op {
            Operation::ValidateEffect { effect, .. } => {
                let ok = effect.kind == "counter.increment"
                    && effect.target.kind == "counter.value"
                    && effect.target.extension == ID
                    && by(&effect.payload).is_some();
                out(ValidateOutput {
                    valid: ok,
                    reason: (!ok)
                        .then(|| "counter.increment takes {\"by\": positive integer}".into()),
                })
            }
            Operation::ApplyEffect { effect, prior } => {
                let total = totals(&prior)
                    .get(&effect.target.locator)
                    .copied()
                    .unwrap_or(0)
                    + by(&effect.payload).unwrap_or(0);
                out(ApplyOutput {
                    outcome: json!({"total": total}),
                })
            }
            Operation::Verify {
                kind,
                config,
                effects,
                ..
            } if kind == "counter.at-least" => {
                let cfg = config.unwrap_or(Value::Null);
                let (name, min) = (
                    cfg["name"].as_str().unwrap_or_default(),
                    cfg["min"].as_i64().unwrap_or(i64::MAX),
                );
                let total = totals(&effects).get(name).copied().unwrap_or(0);
                let mut facts = Facts::new();
                facts.insert(format!("counter.{name}.total"), FactValue::Int(total));
                out(VerifyOutput {
                    status: if total >= min {
                        VerificationStatus::Pass
                    } else {
                        VerificationStatus::Fail
                    },
                    findings: vec![],
                    facts,
                })
            }
            other => Err(WireError::new("unsupported", other.name())),
        }
    }
}

fn main() -> std::process::ExitCode {
    serve(Counter)
}
