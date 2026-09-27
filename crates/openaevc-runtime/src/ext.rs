//! Runtime side of the extension contract: registry lookups and invocation with per-invocation
//! capability grants and scoped host calls. Extensions never touch runtime state directly; they
//! only return data that the runtime validates and records.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use openaevc_core::names;
use openaevc_extension_contract::host::{self, CallError, Entrypoint, HostCallHandler, HostLimits};
use openaevc_extension_contract::wire::{HostCall, Operation, WireError};
use openaevc_protocol::{
    b64, err, AppliedEffect, ErrorCode, ExtensionRef, FactValue, Facts, HostCapability,
    ProtocolError, ResourceRef,
};
use serde_json::{json, Value};

use crate::records::{self, ExtensionRecord};
use crate::tx::Tx;
use crate::Result;

/// Resolves a registration entrypoint inside one of the configured extension directories.
pub(crate) fn resolve_entrypoint(dirs: &[PathBuf], entry: &str) -> Result<PathBuf> {
    let rel = Path::new(entry);
    if entry.is_empty() || !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(err::invalid(
            "extension entrypoint must be a plain relative path inside an extension directory",
        ));
    }
    for dir in dirs {
        let Ok(root) = std::fs::canonicalize(dir) else {
            continue;
        };
        let Ok(candidate) = std::fs::canonicalize(root.join(rel)) else {
            continue;
        };
        if candidate.starts_with(&root) && candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(err::not_found(format!(
        "extension entrypoint {entry:?} not found in any extension directory"
    )))
}

pub(crate) fn limits(tx: &Tx<'_>) -> HostLimits {
    HostLimits {
        max_frame: tx.rt.config.max_extension_frame,
        deadline: Duration::from_millis(tx.rt.config.extension_deadline_ms),
        ..HostLimits::default()
    }
}

pub(crate) fn active_extensions(tx: &Tx<'_>) -> Result<Vec<ExtensionRecord>> {
    Ok(tx
        .peek_list::<ExtensionRecord>(records::EXTENSION, &records::prefix(&tx.ns))?
        .into_iter()
        .map(|(_, r)| r)
        .filter(|r| r.active)
        .collect())
}

/// Active extension declaring `kind` for the selected declaration list.
pub(crate) fn find(
    tx: &Tx<'_>,
    what: &str,
    kind: &str,
    pick: impl Fn(&ExtensionRecord) -> Vec<String>,
) -> Result<ExtensionRecord> {
    active_extensions(tx)?
        .into_iter()
        .find(|r| pick(r).iter().any(|k| k == kind))
        .ok_or_else(|| err::not_found(format!("no registered extension provides {what} {kind}")))
}

pub(crate) fn by_effect(tx: &Tx<'_>, kind: &str) -> Result<ExtensionRecord> {
    find(tx, "effect kind", kind, |r| {
        r.manifest
            .effect_kinds
            .iter()
            .map(|e| e.kind.clone())
            .collect()
    })
}

/// Everything an invocation produced besides its output.
#[derive(Debug, Default)]
pub(crate) struct Collected {
    pub evidence: Vec<(String, String, Vec<u8>)>,
    pub facts: Facts,
    pub logs: Vec<Value>,
}

struct Calls<'a> {
    scope: &'a [ResourceRef],
    prior: &'a [AppliedEffect],
    config: Option<&'a Value>,
    now: String,
    entropy: &'a dyn openaevc_core::IdGenerator,
    collected: Collected,
}

const MAX_EVIDENCE: usize = 16;
const MAX_PROCESS_OUTPUT: usize = 1024 * 1024;

impl HostCallHandler for Calls<'_> {
    fn handle(&mut self, call: &HostCall) -> std::result::Result<Value, CallError> {
        let fail = |code: &str, m: &str| Err(CallError::Failed(WireError::new(code, m)));
        match call {
            HostCall::ResourceRead { resource } => {
                let in_scope = self.scope.iter().any(|r| {
                    r.kind == resource.kind
                        && r.locator == resource.locator
                        && r.extension == resource.extension
                });
                if !in_scope {
                    return Err(CallError::Denied(format!(
                        "resource {}:{} is outside the invocation scope",
                        resource.kind, resource.locator
                    )));
                }
                let effects: Vec<&AppliedEffect> = self
                    .prior
                    .iter()
                    .filter(|e| {
                        e.target.kind == resource.kind && e.target.locator == resource.locator
                    })
                    .collect();
                serde_json::to_value(effects)
                    .map_err(|e| CallError::Failed(WireError::new("encode", e.to_string())))
            }
            HostCall::ProcessExecute {
                program,
                args,
                timeout_ms,
            } => host::run_process(
                program,
                args,
                Duration::from_millis((*timeout_ms).min(30_000)),
                MAX_PROCESS_OUTPUT,
            )
            .map_err(CallError::Failed),
            HostCall::EvidenceAttach {
                kind,
                media_type,
                data,
            } => {
                if self.collected.evidence.len() >= MAX_EVIDENCE {
                    return fail("limit", "too many evidence attachments");
                }
                if !names::is_namespaced(kind) {
                    return fail("invalid", "evidence kind must be a namespaced name");
                }
                self.collected
                    .evidence
                    .push((kind.clone(), media_type.clone(), data.clone()));
                Ok(Value::Bool(true))
            }
            HostCall::FactEmit { name, value } => {
                if !names::is_namespaced(name) {
                    return fail("invalid", "fact names must be namespaced");
                }
                self.collected.facts.insert(name.clone(), value.clone());
                Ok(Value::Bool(true))
            }
            HostCall::ConfigResolve { key } => match self.config.and_then(|c| c.get(key)) {
                Some(v) => Ok(v.clone()),
                None => fail("not_found", "configuration key not present"),
            },
            HostCall::ClockNow {} => Ok(Value::String(self.now.clone())),
            HostCall::EntropyRandom { len } => {
                if *len > 1024 {
                    return fail("limit", "at most 1024 random bytes per call");
                }
                let mut out = Vec::with_capacity(*len as usize);
                while out.len() < *len as usize {
                    out.extend_from_slice(&self.entropy.next_bytes());
                }
                out.truncate(*len as usize);
                Ok(Value::String(b64::encode(&out)))
            }
            HostCall::Log {
                level,
                message,
                fields,
            } => {
                if self.collected.logs.len() < 256 {
                    self.collected
                        .logs
                        .push(json!({"level": level, "message": message, "fields": fields}));
                }
                Ok(Value::Bool(true))
            }
        }
    }
}

/// Invokes an operation on a registered extension. The artifact is re-hashed before every
/// spawn; a changed binary fails with `EXTENSION_INCOMPATIBLE`.
pub(crate) fn invoke(
    tx: &Tx<'_>,
    rec: &ExtensionRecord,
    op: Operation,
    config: Option<&Value>,
    scope: &[ResourceRef],
    prior: &[AppliedEffect],
) -> Result<(Value, Collected, ExtensionRef)> {
    let program = PathBuf::from(&rec.program);
    let digest = host::artifact_digest(&program).map_err(|_| {
        ProtocolError::new(
            ErrorCode::ExtensionIncompatible,
            format!("extension {} artifact is unavailable", rec.manifest.id),
        )
    })?;
    if digest != rec.manifest.artifact_digest {
        return Err(ProtocolError::new(
            ErrorCode::ExtensionIncompatible,
            format!(
                "extension {} artifact changed since registration",
                rec.manifest.id
            ),
        ));
    }
    let granted: Vec<HostCapability> = op
        .allowed_capabilities()
        .iter()
        .copied()
        .filter(|c| rec.manifest.host_capabilities.contains(c) && rec.approved.contains(c))
        .collect();
    let mut calls = Calls {
        scope,
        prior,
        config,
        now: tx.now.to_string(),
        entropy: tx.rt.ids.as_ref(),
        collected: Collected::default(),
    };
    let ep = Entrypoint {
        program,
        args: rec.manifest.entrypoint.args.clone(),
    };
    let result = host::invoke(&ep, &limits(tx), &rec.manifest, op, granted, &mut calls)
        .map_err(|e| e.into_protocol(&rec.manifest.id))?;
    Ok((result.output, calls.collected, rec.reference()))
}

/// Decodes an extension output strictly into the expected type.
pub(crate) fn decode<T: serde::de::DeserializeOwned + serde::Serialize>(
    rec: &ExtensionRecord,
    v: Value,
) -> Result<T> {
    openaevc_canonical::from_value(v).map_err(|e| {
        ProtocolError::new(
            ErrorCode::ExtensionFailed,
            format!(
                "extension {} returned malformed output: {e}",
                rec.manifest.id
            ),
        )
        .with_extension_error(openaevc_protocol::ExtensionErrorInfo {
            extension_id: rec.manifest.id.clone(),
            code: "malformed_output".into(),
            message: e.to_string(),
        })
    })
}

/// Namespaced facts are the only extension facts accepted.
pub(crate) fn merge_facts(into: &mut Facts, from: Facts) -> Result<()> {
    for (k, v) in from {
        names::validate_namespaced(&k)?;
        if let FactValue::Set(s) = &v {
            if s.len() > 10_000 {
                return Err(err::invalid("fact set too large"));
            }
        }
        into.insert(k, v);
    }
    Ok(())
}
