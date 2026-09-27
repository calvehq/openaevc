//! Extension-executable target: checks that an extension binary speaks the v1 contract so a
//! conforming runtime can register and invoke it.

use std::path::Path;
use std::time::Instant;

use openaevc_extension_contract::host::{
    self, CallError, Entrypoint, HostCallHandler, HostError, HostLimits,
};
use openaevc_extension_contract::wire::{HostCall, Operation, WireError};
use openaevc_protocol::*;
use serde_json::Value;

use crate::{CaseOutcome, Profile, Report, Status};

struct DenyAll;

impl HostCallHandler for DenyAll {
    fn handle(&mut self, _: &HostCall) -> Result<Value, CallError> {
        Err(CallError::Failed(WireError::new(
            "unavailable",
            "the conformance host serves no host calls",
        )))
    }
}

fn is_namespaced(s: &str) -> bool {
    s.split('.').filter(|p| !p.is_empty()).count() >= 2
}

/// Runs the extension checks against the executable at `path`.
pub fn check(path: &Path) -> Report {
    // The host starts extensions in their own directory, so relative paths are resolved first.
    let path = &std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let ep = Entrypoint {
        program: path.clone(),
        args: vec![],
    };
    let limits = HostLimits::default();
    let mut outcomes = Vec::new();
    let mut record = |id: &str, reqs: &[&str], start: Instant, r: Result<(), String>| {
        outcomes.push(CaseOutcome {
            id: id.into(),
            profile: Profile::ExtensionHost,
            requirements: reqs.iter().map(|s| s.to_string()).collect(),
            status: r.map_or_else(Status::Failed, |()| Status::Passed),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    };

    let start = Instant::now();
    let hs = host::handshake(&ep, &limits);
    let manifest = match &hs {
        Ok((m, _)) => Some(m.clone()),
        Err(_) => None,
    };
    record(
        "extension.handshake",
        &["AEVC-EXT-0002"],
        start,
        hs.map(drop).map_err(|e| format!("handshake failed: {e:?}")),
    );

    let start = Instant::now();
    let r = match (&manifest, std::fs::read(path)) {
        (None, _) => Err("no manifest".into()),
        (_, Err(e)) => Err(format!("cannot read executable: {e}")),
        (Some(m), Ok(bytes)) => {
            let actual = openaevc_crypto::sha256(&bytes);
            if m.artifact_digest != actual {
                Err(format!(
                    "manifest artifact_digest {} != executable digest {actual}",
                    m.artifact_digest
                ))
            } else if SUPPORTED_PROTOCOL.negotiate(&m.protocol).is_none()
                || SUPPORTED_CONTRACT.negotiate(&m.contract).is_none()
            {
                Err("protocol or contract range does not intersect v1".into())
            } else {
                Ok(())
            }
        }
    };
    record("extension.manifest_pinning", &["AEVC-EXT-0002"], start, r);

    let start = Instant::now();
    let r = match &manifest {
        None => Err("no manifest".into()),
        Some(m) => {
            let kinds = m
                .resource_kinds
                .iter()
                .map(|k| k.kind.as_str())
                .chain(m.effect_kinds.iter().map(|k| k.kind.as_str()))
                .chain(m.verifier_kinds.iter().map(String::as_str))
                .chain(m.evaluator_kinds.iter().map(String::as_str));
            match std::iter::once(m.id.as_str())
                .chain(kinds)
                .find(|k| !is_namespaced(k))
            {
                Some(bad) => Err(format!("identifier {bad:?} is not namespaced")),
                None => Ok(()),
            }
        }
    };
    record("extension.manifest_names", &["AEVC-EXT-0003"], start, r);

    // An operation for a kind the extension does not provide must be answered with an error,
    // not a crash or a protocol violation.
    let start = Instant::now();
    let r = match &manifest {
        None => Err("no manifest".into()),
        Some(m) => {
            let op = Operation::Verify {
                kind: "org.openaevc.conformance.unknown-kind".into(),
                config: None,
                pack: "cpk_agjdus24nvyadaareizuivlgo4".parse().expect("static id"),
                generation: 1,
                candidate: Digest::ZERO,
                effects: vec![],
                evidence: vec![],
            };
            match host::invoke(&ep, &limits, m, op, vec![], &mut DenyAll) {
                Err(HostError::Extension(_)) => Ok(()),
                Ok(r) => Err(format!("unknown kind produced output: {}", r.output)),
                Err(e) => Err(format!(
                    "unknown kind was not answered with an extension error: {e:?}"
                )),
            }
        }
    };
    record("extension.unknown_operation", &["AEVC-EXT-0006"], start, r);

    Report::new(
        Profile::ExtensionHost,
        format!("extension {}", path.display()),
        None,
        outcomes,
    )
}
