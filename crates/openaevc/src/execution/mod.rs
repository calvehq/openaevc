//! Execution model (spec/execution.md): pure functions and contracts used by the runtime.
//!
//! Roles: the **runtime** owns lifecycle, authority, provenance and candidate state; a
//! **provider** supplies workers; a **worker** does the work; a **harness** coordinates the worker
//! with a structured protocol ([`ExecutionSession`]); **extensions** interpret resources/effects.
//! Workers never mutate accepted state: they submit effect proposals through the runtime.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use crate::protocol::{
    err, AppliedEffect, Digest, EffectProposal, EffectSummary, ErrorCode, ExecutionId,
    ExecutionState, ExtensionRef, Lease, LeaseId, ObservationId, PackState, ProtocolError,
    Provenance, ResourceRef, ResourceSelector, Timestamp, WorkUnitState,
};

// ---------------------------------------------------------------------------------------------
// Leases

pub fn new_lease(
    id: LeaseId,
    execution: ExecutionId,
    generation: u64,
    provider: &str,
    now: Timestamp,
    lease_ms: u64,
    heartbeat_ms: u64,
) -> Lease {
    Lease {
        id,
        execution,
        generation,
        provider: provider.to_owned(),
        expires_at: now.plus_millis(lease_ms),
        heartbeat_interval_ms: heartbeat_ms,
    }
}

/// Whether the lease is past its expiry plus `grace_ms` (resumable providers get a grace period).
pub fn lease_expired(l: &Lease, now: Timestamp, grace_ms: u64) -> bool {
    now >= l.expires_at.plus_millis(grace_ms)
}

pub fn renew(l: &Lease, now: Timestamp, lease_ms: u64) -> Lease {
    Lease {
        expires_at: now.plus_millis(lease_ms),
        ..l.clone()
    }
}

// ---------------------------------------------------------------------------------------------
// Admission

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderSupport {
    pub harness_supported: bool,
    pub worker_kind_supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryFacts {
    pub previous_state: ExecutionState,
    pub same_work_unit: bool,
    pub attempts_used: u32,
    pub max_attempts: u32,
}

/// Facts the runtime gathers before admitting an execution (authority is checked separately).
#[derive(Debug, Clone)]
pub struct AdmissionFacts {
    pub pack_state: PackState,
    pub pack_generation: u64,
    pub expected_generation: u64,
    pub work_unit: Option<WorkUnitState>,
    /// Unsatisfied dependency nodes of the work unit.
    pub waiting_on: Vec<String>,
    pub provider: Option<ProviderSupport>,
    /// Requested effect kinds with no active extension.
    pub unregistered_effects: Vec<String>,
    /// Requested effect kinds whose extension is not among the pack's bindings.
    pub unbound_effects: Vec<String>,
    pub active_execution: Option<String>,
    pub retry: Option<RetryFacts>,
    /// Effects requested together with a non-empty resource scope (or no effects at all).
    pub has_scope: bool,
}

fn fail(code: ErrorCode, msg: impl Into<String>) -> Result<(), ProtocolError> {
    Err(ProtocolError::new(code, msg))
}

/// Admission checks in protocol order (spec/execution.md §Admission).
pub fn check_admission(f: &AdmissionFacts) -> Result<(), ProtocolError> {
    match f.pack_state {
        PackState::Open => {}
        PackState::Quarantined => return fail(ErrorCode::Quarantined, "pack is quarantined"),
        PackState::Promoted => return fail(ErrorCode::ImmutableObject, "pack is promoted"),
        s => {
            return Err(ProtocolError::new(
                ErrorCode::InvalidTransition,
                format!("executions require an OPEN pack (pack is {})", s.as_str()),
            ))
        }
    }
    if f.pack_generation != f.expected_generation {
        return Err(
            ProtocolError::new(ErrorCode::StaleGeneration, "pack generation changed")
                .with_generations(f.expected_generation, f.pack_generation),
        );
    }
    match f.work_unit {
        None => return fail(ErrorCode::NotFound, "work unit not found in pack"),
        Some(WorkUnitState::Open) => {}
        Some(s) => return fail(ErrorCode::InvalidTransition, format!("work unit is {s:?}")),
    }
    if !f.waiting_on.is_empty() {
        let mut e = ProtocolError::new(
            ErrorCode::ExecutionNotReady,
            "work unit has unsatisfied dependencies",
        );
        e.object_ids = f.waiting_on.clone();
        return Err(e);
    }
    match f.provider {
        None => return fail(ErrorCode::NotFound, "provider not registered"),
        Some(p) if !p.harness_supported => {
            return fail(
                ErrorCode::InvalidArgument,
                "provider does not support the requested harness",
            )
        }
        Some(p) if !p.worker_kind_supported => {
            return fail(
                ErrorCode::InvalidArgument,
                "provider does not support the requested worker kind",
            )
        }
        Some(_) => {}
    }
    if !f.unregistered_effects.is_empty() {
        return fail(
            ErrorCode::ExtensionIncompatible,
            format!(
                "no registered extension provides {}",
                f.unregistered_effects.join(", ")
            ),
        );
    }
    if !f.unbound_effects.is_empty() {
        return fail(
            ErrorCode::InvalidArgument,
            format!(
                "effects {} are not provided by the pack's bound extensions",
                f.unbound_effects.join(", ")
            ),
        );
    }
    if let Some(e) = &f.active_execution {
        return Err(ProtocolError::new(
            ErrorCode::Conflict,
            "work unit already has an active execution lease",
        )
        .with_object(e));
    }
    if !f.has_scope {
        return fail(
            ErrorCode::InvalidArgument,
            "allowed effects require a non-empty allowed resource scope",
        );
    }
    if let Some(r) = f.retry {
        if !r.same_work_unit {
            return fail(
                ErrorCode::InvalidArgument,
                "retry_of must name an attempt of the same work unit",
            );
        }
        if !matches!(
            r.previous_state,
            ExecutionState::Failed | ExecutionState::Lost | ExecutionState::Cancelled
        ) {
            return fail(
                ErrorCode::InvalidTransition,
                format!(
                    "cannot retry an execution in state {}",
                    r.previous_state.as_str()
                ),
            );
        }
        if r.attempts_used >= r.max_attempts {
            return fail(ErrorCode::Conflict, "retry budget exhausted");
        }
    }
    Ok(())
}

pub fn in_scope(selectors: &[ResourceSelector], r: &ResourceRef) -> bool {
    selectors
        .iter()
        .any(|s| crate::authority::selector_matches(s, r))
}

// ---------------------------------------------------------------------------------------------
// Candidate assembly

/// Effects already applied to the same resource (oldest first).
pub fn prior_effects(effects: &[AppliedEffect], target: &ResourceRef) -> Vec<AppliedEffect> {
    effects
        .iter()
        .filter(|e| {
            e.target.kind == target.kind
                && e.target.locator == target.locator
                && e.target.extension == target.extension
        })
        .cloned()
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSummary {
    pub effects: Vec<EffectSummary>,
    pub resources: Vec<ResourceRef>,
    pub extensions: Vec<ExtensionRef>,
}

pub fn summarize(effects: &[AppliedEffect]) -> CandidateSummary {
    let resources: BTreeSet<ResourceRef> = effects.iter().map(|e| e.target.clone()).collect();
    let extensions: BTreeSet<ExtensionRef> = effects
        .iter()
        .filter_map(|e| e.provenance.extension.clone())
        .collect();
    CandidateSummary {
        effects: effects
            .iter()
            .map(|e| EffectSummary {
                kind: e.kind.clone(),
                target: e.target.clone(),
            })
            .collect(),
        resources: resources.into_iter().collect(),
        extensions: extensions.into_iter().collect(),
    }
}

/// Digest committing to the provenance of every candidate effect, in order.
pub fn provenance_root(effects: &[AppliedEffect]) -> Result<Digest, ProtocolError> {
    let all: Vec<&Provenance> = effects.iter().map(|e| &e.provenance).collect();
    crate::crypto::digest_of(&all)
}

/// Minimum provenance (spec/observations.md): an effect without it cannot enter a promotable
/// candidate.
pub fn provenance_complete(p: &Provenance) -> bool {
    !p.provider.is_empty() && !p.harness.is_empty() && p.extension.is_some() && p.generation > 0
}

// ---------------------------------------------------------------------------------------------
// Contracts

/// Structured protocol a harness uses to drive one admitted execution.
pub trait ExecutionSession {
    fn heartbeat(&mut self) -> Result<(), ProtocolError>;
    /// Submits an effect proposal; `Ok(true)` if applied, `Ok(false)` if the extension rejected it.
    fn submit_effect(&mut self, effect: EffectProposal) -> Result<bool, ProtocolError>;
    fn observe(
        &mut self,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<ObservationId, ProtocolError>;
}

/// Coordinates a worker for one work unit.
pub trait Harness {
    fn id(&self) -> &str;
    fn run(
        &mut self,
        work_kind: &str,
        spec: Option<&serde_json::Value>,
        session: &mut dyn ExecutionSession,
    ) -> Result<(), String>;
}

/// Supplies workers and harnesses for admitted executions.
pub trait Provider {
    fn descriptor(&self) -> crate::protocol::ProviderDescriptor;
    fn harness(&self, id: &str) -> Option<Box<dyn Harness>>;
}

/// Fails with `INVALID_ARGUMENT` unless `name` is namespaced.
pub fn check_kind(name: &str) -> Result<(), ProtocolError> {
    if crate::core::names::is_namespaced(name) {
        Ok(())
    } else {
        Err(err::invalid(format!("{name:?} is not a namespaced name")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;
    use serde_json::json;

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_unix_nanos(0).plus_millis(ms)
    }

    #[test]
    fn leases_expire_and_renew() {
        let l = new_lease(
            "lse_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            "exe_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            3,
            "p.x",
            t(0),
            1000,
            250,
        );
        assert_eq!(l.expires_at, t(1000));
        assert!(!lease_expired(&l, t(999), 0));
        assert!(lease_expired(&l, t(1000), 0));
        assert!(!lease_expired(&l, t(1500), 1000), "resumable grace");
        let r = renew(&l, t(900), 1000);
        assert_eq!(r.expires_at, t(1900));
    }

    fn facts() -> AdmissionFacts {
        AdmissionFacts {
            pack_state: PackState::Open,
            pack_generation: 2,
            expected_generation: 2,
            work_unit: Some(WorkUnitState::Open),
            waiting_on: vec![],
            provider: Some(ProviderSupport {
                harness_supported: true,
                worker_kind_supported: true,
            }),
            unregistered_effects: vec![],
            unbound_effects: vec![],
            active_execution: None,
            retry: None,
            has_scope: true,
        }
    }

    #[test]
    fn admission_accepts_ready_work() {
        check_admission(&facts()).unwrap();
    }

    #[test]
    fn admission_rejections_in_order() {
        type Mutation = Box<dyn Fn(&mut AdmissionFacts)>;
        let cases: Vec<(Mutation, ErrorCode)> = vec![
            (
                Box::new(|f| f.pack_state = PackState::Sealed),
                ErrorCode::InvalidTransition,
            ),
            (
                Box::new(|f| f.pack_state = PackState::Quarantined),
                ErrorCode::Quarantined,
            ),
            (
                Box::new(|f| f.pack_state = PackState::Promoted),
                ErrorCode::ImmutableObject,
            ),
            (
                Box::new(|f| f.expected_generation = 1),
                ErrorCode::StaleGeneration,
            ),
            (Box::new(|f| f.work_unit = None), ErrorCode::NotFound),
            (
                Box::new(|f| f.work_unit = Some(WorkUnitState::Completed)),
                ErrorCode::InvalidTransition,
            ),
            (
                Box::new(|f| f.waiting_on = vec!["wku_x".into()]),
                ErrorCode::ExecutionNotReady,
            ),
            (Box::new(|f| f.provider = None), ErrorCode::NotFound),
            (
                Box::new(|f| {
                    f.provider = Some(ProviderSupport {
                        harness_supported: false,
                        worker_kind_supported: true,
                    })
                }),
                ErrorCode::InvalidArgument,
            ),
            (
                Box::new(|f| f.unregistered_effects = vec!["x.y".into()]),
                ErrorCode::ExtensionIncompatible,
            ),
            (
                Box::new(|f| f.unbound_effects = vec!["x.y".into()]),
                ErrorCode::InvalidArgument,
            ),
            (
                Box::new(|f| f.active_execution = Some("exe_1".into())),
                ErrorCode::Conflict,
            ),
            (
                Box::new(|f| f.has_scope = false),
                ErrorCode::InvalidArgument,
            ),
            (
                Box::new(|f| {
                    f.retry = Some(RetryFacts {
                        previous_state: ExecutionState::Succeeded,
                        same_work_unit: true,
                        attempts_used: 1,
                        max_attempts: 3,
                    })
                }),
                ErrorCode::InvalidTransition,
            ),
            (
                Box::new(|f| {
                    f.retry = Some(RetryFacts {
                        previous_state: ExecutionState::Lost,
                        same_work_unit: false,
                        attempts_used: 1,
                        max_attempts: 3,
                    })
                }),
                ErrorCode::InvalidArgument,
            ),
            (
                Box::new(|f| {
                    f.retry = Some(RetryFacts {
                        previous_state: ExecutionState::Failed,
                        same_work_unit: true,
                        attempts_used: 3,
                        max_attempts: 3,
                    })
                }),
                ErrorCode::Conflict,
            ),
        ];
        for (i, (mutate, code)) in cases.into_iter().enumerate() {
            let mut f = facts();
            mutate(&mut f);
            assert_eq!(check_admission(&f).unwrap_err().code, code, "case {i}");
        }
        let mut f = facts();
        f.retry = Some(RetryFacts {
            previous_state: ExecutionState::Lost,
            same_work_unit: true,
            attempts_used: 1,
            max_attempts: 3,
        });
        check_admission(&f).unwrap();
    }

    fn eff(key: &str, n: u8) -> AppliedEffect {
        AppliedEffect {
            id: EffectId::from_bytes([1, 2, 3, 4, 5, 6, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, n])
                .unwrap(),
            work_unit: "wku_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            kind: "kv.set".into(),
            target: ResourceRef {
                kind: "kv.entry".into(),
                locator: key.into(),
                version: None,
                extension: "org.x.kv".into(),
            },
            payload: json!({"value": n.to_string()}),
            preconditions: vec![],
            outputs: vec![],
            outcome: json!({}),
            provenance: provenance_fixture(),
        }
    }

    fn provenance_fixture() -> Provenance {
        Provenance {
            actor: "pri_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            caller: "pri_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            provider: "org.x.provider".into(),
            worker: Some("w1".into()),
            harness: "org.x.harness".into(),
            extension: Some(ExtensionRef {
                id: "org.x.kv".into(),
                version: "1.0.0".into(),
                manifest_digest: Digest::ZERO,
            }),
            grants: vec![],
            request_id: "req_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            pack: "cpk_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            generation: 1,
            execution: "exe_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            runtime_instance: "rti_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            inputs: vec![],
        }
    }

    #[test]
    fn candidate_helpers() {
        let effects = vec![eff("a", 1), eff("b", 2), eff("a", 3)];
        let prior = prior_effects(&effects, &effects[0].target);
        assert_eq!(prior.len(), 2);
        let summary = summarize(&effects);
        assert_eq!(summary.effects.len(), 3);
        assert_eq!(summary.resources.len(), 2);
        assert_eq!(summary.extensions.len(), 1);
        assert_eq!(
            provenance_root(&effects).unwrap(),
            provenance_root(&effects).unwrap()
        );
        assert_ne!(
            provenance_root(&effects).unwrap(),
            provenance_root(&effects[..2]).unwrap()
        );
    }

    #[test]
    fn provenance_completeness() {
        assert!(provenance_complete(&provenance_fixture()));
        let mut p = provenance_fixture();
        p.extension = None;
        assert!(!provenance_complete(&p));
        let mut p = provenance_fixture();
        p.harness.clear();
        assert!(!provenance_complete(&p));
    }

    #[test]
    fn selectors_bound_effects() {
        let r = eff("app/a", 1).target;
        let sel = |p: &str| ResourceSelector {
            kind: "kv.entry".into(),
            locator_prefix: Some(p.into()),
        };
        assert!(in_scope(&[sel("app/")], &r));
        assert!(!in_scope(&[sel("other/")], &r));
        assert!(!in_scope(&[], &r));
    }
}
