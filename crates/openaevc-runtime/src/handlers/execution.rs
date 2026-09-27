//! Execution commands (spec/execution.md): admission, leases, effect proposals, observations,
//! completion, cancellation and loss.

use std::collections::BTreeSet;

use openaevc_core::lifecycle::check_execution_transition;
use openaevc_core::IdGeneratorExt;
use openaevc_execution::{self as exec, AdmissionFacts, ProviderSupport, RetryFacts};
use openaevc_extension_contract::wire::{ApplyOutput, Operation, ValidateOutput};
use openaevc_protocol::{
    err, ActiveEdge, ActiveEdgeKind, AppliedEffect, Blob, ChangePack, CommandResult, Digest,
    EffectId, EffectProposal, ErrorCode, Execution, ExecutionId, ExecutionRequest, ExecutionState,
    LeaseId, NamespaceId, NodeRef, ObjectKind, Observation, PrincipalId, ProtocolError, Provenance,
    ProviderDescriptor, ResourceRef, WorkUnitState,
};
use serde_json::{json, Value};

use super::packs;
use crate::records::{self, ExtensionRecord};
use crate::tx::Tx;
use crate::view::NsView;
use crate::{authz, ext, Ctx, Result, Shared};

const MAX_INLINE_OBSERVATION: usize = 64 * 1024;
const MAX_BLOB: usize = 8 * 1024 * 1024;

fn exe_key(tx: &Tx<'_>, id: ExecutionId) -> String {
    records::key(&tx.ns, id)
}

fn provider(tx: &Tx<'_>, id: &str) -> Result<Option<ProviderDescriptor>> {
    tx.peek(records::PROVIDER, &records::key(&tx.ns, id))
}

fn active_list(tx: &mut Tx<'_>) -> Result<Vec<ExecutionId>> {
    Ok(tx
        .get(records::ACTIVE_EXECUTIONS, &tx.ns.to_string())?
        .unwrap_or_default())
}

fn set_active(
    tx: &mut Tx<'_>,
    id: ExecutionId,
    active: bool,
    work_unit: openaevc_protocol::WorkUnitId,
) -> Result<()> {
    let mut list = active_list(tx)?;
    list.retain(|x| *x != id);
    let wkey = records::key(&tx.ns, work_unit);
    if active {
        list.push(id);
        tx.put(records::WU_EXECUTION, &wkey, &Some(id))?;
    } else {
        tx.put(records::WU_EXECUTION, &wkey, &None::<ExecutionId>)?;
    }
    tx.put(records::ACTIVE_EXECUTIONS, &tx.ns.to_string(), &list)
}

fn add_edges(tx: &mut Tx<'_>, new: Vec<ActiveEdge>) -> Result<()> {
    let key = tx.ns.to_string();
    let mut all: Vec<ActiveEdge> = tx.get(records::EDGES, &key)?.unwrap_or_default();
    all.extend(new);
    tx.put(records::EDGES, &key, &all)
}

fn transition(
    tx: &mut Tx<'_>,
    e: &mut Execution,
    to: ExecutionState,
    kind: &str,
    body: Value,
) -> Result<()> {
    check_execution_transition(e.state, to)?;
    e.state = to;
    e.updated_at = tx.now;
    if to.is_terminal() {
        e.finished_at = Some(tx.now);
    }
    tx.emit(
        kind,
        body,
        vec![
            e.id.to_string(),
            e.pack.to_string(),
            e.work_unit.to_string(),
        ],
    );
    Ok(())
}

/// Grants authorizing `principal` for `action` over `scope` (admission) — authority is
/// evaluated for the execution actor, not merely the caller.
fn authorize_scope(
    tx: &Tx<'_>,
    ctx: &Ctx,
    principal: PrincipalId,
    action: &str,
    scope: &openaevc_protocol::ResourceSelector,
) -> Result<Vec<Digest>> {
    let view = NsView {
        tx,
        roots: ctx.roots.clone(),
    };
    Ok(openaevc_authority::authorize_scope(&view, tx.now, principal, action, scope)?.grants)
}

fn authorize_resource(
    tx: &Tx<'_>,
    ctx: &Ctx,
    principal: PrincipalId,
    action: &str,
    r: &ResourceRef,
) -> Result<Vec<Digest>> {
    let view = NsView {
        tx,
        roots: ctx.roots.clone(),
    };
    let req = openaevc_authority::Request {
        principal,
        action,
        resource: Some(r),
    };
    Ok(openaevc_authority::authorize(&view, tx.now, &req)?.grants)
}

pub(crate) fn start(tx: &mut Tx<'_>, ctx: &Ctx, req: ExecutionRequest) -> Result<CommandResult> {
    let admission = authz(tx, ctx, "execution.start", None)?;
    for k in req.allowed_effects.iter() {
        exec::check_kind(k)?;
    }
    openaevc_core::names::validate_keys(&req.budget)?;
    if req.idempotency_key.is_empty() || req.idempotency_key.len() > 128 {
        return Err(err::invalid("idempotency_key must be 1..=128 bytes"));
    }
    let idem_key = records::key(&tx.ns, &req.idempotency_key);
    if let Some(existing) = tx.get::<ExecutionId>(records::EXECUTION_IDEMPOTENCY, &idem_key)? {
        let e: Execution = tx.require(records::EXECUTION, &exe_key(tx, existing), "execution")?;
        if e.work_unit == req.work_unit && e.pack == req.pack && !e.state.is_terminal() {
            tx.emit(
                "execution.admission_replayed",
                json!({"execution": e.id}),
                vec![e.id.to_string()],
            );
            return Ok(CommandResult {
                id: Some(e.id.to_string()),
                state: Some(e.state.as_str().into()),
                lease: e.lease,
                generation: Some(e.generation),
                ..Default::default()
            });
        }
        return Err(ProtocolError::new(
            ErrorCode::Conflict,
            "idempotency key already used for another execution",
        )
        .with_object(existing));
    }
    let pack: ChangePack = packs::load(tx, req.pack)?;
    let unit = pack.work_units.iter().find(|w| w.id == req.work_unit);
    let waiting: Vec<String> = super::work_status(tx, Some(req.pack), false)?
        .into_iter()
        .filter(|w| w["work_unit"] == req.work_unit.to_string())
        .flat_map(|w| w["waiting_on"].as_array().cloned().unwrap_or_default())
        .filter_map(|n| n["node"].as_str().map(str::to_owned))
        .filter(|n| *n != req.pack.to_string())
        .collect();
    let prov = provider(tx, &req.provider)?;
    let support = prov.as_ref().map(|p| ProviderSupport {
        harness_supported: p.harnesses.contains(&req.harness),
        worker_kind_supported: req
            .worker
            .as_ref()
            .is_none_or(|w| p.worker_kinds.contains(&w.kind)),
    });
    let mut extensions: Vec<ExtensionRecord> = Vec::new();
    let (mut unregistered, mut unbound) = (Vec::new(), Vec::new());
    for k in &req.allowed_effects {
        match ext::by_effect(tx, k) {
            Ok(rec) => {
                if !pack.extension_bindings.is_empty()
                    && !pack.extension_bindings.contains(&rec.manifest.id)
                {
                    unbound.push(k.clone());
                }
                if !extensions.iter().any(|x| x.manifest.id == rec.manifest.id) {
                    extensions.push(rec);
                }
            }
            Err(_) => unregistered.push(k.clone()),
        }
    }
    let active = tx
        .peek::<Option<ExecutionId>>(records::WU_EXECUTION, &records::key(&tx.ns, req.work_unit))?
        .flatten();
    let (retry, attempt) = match req.retry_of {
        None => (None, 1),
        Some(prev_id) => {
            let prev: Execution = tx.require(
                records::EXECUTION,
                &exe_key(tx, prev_id),
                "retried execution",
            )?;
            (
                Some(RetryFacts {
                    previous_state: prev.state,
                    same_work_unit: prev.work_unit == req.work_unit && prev.pack == req.pack,
                    attempts_used: prev.attempt,
                    max_attempts: prev.max_attempts,
                }),
                prev.attempt + 1,
            )
        }
    };
    exec::check_admission(&AdmissionFacts {
        pack_state: pack.state,
        pack_generation: pack.generation,
        expected_generation: req.expected_generation,
        work_unit: unit.map(|u| u.state),
        waiting_on: waiting,
        provider: support,
        unregistered_effects: unregistered,
        unbound_effects: unbound,
        active_execution: active.map(|a| a.to_string()),
        retry,
        has_scope: req.allowed_effects.is_empty() || !req.allowed_resources.is_empty(),
    })?;
    let provider = prov.ok_or_else(|| err::not_found("provider"))?;
    // Authority over the whole requested scope, for the actor, before anything starts.
    let mut grants: BTreeSet<Digest> = admission.grants.into_iter().collect();
    for a in &provider.required_actions {
        grants.extend(authz(tx, ctx, a, None)?.grants);
    }
    for kind in &req.allowed_effects {
        let rec = ext::by_effect(tx, kind)?;
        let decl = rec
            .manifest
            .effect_kinds
            .iter()
            .find(|e| &e.kind == kind)
            .ok_or_else(|| err::internal("effect declaration"))?;
        for sel in &req.allowed_resources {
            for action in &decl.required_actions {
                grants.extend(authorize_scope(tx, ctx, ctx.principal, action, sel)?);
            }
        }
    }
    for d in &req.context {
        tx.load_object(d)?.ok_or_else(|| {
            err::not_found(format!("context object {d} not found")).with_object(d)
        })?;
    }
    if req.max_attempts == 0 || req.timeout_ms == 0 {
        return Err(err::invalid("max_attempts and timeout_ms must be positive"));
    }
    let id: ExecutionId = tx.rt.ids.next();
    let lease = exec::new_lease(
        tx.rt.ids.next(),
        id,
        pack.generation,
        &provider.id,
        tx.now,
        tx.rt.config.lease_ms,
        tx.rt.config.heartbeat_interval_ms,
    );
    let mut e = Execution {
        id,
        namespace: tx.ns,
        pack: req.pack,
        generation: pack.generation,
        work_unit: req.work_unit,
        actor: ctx.principal,
        provider: provider.id.clone(),
        harness: req.harness,
        worker: req.worker,
        state: ExecutionState::Pending,
        allowed_resources: req.allowed_resources,
        allowed_effects: req.allowed_effects,
        grants: grants.into_iter().collect(),
        extensions: extensions.iter().map(ExtensionRecord::reference).collect(),
        context: req.context.clone(),
        timeout_ms: req.timeout_ms,
        budget: req.budget,
        max_attempts: req.max_attempts,
        attempt,
        idempotency_key: req.idempotency_key,
        retry_of: req.retry_of,
        lease: Some(lease.clone()),
        request_id: ctx.request_id,
        created_at: tx.now,
        updated_at: tx.now,
        finished_at: None,
        failure: None,
        effects: vec![],
        observations: vec![],
    };
    let admitted = json!({"execution": id, "attempt": attempt, "retry_of": e.retry_of, "generation": e.generation, "work_unit": e.work_unit});
    transition(
        tx,
        &mut e,
        ExecutionState::Admitted,
        "execution.admitted",
        admitted,
    )?;
    transition(
        tx,
        &mut e,
        ExecutionState::Starting,
        "execution.starting",
        json!({"execution": id, "lease": lease.id, "expires_at": lease.expires_at}),
    )?;
    let mut edges = vec![ActiveEdge {
        from: id.into(),
        to: e.work_unit.into(),
        kind: ActiveEdgeKind::Consumes,
        annotations: Default::default(),
    }];
    if let Some(prev) = e.retry_of {
        edges.push(ActiveEdge {
            from: id.into(),
            to: prev.into(),
            kind: ActiveEdgeKind::DerivedFrom,
            annotations: Default::default(),
        });
    }
    edges.extend(req.context.iter().map(|d| ActiveEdge {
        from: id.into(),
        to: NodeRef::Digest(*d),
        kind: ActiveEdgeKind::Consumes,
        annotations: Default::default(),
    }));
    add_edges(tx, edges)?;
    tx.put(records::EXECUTION, &exe_key(tx, id), &e)?;
    tx.put(records::EXECUTION_IDEMPOTENCY, &idem_key, &id)?;
    set_active(tx, id, true, e.work_unit)?;
    Ok(CommandResult {
        id: Some(id.to_string()),
        state: Some(e.state.as_str().into()),
        generation: Some(e.generation),
        lease: Some(lease),
        ..Default::default()
    })
}

/// Loads an execution for a worker-side command and checks caller, state and lease.
fn load_for_worker(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: ExecutionId,
    lease: LeaseId,
    action: &str,
) -> Result<Execution> {
    authz(tx, ctx, action, None)?;
    let e: Execution = tx.require(records::EXECUTION, &exe_key(tx, id), "execution")?;
    let provider_principal = provider(tx, &e.provider)?.map(|p| p.principal);
    if ctx.principal != e.actor && Some(ctx.principal) != provider_principal {
        return Err(
            err::forbidden("only the execution's actor or provider may drive it").with_object(id),
        );
    }
    if e.state == ExecutionState::Lost {
        return Err(ProtocolError::new(
            ErrorCode::ExecutionLost,
            format!("execution {id} was lost; start a new attempt"),
        )
        .with_object(id));
    }
    if e.state.is_terminal() {
        return Err(ProtocolError::new(
            ErrorCode::InvalidTransition,
            format!("execution {id} is {}", e.state.as_str()),
        )
        .with_object(id));
    }
    if e.lease.as_ref().map(|l| l.id) != Some(lease) {
        return Err(
            err::forbidden("lease does not match the execution's current lease").with_object(id),
        );
    }
    Ok(e)
}

fn require_live_lease(tx: &Tx<'_>, e: &Execution) -> Result<()> {
    match &e.lease {
        Some(l) if !exec::lease_expired(l, tx.now, 0) => Ok(()),
        _ => Err(
            err::conflict("execution lease expired; resume it with HeartbeatExecution")
                .with_object(e.id),
        ),
    }
}

fn ensure_running(tx: &mut Tx<'_>, e: &mut Execution) -> Result<()> {
    if e.state == ExecutionState::Starting {
        let id = e.id;
        transition(
            tx,
            e,
            ExecutionState::Running,
            "execution.running",
            json!({"execution": id}),
        )?;
    }
    Ok(())
}

fn save(tx: &mut Tx<'_>, e: &Execution) -> Result<()> {
    tx.put(records::EXECUTION, &exe_key(tx, e.id), e)
}

pub(crate) fn heartbeat(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: ExecutionId,
    lease: LeaseId,
    generation: u64,
) -> Result<CommandResult> {
    let mut e = load_for_worker(tx, ctx, id, lease, "execution.start")?;
    if generation != e.generation {
        return Err(ProtocolError::new(
            ErrorCode::StaleGeneration,
            "lease generation does not match",
        )
        .with_generations(generation, e.generation));
    }
    let l = e.lease.as_ref().ok_or_else(|| err::internal("lease"))?;
    let renewed = exec::renew(l, tx.now, tx.rt.config.lease_ms);
    let resumed = exec::lease_expired(l, tx.now, 0);
    e.lease = Some(renewed.clone());
    ensure_running(tx, &mut e)?;
    tx.emit(
        "execution.heartbeat",
        json!({"execution": id, "expires_at": renewed.expires_at, "resumed": resumed}),
        vec![id.to_string()],
    );
    save(tx, &e)?;
    Ok(CommandResult {
        id: Some(id.to_string()),
        state: Some(e.state.as_str().into()),
        lease: Some(renewed),
        ..Default::default()
    })
}

pub(crate) fn submit_effect(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: ExecutionId,
    lease: LeaseId,
    effect: EffectProposal,
) -> Result<CommandResult> {
    let mut e = load_for_worker(tx, ctx, id, lease, "execution.start")?;
    require_live_lease(tx, &e)?;
    exec::check_kind(&effect.kind)?;
    if !e.allowed_effects.contains(&effect.kind) {
        return Err(err::forbidden(format!(
            "effect kind {} is outside the execution's allowed effects",
            effect.kind
        ))
        .with_missing_action(effect.kind.clone()));
    }
    if !exec::in_scope(&e.allowed_resources, &effect.target) {
        return Err(err::forbidden(format!(
            "resource {}:{} is outside the execution's allowed resources",
            effect.target.kind, effect.target.locator
        )));
    }
    let rec = ext::by_effect(tx, &effect.kind)?;
    let decl = rec
        .manifest
        .effect_kinds
        .iter()
        .find(|d| d.kind == effect.kind)
        .ok_or_else(|| err::internal("effect declaration"))?
        .clone();
    if effect.target.kind != decl.resource_kind || effect.target.extension != rec.manifest.id {
        return Err(err::invalid(format!(
            "{} effects target {} resources of {}",
            effect.kind, decl.resource_kind, rec.manifest.id
        )));
    }
    let mut grants: BTreeSet<Digest> = e.grants.iter().copied().collect();
    for action in &decl.required_actions {
        grants.extend(authorize_resource(
            tx,
            ctx,
            e.actor,
            action,
            &effect.target,
        )?);
    }
    let mut pack = packs::load(tx, e.pack)?;
    if pack.state != openaevc_protocol::PackState::Open {
        return Err(packs::state_error(&pack, "mutate"));
    }
    if pack.generation != e.generation {
        return Err(ProtocolError::new(
            ErrorCode::StaleGeneration,
            "pack changed since the execution was admitted",
        )
        .with_generations(e.generation, pack.generation));
    }
    ensure_running(tx, &mut e)?;
    let prior = exec::prior_effects(&pack.candidate_effects, &effect.target);
    let scope = [effect.target.clone()];
    let (out, _, _) = ext::invoke(
        tx,
        &rec,
        Operation::ValidateEffect {
            effect: effect.clone(),
            prior: prior.clone(),
        },
        None,
        &scope,
        &prior,
    )?;
    let verdict: ValidateOutput = ext::decode(&rec, out)?;
    let effect_id: EffectId = tx.rt.ids.next();
    if !verdict.valid {
        tx.emit(
            "effect.rejected",
            json!({"execution": id, "effect": effect_id, "kind": effect.kind, "target": effect.target, "reason": verdict.reason}),
            vec![id.to_string(), effect_id.to_string()],
        );
        save(tx, &e)?;
        return Ok(CommandResult {
            id: Some(effect_id.to_string()),
            state: Some("REJECTED".into()),
            ..Default::default()
        });
    }
    let (out, _, extension) = ext::invoke(
        tx,
        &rec,
        Operation::ApplyEffect {
            effect: effect.clone(),
            prior: prior.clone(),
        },
        None,
        &scope,
        &prior,
    )?;
    let applied: ApplyOutput = ext::decode(&rec, out)?;
    let provenance = Provenance {
        actor: e.actor,
        caller: ctx.caller,
        provider: e.provider.clone(),
        worker: e.worker.as_ref().map(|w| w.id.clone()),
        harness: e.harness.clone(),
        extension: Some(extension),
        grants: grants.into_iter().collect(),
        request_id: ctx.request_id,
        pack: e.pack,
        generation: e.generation,
        execution: id,
        runtime_instance: tx.rt.instance,
        inputs: e.context.clone(),
    };
    if !exec::provenance_complete(&provenance) {
        return Err(err::invalid("effect lacks minimum provenance"));
    }
    let record = AppliedEffect {
        id: effect_id,
        work_unit: e.work_unit,
        kind: effect.kind.clone(),
        target: effect.target.clone(),
        payload: effect.payload,
        preconditions: effect.preconditions,
        outputs: effect.outputs,
        outcome: applied.outcome.clone(),
        provenance,
    };
    pack.candidate_effects.push(record);
    packs::save(tx, &mut pack, false)?;
    e.effects.push(effect_id);
    save(tx, &e)?;
    tx.emit(
        "effect.applied",
        json!({"execution": id, "effect": effect_id, "kind": effect.kind, "target": effect.target, "outcome": applied.outcome, "generation": e.generation}),
        vec![id.to_string(), effect_id.to_string(), e.pack.to_string()],
    );
    Ok(CommandResult {
        id: Some(effect_id.to_string()),
        state: Some("APPLIED".into()),
        generation: Some(e.generation),
        ..Default::default()
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_observation(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: ExecutionId,
    lease: LeaseId,
    kind: String,
    payload: Option<Value>,
    blob: Option<Blob>,
    related_resources: Vec<ResourceRef>,
    related_effects: Vec<EffectId>,
) -> Result<CommandResult> {
    authz(tx, ctx, "observation.append", None)?;
    let mut e = load_for_worker(tx, ctx, id, lease, "execution.start")?;
    require_live_lease(tx, &e)?;
    exec::check_kind(&kind)?;
    if payload.is_none() && blob.is_none() {
        return Err(err::invalid("an observation needs a payload or a blob"));
    }
    if let Some(p) = &payload {
        if openaevc_canonical::to_canonical(p)?.len() > MAX_INLINE_OBSERVATION {
            return Err(err::invalid(
                "inline observation payload too large; use a blob",
            ));
        }
    }
    if blob.as_ref().is_some_and(|b| b.data.len() > MAX_BLOB) {
        return Err(err::invalid("observation blob too large"));
    }
    if let Some(bad) = related_effects.iter().find(|x| !e.effects.contains(x)) {
        return Err(err::invalid(format!(
            "effect {bad} was not produced by this execution"
        )));
    }
    ensure_running(tx, &mut e)?;
    let blob_digest = match blob {
        Some(b) => Some(tx.object(ObjectKind::Blob, None, &b, false)?.digest()),
        None => None,
    };
    let obs_id = tx.rt.ids.next();
    let observation = Observation {
        id: obs_id,
        execution: id,
        pack: e.pack,
        generation: e.generation,
        work_unit: e.work_unit,
        producer: ctx.principal,
        observed_at: tx.now,
        kind: kind.clone(),
        payload,
        blob: blob_digest,
        related_resources,
        related_effects,
        provenance: Provenance {
            actor: e.actor,
            caller: ctx.caller,
            provider: e.provider.clone(),
            worker: e.worker.as_ref().map(|w| w.id.clone()),
            harness: e.harness.clone(),
            extension: e.extensions.first().cloned(),
            grants: e.grants.clone(),
            request_id: ctx.request_id,
            pack: e.pack,
            generation: e.generation,
            execution: id,
            runtime_instance: tx.rt.instance,
            inputs: e.context.clone(),
        },
    };
    let obj = tx.object(
        ObjectKind::Observation,
        Some(obs_id.to_string()),
        &observation,
        false,
    )?;
    add_edges(
        tx,
        vec![ActiveEdge {
            from: id.into(),
            to: NodeRef::Digest(obj.digest()),
            kind: ActiveEdgeKind::Produces,
            annotations: Default::default(),
        }],
    )?;
    e.observations.push(obs_id);
    save(tx, &e)?;
    tx.emit(
        "observation.appended",
        json!({"execution": id, "observation": obs_id, "digest": obj.digest(), "kind": kind}),
        vec![id.to_string(), obj.digest().to_string()],
    );
    Ok(CommandResult {
        id: Some(obs_id.to_string()),
        digest: Some(obj.digest()),
        ..Default::default()
    })
}

pub(crate) fn complete(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: ExecutionId,
    lease: LeaseId,
) -> Result<CommandResult> {
    let mut e = load_for_worker(tx, ctx, id, lease, "execution.start")?;
    require_live_lease(tx, &e)?;
    ensure_running(tx, &mut e)?;
    let body = json!({"execution": id, "effects": e.effects.len()});
    transition(
        tx,
        &mut e,
        ExecutionState::Succeeded,
        "execution.succeeded",
        body,
    )?;
    let mut pack = packs::load(tx, e.pack)?;
    if let Some(u) = pack.work_units.iter_mut().find(|u| u.id == e.work_unit) {
        u.state = WorkUnitState::Completed;
    }
    packs::save(tx, &mut pack, false)?;
    set_active(tx, id, false, e.work_unit)?;
    save(tx, &e)?;
    Ok(CommandResult {
        id: Some(id.to_string()),
        state: Some("SUCCEEDED".into()),
        ..Default::default()
    })
}

pub(crate) fn fail(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: ExecutionId,
    lease: LeaseId,
    reason: String,
) -> Result<CommandResult> {
    let mut e = load_for_worker(tx, ctx, id, lease, "execution.start")?;
    e.failure = Some(reason.clone());
    transition(
        tx,
        &mut e,
        ExecutionState::Failed,
        "execution.failed",
        json!({"execution": id, "reason": reason}),
    )?;
    set_active(tx, id, false, e.work_unit)?;
    save(tx, &e)?;
    Ok(CommandResult {
        id: Some(id.to_string()),
        state: Some("FAILED".into()),
        ..Default::default()
    })
}

pub(crate) fn cancel(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: ExecutionId,
    reason: Option<String>,
) -> Result<CommandResult> {
    authz(tx, ctx, "execution.cancel", None)?;
    let mut e: Execution = tx.require(records::EXECUTION, &exe_key(tx, id), "execution")?;
    if e.state == ExecutionState::Lost {
        return Err(ProtocolError::new(
            ErrorCode::ExecutionLost,
            format!("execution {id} was lost"),
        ));
    }
    e.failure = reason.clone();
    transition(
        tx,
        &mut e,
        ExecutionState::Cancelled,
        "execution.cancelled",
        json!({"execution": id, "reason": reason}),
    )?;
    set_active(tx, id, false, e.work_unit)?;
    save(tx, &e)?;
    Ok(CommandResult {
        id: Some(id.to_string()),
        state: Some("CANCELLED".into()),
        ..Default::default()
    })
}

/// Marks executions whose lease (plus the resumable grace period) has expired as LOST, in a
/// system transaction of its own. A lost execution never becomes successful.
pub(crate) fn expire_leases(rt: &Shared, ns: NamespaceId) -> Result<()> {
    let mut tx = Tx::new(rt, ns, rt.runtime_principal)?;
    let active = active_list(&mut tx)?;
    if active.is_empty() {
        return Ok(());
    }
    for id in active {
        let Some(mut e) = tx.get::<Execution>(records::EXECUTION, &exe_key(&tx, id))? else {
            continue;
        };
        let resumable = provider(&tx, &e.provider)?.is_some_and(|p| p.resumable);
        let grace = if resumable { rt.config.lease_ms } else { 0 };
        let expired = e
            .lease
            .as_ref()
            .is_some_and(|l| exec::lease_expired(l, tx.now, grace));
        if expired && !e.state.is_terminal() {
            e.failure = Some("lease expired".into());
            transition(
                &mut tx,
                &mut e,
                ExecutionState::Lost,
                "execution.lost",
                json!({"execution": id, "reason": "lease expired"}),
            )?;
            set_active(&mut tx, id, false, e.work_unit)?;
            save(&mut tx, &e)?;
        }
    }
    if tx.event_count() == 0 {
        return Ok(());
    }
    let events = tx.finish_events()?;
    let batch = tx.into_batch(events)?;
    rt.store.commit(batch)?;
    rt.notify.send_modify(|v| *v += 1);
    Ok(())
}
