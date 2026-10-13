//! ChangePack / RevisionPack lifecycle (spec/changepack.md, spec/revisions.md).

use crate::core::lifecycle::check_pack_transition;
use crate::core::{names, IdGeneratorExt};
use crate::protocol::{
    err, ChangePack, CommandResult, Digest, ErrorCode, Metadata, ObjectKind, PackId, PackSpec,
    PackState, PromotedPack, ProtocolError, QuarantineInfo, ResourceRef, RevisionInfo,
    RevisionRelation, SealInfo, WorkUnitState,
};
use serde_json::{json, Value};

use crate::runtime::records;
use crate::runtime::tx::Tx;
use crate::runtime::{authz, Ctx, Result};

pub(crate) fn key(tx: &Tx<'_>, id: PackId) -> String {
    records::key(&tx.ns, id)
}

pub(crate) fn load(tx: &mut Tx<'_>, id: PackId) -> Result<ChangePack> {
    tx.get(records::PACK, &key(tx, id))?
        .ok_or_else(|| err::not_found(format!("pack {id} not found")).with_object(id))
}

/// Error for any attempt to change a pack that is not in `allowed` states.
pub(crate) fn state_error(p: &ChangePack, action: &str) -> ProtocolError {
    let (code, msg) = match p.state {
        PackState::Promoted => (
            ErrorCode::ImmutableObject,
            format!("pack {} is promoted and immutable", p.id),
        ),
        PackState::Quarantined => (
            ErrorCode::Quarantined,
            format!("pack {} is quarantined", p.id),
        ),
        PackState::Sealed | PackState::Qualified if action == "mutate" => (
            ErrorCode::InvalidTransition,
            format!("pack {} is sealed; use ReopenChangePack to change it", p.id),
        ),
        s => (
            ErrorCode::InvalidTransition,
            format!("cannot {action} pack {} in state {}", p.id, s.as_str()),
        ),
    };
    ProtocolError::new(code, msg).with_object(p.id)
}

pub(crate) fn check_generation(p: &ChangePack, expected: u64) -> Result<()> {
    if p.generation != expected {
        return Err(ProtocolError::new(
            ErrorCode::StaleGeneration,
            format!("pack {} is at generation {}", p.id, p.generation),
        )
        .with_object(p.id)
        .with_generations(expected, p.generation));
    }
    Ok(())
}

/// Loads an OPEN pack for a structural mutation at `expected` generation.
pub(crate) fn load_mutable(tx: &mut Tx<'_>, id: PackId, expected: u64) -> Result<ChangePack> {
    let p = load(tx, id)?;
    if p.state != PackState::Open {
        return Err(state_error(&p, "mutate"));
    }
    check_generation(&p, expected)?;
    Ok(p)
}

/// Persists the pack; a generation change also records the new generation in history.
pub(crate) fn save(tx: &mut Tx<'_>, p: &mut ChangePack, new_generation: bool) -> Result<()> {
    if new_generation {
        p.generation += 1;
    }
    p.updated_at = tx.now;
    tx.put(records::PACK, &key(tx, p.id), p)?;
    // History keeps the latest state of every generation (effects accumulate within one).
    tx.put(
        records::PACK_GENERATION,
        &records::generation_key(&tx.ns, p.id, p.generation),
        p,
    )
}

fn validate_resource(r: &ResourceRef) -> Result<()> {
    names::validate_namespaced(&r.kind)?;
    names::validate_extension_id(&r.extension)
}

fn validate_intent(v: &Value) -> Result<()> {
    let m = v
        .as_object()
        .ok_or_else(|| err::invalid("intent must be an object with namespaced keys"))?;
    names::validate_keys(m)
}

fn require_objects(tx: &Tx<'_>, digests: &[Digest], kind: ObjectKind) -> Result<()> {
    for d in digests {
        let o = tx.load_object(d)?.ok_or_else(|| {
            err::not_found(format!("{} {d} not found", kind.as_str())).with_object(d)
        })?;
        if o.kind() != kind {
            return Err(err::invalid(format!("{d} is not a {}", kind.as_str())).with_object(d));
        }
    }
    Ok(())
}

pub(crate) fn validate_fields(
    tx: &Tx<'_>,
    intent: Option<&Value>,
    resources: &[ResourceRef],
    policies: &[Digest],
    bindings: &[String],
    conflicts: &[Digest],
    metadata: &Metadata,
) -> Result<()> {
    if let Some(i) = intent {
        validate_intent(i)?;
    }
    resources.iter().try_for_each(validate_resource)?;
    bindings
        .iter()
        .try_for_each(|b| names::validate_extension_id(b))?;
    names::validate_keys(metadata)?;
    for d in policies {
        super::namespace::registered_policy(tx, d)?;
    }
    require_objects(tx, conflicts, ObjectKind::PromotedPack)?;
    Ok(())
}

fn new_pack(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: PackId,
    spec: PackSpec,
    revision: Option<RevisionInfo>,
) -> Result<CommandResult> {
    validate_fields(
        tx,
        spec.intent.as_ref(),
        &spec.resource_refs,
        &spec.required_policies,
        &spec.extension_bindings,
        &spec.conflicts_with,
        &spec.metadata,
    )?;
    let mut p = ChangePack {
        id,
        namespace: tx.ns,
        generation: 0,
        state: PackState::Open,
        created_by: ctx.principal,
        created_at: tx.now,
        updated_at: tx.now,
        intent: spec.intent,
        resource_refs: spec.resource_refs,
        work_units: vec![],
        required_policies: spec.required_policies,
        extension_bindings: spec.extension_bindings,
        conflicts_with: spec.conflicts_with,
        revision,
        candidate_effects: vec![],
        sealed: None,
        qualification: None,
        quarantine: None,
        promotion: None,
        metadata: spec.metadata,
    };
    save(tx, &mut p, true)?;
    tx.emit(
        "changepack.created",
        json!({"pack": id, "generation": 1, "revision": p.revision}),
        vec![id.to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        generation: Some(1),
        state: Some("OPEN".into()),
        ..Default::default()
    })
}

pub(crate) fn create(tx: &mut Tx<'_>, ctx: &Ctx, spec: PackSpec) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.create", None)?;
    let id = PackId::Change(tx.rt.ids.next());
    new_pack(tx, ctx, id, spec, None)
}

pub(crate) fn create_revision(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    relation: RevisionRelation,
    targets: Vec<Digest>,
    spec: PackSpec,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.create", None)?;
    if targets.is_empty() {
        return Err(err::invalid(
            "a RevisionPack needs at least one target promoted pack",
        ));
    }
    let mut sorted = targets.clone();
    sorted.sort();
    sorted.dedup();
    for t in &sorted {
        tx.require_object::<PromotedPack>(t, ObjectKind::PromotedPack)?;
    }
    let id = PackId::Revision(tx.rt.ids.next());
    let r = new_pack(
        tx,
        ctx,
        id,
        spec,
        Some(RevisionInfo {
            relation,
            targets: sorted.clone(),
        }),
    )?;
    let mut edges: Vec<crate::protocol::ActiveEdge> = tx
        .get(records::EDGES, &tx.ns.to_string())?
        .unwrap_or_default();
    for t in sorted {
        edges.push(crate::protocol::ActiveEdge {
            from: id.into(),
            to: crate::protocol::NodeRef::Digest(t),
            kind: crate::protocol::ActiveEdgeKind::RevisionOf,
            annotations: Default::default(),
        });
    }
    tx.put(records::EDGES, &tx.ns.to_string(), &edges)?;
    Ok(r)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn update(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: PackId,
    expected: u64,
    intent: Option<Value>,
    resource_refs: Option<Vec<ResourceRef>>,
    required_policies: Option<Vec<Digest>>,
    extension_bindings: Option<Vec<String>>,
    conflicts_with: Option<Vec<Digest>>,
    metadata: Option<Metadata>,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.mutate", None)?;
    let mut p = load_mutable(tx, id, expected)?;
    validate_fields(
        tx,
        intent.as_ref(),
        resource_refs.as_deref().unwrap_or_default(),
        required_policies.as_deref().unwrap_or_default(),
        extension_bindings.as_deref().unwrap_or_default(),
        conflicts_with.as_deref().unwrap_or_default(),
        metadata.as_ref().unwrap_or(&Metadata::new()),
    )?;
    if let Some(v) = intent {
        p.intent = Some(v);
    }
    if let Some(v) = resource_refs {
        p.resource_refs = v;
    }
    if let Some(v) = required_policies {
        p.required_policies = v;
    }
    if let Some(v) = extension_bindings {
        p.extension_bindings = v;
    }
    if let Some(v) = conflicts_with {
        p.conflicts_with = v;
    }
    if let Some(v) = metadata {
        p.metadata = v;
    }
    save(tx, &mut p, true)?;
    tx.emit(
        "changepack.updated",
        json!({"pack": id, "generation": p.generation}),
        vec![id.to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        generation: Some(p.generation),
        ..Default::default()
    })
}

pub(crate) fn seal(tx: &mut Tx<'_>, ctx: &Ctx, id: PackId, expected: u64) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.seal", None)?;
    let mut p = load(tx, id)?;
    if p.state != PackState::Open {
        return Err(state_error(&p, "seal"));
    }
    check_generation(&p, expected)?;
    for wu in &p.work_units {
        if tx
            .peek::<Option<crate::protocol::ExecutionId>>(
                records::WU_EXECUTION,
                &records::key(&tx.ns, wu.id),
            )?
            .flatten()
            .is_some()
        {
            return Err(err::conflict(format!(
                "work unit {} has an active execution; finish or cancel it before sealing",
                wu.id
            )));
        }
    }
    let candidate = crate::protocol::Candidate {
        pack: id,
        generation: p.generation,
        effects: p.candidate_effects.clone(),
    };
    let obj = tx.object(ObjectKind::Candidate, None, &candidate, false)?;
    check_pack_transition(p.state, PackState::Sealed)?;
    p.state = PackState::Sealed;
    p.sealed = Some(SealInfo {
        generation: p.generation,
        candidate: obj.digest(),
        sealed_at: tx.now,
    });
    save(tx, &mut p, false)?;
    tx.emit(
        "changepack.sealed",
        json!({"pack": id, "generation": p.generation, "candidate": obj.digest()}),
        vec![id.to_string(), obj.digest().to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        generation: Some(p.generation),
        digest: Some(obj.digest()),
        state: Some("SEALED".into()),
        ..Default::default()
    })
}

pub(crate) fn reopen(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: PackId,
    expected: u64,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.reopen", None)?;
    let mut p = load(tx, id)?;
    if !matches!(p.state, PackState::Sealed | PackState::Qualified) {
        return Err(state_error(&p, "reopen"));
    }
    check_generation(&p, expected)?;
    check_pack_transition(p.state, PackState::Open)?;
    let invalidated = p.sealed.as_ref().map(|s| s.candidate);
    p.state = PackState::Open;
    p.sealed = None;
    p.qualification = None;
    save(tx, &mut p, true)?;
    tx.emit(
        "changepack.reopened",
        json!({"pack": id, "generation": p.generation, "invalidated_candidate": invalidated}),
        vec![id.to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        generation: Some(p.generation),
        state: Some("OPEN".into()),
        ..Default::default()
    })
}

pub(crate) fn abandon(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: PackId,
    expected: u64,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.abandon", None)?;
    let mut p = load(tx, id)?;
    if !matches!(
        p.state,
        PackState::Open | PackState::Sealed | PackState::Qualified | PackState::Quarantined
    ) {
        return Err(state_error(&p, "abandon"));
    }
    check_generation(&p, expected)?;
    check_pack_transition(p.state, PackState::Abandoned)?;
    p.state = PackState::Abandoned;
    for wu in &mut p.work_units {
        if wu.state == WorkUnitState::Open {
            wu.state = WorkUnitState::Cancelled;
        }
    }
    save(tx, &mut p, false)?;
    tx.emit(
        "changepack.abandoned",
        json!({"pack": id, "generation": p.generation}),
        vec![id.to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        state: Some("ABANDONED".into()),
        ..Default::default()
    })
}

pub(crate) fn quarantine(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: PackId,
    reason: String,
) -> Result<CommandResult> {
    authz(tx, ctx, "quarantine.manage", None)?;
    let mut p = load(tx, id)?;
    if !matches!(
        p.state,
        PackState::Open | PackState::Sealed | PackState::Qualified
    ) {
        return Err(state_error(&p, "quarantine"));
    }
    check_pack_transition(p.state, PackState::Quarantined)?;
    p.quarantine = Some(QuarantineInfo {
        previous_state: p.state,
        reason: reason.clone(),
        by: ctx.principal,
        at: tx.now,
    });
    p.state = PackState::Quarantined;
    save(tx, &mut p, false)?;
    tx.emit(
        "changepack.quarantined",
        json!({"pack": id, "reason": reason}),
        vec![id.to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        state: Some("QUARANTINED".into()),
        ..Default::default()
    })
}

pub(crate) fn release(tx: &mut Tx<'_>, ctx: &Ctx, id: PackId) -> Result<CommandResult> {
    authz(tx, ctx, "quarantine.manage", None)?;
    let mut p = load(tx, id)?;
    let Some(q) = p
        .quarantine
        .take()
        .filter(|_| p.state == PackState::Quarantined)
    else {
        return Err(ProtocolError::new(
            ErrorCode::InvalidTransition,
            format!("pack {id} is not quarantined"),
        )
        .with_object(id));
    };
    check_pack_transition(p.state, q.previous_state)?;
    p.state = q.previous_state;
    save(tx, &mut p, false)?;
    tx.emit(
        "changepack.released",
        json!({"pack": id, "state": p.state}),
        vec![id.to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        state: Some(p.state.as_str().into()),
        ..Default::default()
    })
}
