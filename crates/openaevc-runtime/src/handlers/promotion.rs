//! Promotion (spec/promotion.md): the atomic transition from qualified mutable work to an
//! immutable PromotedPack. Every precondition is re-checked inside the same transaction that
//! writes the PromotedPack, the PromotionRecord, the state change, the events and the receipt, so
//! either all of it becomes visible or none of it does.

use std::collections::BTreeSet;

use openaevc_core::IdGeneratorExt;
use openaevc_protocol::{
    err, ChangePack, CommandResult, DecisionOutcome, Digest, ErrorCode, ExtensionManifest,
    ObjectKind, PackId, PackState, PromotedPack, PromotionId, PromotionInfo, PromotionRecord,
    ProtocolError,
};
use openaevc_verification::{self as verification, Subject};
use serde_json::json;

use super::{evidence, packs};
use crate::records;
use crate::tx::Tx;
use crate::{authz, Ctx, Result};

/// PromotedPack digests of the packs `p` depends on (all must already be promoted).
fn dependencies(tx: &mut Tx<'_>, p: &ChangePack) -> Result<Vec<Digest>> {
    let mine: BTreeSet<String> = std::iter::once(p.id.to_string())
        .chain(p.work_units.iter().map(|w| w.id.to_string()))
        .collect();
    let waits = super::wait_edges(&super::edges(tx)?);
    let mut deps = BTreeSet::new();
    for (from, to) in waits.iter().filter(|(f, _)| mine.contains(&f.to_string())) {
        let Some(owner) = super::owner(tx, to)? else {
            continue;
        };
        if owner == p.id {
            continue;
        }
        let other = packs::load(tx, owner)?;
        let promoted = other
            .promotion
            .as_ref()
            .filter(|_| other.state == PackState::Promoted)
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::DependencyMissing,
                    format!("{from} depends on {to}, whose pack {owner} is not promoted"),
                )
                .with_object(owner)
            })?;
        deps.insert(promoted.promoted_pack);
    }
    Ok(deps.into_iter().collect())
}

pub(crate) fn promote(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    id: PackId,
    generation: u64,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.promote", None)?;
    let mut p = packs::load(tx, id)?;
    match p.state {
        PackState::Qualified => {}
        PackState::Open | PackState::Sealed => {
            return Err(ProtocolError::new(
                ErrorCode::NotQualified,
                format!("pack {id} is {} and not qualified", p.state.as_str()),
            )
            .with_object(id));
        }
        _ => return Err(packs::state_error(&p, "promote")),
    }
    packs::check_generation(&p, generation)?;
    let sealed = p
        .sealed
        .clone()
        .ok_or_else(|| err::internal("qualified pack without seal"))?;
    let q = p
        .qualification
        .clone()
        .ok_or_else(|| err::internal("qualified pack without qualification"))?;
    if q.generation != sealed.generation
        || q.candidate != sealed.candidate
        || sealed.generation != generation
    {
        return Err(ProtocolError::new(
            ErrorCode::NotQualified,
            "qualification does not match the sealed candidate",
        )
        .with_object(id));
    }
    let s = Subject {
        generation,
        candidate: sealed.candidate,
    };
    let candidate = evidence::candidate(tx, &s)?;
    if !candidate.effects.iter().all(|e| {
        openaevc_execution::provenance_complete(&e.provenance)
            && e.provenance.generation == generation
    }) {
        return Err(ProtocolError::new(
            ErrorCode::NotQualified,
            "candidate contains effects without complete provenance for this generation",
        ));
    }
    // Mandatory and pack policies must still allow, over the current facts.
    let mut res = evidence::results(tx, id)?;
    let (decision, outcome) = evidence::decide(tx, &p, &s, &mut res)?;
    if outcome != DecisionOutcome::Allow {
        return Err(ProtocolError::new(
            ErrorCode::PolicyDenied,
            "promotion gates no longer allow this candidate",
        )
        .with_object(decision));
    }
    tx.put(records::PACK_RESULTS, &records::key(&tx.ns, id), &res)?;
    let inputs = verification::inputs(&res, &s);
    for d in inputs
        .verifications
        .iter()
        .chain(&inputs.evaluations)
        .chain(&inputs.evidence)
    {
        tx.load_object(d)?.ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::EvidenceInvalid,
                format!("qualification input {d} is missing"),
            )
            .with_object(d)
        })?;
    }
    let summary = openaevc_execution::summarize(&candidate.effects);
    for x in &summary.extensions {
        tx.require_object::<ExtensionManifest>(&x.manifest_digest, ObjectKind::ExtensionManifest)
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::ExtensionIncompatible,
                    format!("extension manifest {} is not resolvable", x.manifest_digest),
                )
            })?;
    }
    let dependencies = dependencies(tx, &p)?;
    let record = PromotionRecord {
        id: tx.rt.ids.next::<PromotionId>(),
        pack: id,
        generation,
        candidate: s.candidate,
        policy_decision: decision,
        promoted_by: ctx.principal,
        promoted_at: tx.now,
        request_id: ctx.request_id,
    };
    let record_obj = tx.object(
        ObjectKind::PromotionRecord,
        Some(record.id.to_string()),
        &record,
        false,
    )?;
    let mut decisions = vec![q.decision, decision];
    decisions.dedup();
    let promoted = PromotedPack {
        pack: id,
        generation,
        candidate: s.candidate,
        effects: summary.effects,
        resources: summary.resources,
        dependencies,
        conflicts_with: p.conflicts_with.clone(),
        revision: p.revision.clone(),
        verifications: inputs.verifications,
        evaluations: inputs.evaluations,
        evidence: inputs.evidence,
        policy_decisions: decisions,
        promotion_record: record_obj.digest(),
        extensions: summary.extensions,
        intent: p.intent.clone(),
        metadata: p.metadata.clone(),
        provenance_root: openaevc_execution::provenance_root(&candidate.effects)?,
    };
    let promoted_obj = tx.object(
        ObjectKind::PromotedPack,
        Some(id.to_string()),
        &promoted,
        false,
    )?;
    p.state = PackState::Promoted;
    p.promotion = Some(PromotionInfo {
        promoted_pack: promoted_obj.digest(),
        promotion_record: record_obj.digest(),
    });
    packs::save(tx, &mut p, false)?;
    tx.emit(
        "changepack.promoted",
        json!({"pack": id, "generation": generation, "promoted_pack": promoted_obj.digest(), "promotion_record": record_obj.digest(), "revision": p.revision}),
        vec![id.to_string(), promoted_obj.digest().to_string(), record_obj.digest().to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        digest: Some(promoted_obj.digest()),
        digests: vec![record_obj.digest()],
        generation: Some(generation),
        state: Some("PROMOTED".into()),
        ..Default::default()
    })
}
