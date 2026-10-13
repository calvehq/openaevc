//! Evidence, verification, evaluation and qualification (spec/evidence.md, verification.md,
//! evaluation.md, policy.md).

use std::collections::BTreeSet;

use crate::core::{names, IdGeneratorExt};
use crate::extension::wire::{EvaluateOutput, EvidenceInput, Operation, VerifyOutput};
use crate::protocol::{
    err, Blob, Candidate, ChangePack, CommandResult, DecisionOutcome, Digest, ErrorCode,
    EvaluationResult, Evidence, ExtensionRef, Facts, NodeRef, ObjectKind, PackId, PackState,
    PolicyDecision, PolicyDocument, ProtocolError, QualificationInfo, ResourceRef, RunProvenance,
    SchemaRef, VerificationResult,
};
use crate::verification::{self as verification, PackResults, ResultRef, Subject};
use serde_json::{json, Value};

use super::packs;
use crate::runtime::records::{self, ExtensionRecord};
use crate::runtime::tx::Tx;
use crate::runtime::{authz, ext, Ctx, Result};

fn results_key(tx: &Tx<'_>, pack: PackId) -> String {
    records::key(&tx.ns, pack)
}

pub(crate) fn results(tx: &mut Tx<'_>, pack: PackId) -> Result<PackResults> {
    let k = results_key(tx, pack);
    Ok(tx.get(records::PACK_RESULTS, &k)?.unwrap_or_default())
}

fn subject_of(p: &ChangePack) -> Result<Subject> {
    let s = p
        .sealed
        .as_ref()
        .ok_or_else(|| err::internal("sealed pack without seal info"))?;
    Ok(Subject {
        generation: s.generation,
        candidate: s.candidate,
    })
}

/// A SEALED or QUALIFIED pack at `generation`, with its sealed subject.
pub(crate) fn load_sealed(
    tx: &mut Tx<'_>,
    pack: PackId,
    generation: u64,
) -> Result<(ChangePack, Subject)> {
    let p = packs::load(tx, pack)?;
    if !matches!(p.state, PackState::Sealed | PackState::Qualified) {
        return Err(match p.state {
            PackState::Open => ProtocolError::new(
                ErrorCode::InvalidTransition,
                format!("pack {pack} must be sealed first"),
            )
            .with_object(pack),
            _ => packs::state_error(&p, "verify"),
        });
    }
    packs::check_generation(&p, generation)?;
    let s = subject_of(&p)?;
    Ok((p, s))
}

pub(crate) fn candidate(tx: &Tx<'_>, s: &Subject) -> Result<Candidate> {
    Ok(tx
        .require_object::<Candidate>(&s.candidate, ObjectKind::Candidate)?
        .1)
}

fn scope_of(c: &Candidate) -> Vec<ResourceRef> {
    let set: BTreeSet<ResourceRef> = c.effects.iter().map(|e| e.target.clone()).collect();
    set.into_iter().collect()
}

/// New results change the facts, so a QUALIFIED pack falls back to SEALED until refreshed.
fn disqualify(tx: &mut Tx<'_>, p: &mut ChangePack) -> Result<()> {
    if p.state == PackState::Qualified {
        p.state = PackState::Sealed;
        p.qualification = None;
        packs::save(tx, p, false)?;
        tx.emit(
            "changepack.disqualified",
            json!({"pack": p.id, "reason": "new qualification facts"}),
            vec![p.id.to_string()],
        );
    }
    Ok(())
}

fn store_evidence(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    p: &ChangePack,
    s: &Subject,
    kind: &str,
    blob: Blob,
    schema: Option<SchemaRef>,
    sources: Vec<NodeRef>,
    extension: Option<ExtensionRef>,
    res: &mut PackResults,
) -> Result<Digest> {
    names::validate_namespaced(kind)?;
    if blob.media_type.is_empty() {
        return Err(err::invalid("evidence needs a media type"));
    }
    let payload = tx.object(ObjectKind::Blob, None, &blob, false)?;
    let evidence = Evidence {
        id: tx.rt.ids.next(),
        kind: kind.into(),
        producer: ctx.principal,
        pack: p.id,
        generation: s.generation,
        candidate: s.candidate,
        payload: payload.digest(),
        media_type: blob.media_type,
        schema,
        sources,
        extension,
        created_at: tx.now,
    };
    let obj = tx.object(
        ObjectKind::Evidence,
        Some(evidence.id.to_string()),
        &evidence,
        false,
    )?;
    res.evidence.push(ResultRef {
        digest: obj.digest(),
        kind: kind.into(),
        generation: s.generation,
        candidate: s.candidate,
        sequence: tx.first_seq,
        outcome: String::new(),
        facts: Facts::new(),
    });
    tx.emit(
        "evidence.registered",
        json!({"pack": p.id, "evidence": obj.digest(), "kind": kind, "generation": s.generation, "candidate": s.candidate}),
        vec![p.id.to_string(), obj.digest().to_string()],
    );
    Ok(obj.digest())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn register_evidence(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    pack: PackId,
    generation: u64,
    candidate_digest: Digest,
    kind: String,
    payload: Blob,
    schema: Option<SchemaRef>,
    sources: Vec<NodeRef>,
    extension: Option<String>,
) -> Result<CommandResult> {
    authz(tx, ctx, "evidence.append", None)?;
    let mut p = packs::load(tx, pack)?;
    if !matches!(p.state, PackState::Sealed | PackState::Qualified) {
        return Err(ProtocolError::new(
            ErrorCode::EvidenceInvalid,
            "evidence can only bind to a sealed candidate",
        )
        .with_object(pack));
    }
    let s = subject_of(&p)?;
    verification::check_binding(generation, candidate_digest, &s)?;
    for n in &sources {
        if let NodeRef::Digest(d) = n {
            tx.load_object(d)?
                .ok_or_else(|| err::not_found(format!("evidence source {d} not found")))?;
        }
    }
    let ext_ref = match extension {
        Some(id) => {
            let rec: ExtensionRecord =
                tx.require(records::EXTENSION, &records::key(&tx.ns, &id), "extension")?;
            Some(rec.reference())
        }
        None => None,
    };
    let mut res = results(tx, pack)?;
    let d = store_evidence(
        tx, ctx, &p, &s, &kind, payload, schema, sources, ext_ref, &mut res,
    )?;
    tx.put(records::PACK_RESULTS, &results_key(tx, pack), &res)?;
    disqualify(tx, &mut p)?;
    Ok(CommandResult {
        digest: Some(d),
        ..Default::default()
    })
}

fn find_ext(
    tx: &Tx<'_>,
    what: &str,
    kind: &str,
    pick: fn(&ExtensionRecord) -> &Vec<String>,
) -> Result<ExtensionRecord> {
    ext::find(tx, what, kind, |r| pick(r).clone())
}

/// Inputs must have been recorded for this pack (RegisterEvidence, a verifier's attachments,
/// RunVerification, RunEvaluation): an imported object bound to the candidate is inert data
/// (AEVC-XCH-0003) and never stands in for registered evidence.
fn require_recorded(tx: &Tx<'_>, pack: PackId, d: &Digest) -> Result<()> {
    let res: PackResults = tx
        .peek(records::PACK_RESULTS, &results_key(tx, pack))?
        .unwrap_or_default();
    let recorded = res
        .evidence
        .iter()
        .chain(&res.verifications)
        .chain(&res.evaluations)
        .any(|r| r.digest == *d);
    if recorded {
        Ok(())
    } else {
        Err(ProtocolError::new(
            ErrorCode::EvidenceInvalid,
            format!("input {d} was not recorded for pack {pack}"),
        )
        .with_object(d))
    }
}

fn evidence_inputs(
    tx: &Tx<'_>,
    pack: PackId,
    s: &Subject,
    digests: &[Digest],
) -> Result<Vec<EvidenceInput>> {
    let mut out = Vec::new();
    for d in digests {
        require_recorded(tx, pack, d)?;
        let (_, e): (_, Evidence) = tx.require_object(d, ObjectKind::Evidence)?;
        verification::check_binding(e.generation, e.candidate, s)?;
        let (_, blob): (_, Blob) = tx.require_object(&e.payload, ObjectKind::Blob)?;
        out.push(EvidenceInput {
            digest: *d,
            kind: e.kind,
            media_type: blob.media_type,
            data: blob.data,
        });
    }
    Ok(out)
}

pub(crate) fn run_verification(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    pack: PackId,
    generation: u64,
    verifier: String,
    config: Option<Value>,
    evidence: Vec<Digest>,
) -> Result<CommandResult> {
    authz(tx, ctx, "verification.run", None)?;
    let (mut p, s) = load_sealed(tx, pack, generation)?;
    let rec = find_ext(tx, "verifier", &verifier, |r| &r.manifest.verifier_kinds)?;
    let inputs = evidence_inputs(tx, pack, &s, &evidence)?;
    let cand = candidate(tx, &s)?;
    let op = Operation::Verify {
        kind: verifier.clone(),
        config: config.clone(),
        pack,
        generation: s.generation,
        candidate: s.candidate,
        effects: cand.effects.clone(),
        evidence: inputs,
    };
    let (out, collected, ext_ref) = ext::invoke(
        tx,
        &rec,
        op,
        config.as_ref(),
        &scope_of(&cand),
        &cand.effects,
    )?;
    let out: VerifyOutput = ext::decode(&rec, out)?;
    let mut facts = Facts::new();
    ext::merge_facts(&mut facts, out.facts)?;
    ext::merge_facts(&mut facts, collected.facts)?;
    let mut res = results(tx, pack)?;
    let mut evidence_refs = evidence;
    for (kind, media_type, data) in collected.evidence {
        let d = store_evidence(
            tx,
            ctx,
            &p,
            &s,
            &kind,
            Blob { media_type, data },
            None,
            vec![NodeRef::Digest(s.candidate)],
            Some(ext_ref.clone()),
            &mut res,
        )?;
        evidence_refs.push(d);
    }
    let result = VerificationResult {
        id: tx.rt.ids.next(),
        pack,
        generation: s.generation,
        candidate: s.candidate,
        verifier: verifier.clone(),
        extension: Some(ext_ref),
        config,
        status: out.status,
        evidence: evidence_refs,
        findings: out.findings,
        facts: facts.clone(),
        started_at: tx.now,
        finished_at: tx.now,
        provenance: RunProvenance {
            caller: ctx.caller,
            request_id: ctx.request_id,
            runtime_instance: tx.rt.instance,
        },
    };
    let obj = tx.object(
        ObjectKind::VerificationResult,
        Some(result.id.to_string()),
        &result,
        false,
    )?;
    res.verifications.push(ResultRef {
        digest: obj.digest(),
        kind: verifier.clone(),
        generation: s.generation,
        candidate: s.candidate,
        sequence: tx.first_seq,
        outcome: out.status.as_str().into(),
        facts,
    });
    tx.put(records::PACK_RESULTS, &results_key(tx, pack), &res)?;
    super::execution::add_result_edge(
        tx,
        obj.digest(),
        s.candidate,
        crate::protocol::ActiveEdgeKind::Verifies,
    )?;
    tx.emit(
        "verification.completed",
        json!({"pack": pack, "verification": obj.digest(), "verifier": verifier, "status": out.status, "generation": s.generation}),
        vec![pack.to_string(), obj.digest().to_string()],
    );
    disqualify(tx, &mut p)?;
    Ok(CommandResult {
        digest: Some(obj.digest()),
        state: Some(out.status.as_str().into()),
        generation: Some(s.generation),
        ..Default::default()
    })
}

fn check_input(tx: &Tx<'_>, pack: PackId, s: &Subject, d: &Digest) -> Result<()> {
    let o = tx
        .load_object(d)?
        .ok_or_else(|| err::not_found(format!("input {d} not found")).with_object(d))?;
    let (generation, candidate) = match o.kind() {
        ObjectKind::Evidence => {
            let e: Evidence = o.body()?;
            (e.generation, e.candidate)
        }
        ObjectKind::VerificationResult => {
            let v: VerificationResult = o.body()?;
            (v.generation, v.candidate)
        }
        ObjectKind::EvaluationResult => {
            let v: EvaluationResult = o.body()?;
            (v.generation, v.candidate)
        }
        k => {
            return Err(ProtocolError::new(
                ErrorCode::EvidenceInvalid,
                format!("{} cannot be an evaluation input", k.as_str()),
            ))
        }
    };
    verification::check_binding(generation, candidate, s)?;
    require_recorded(tx, pack, d)
}

pub(crate) fn run_evaluation(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    pack: PackId,
    generation: u64,
    evaluator: String,
    config: Option<Value>,
    inputs: Vec<Digest>,
) -> Result<CommandResult> {
    authz(tx, ctx, "evaluation.run", None)?;
    let (mut p, s) = load_sealed(tx, pack, generation)?;
    let rec = find_ext(tx, "evaluator", &evaluator, |r| &r.manifest.evaluator_kinds)?;
    for d in &inputs {
        check_input(tx, pack, &s, d)?;
    }
    let mut res = results(tx, pack)?;
    let cand = candidate(tx, &s)?;
    let op = Operation::Evaluate {
        kind: evaluator.clone(),
        config: config.clone(),
        facts: verification::normalize(&res, &s),
        effects: cand.effects.clone(),
    };
    let (out, collected, ext_ref) = ext::invoke(
        tx,
        &rec,
        op,
        config.as_ref(),
        &scope_of(&cand),
        &cand.effects,
    )?;
    let out: EvaluateOutput = ext::decode(&rec, out)?;
    names::validate_keys(&out.metrics)?;
    let mut facts = Facts::new();
    ext::merge_facts(&mut facts, out.facts)?;
    ext::merge_facts(&mut facts, collected.facts)?;
    let result = EvaluationResult {
        id: tx.rt.ids.next(),
        pack,
        generation: s.generation,
        candidate: s.candidate,
        evaluator: evaluator.clone(),
        extension: Some(ext_ref),
        config,
        verdict: out.verdict,
        metrics: out.metrics,
        facts: facts.clone(),
        inputs,
        started_at: tx.now,
        finished_at: tx.now,
        provenance: RunProvenance {
            caller: ctx.caller,
            request_id: ctx.request_id,
            runtime_instance: tx.rt.instance,
        },
    };
    let obj = tx.object(
        ObjectKind::EvaluationResult,
        Some(result.id.to_string()),
        &result,
        false,
    )?;
    res.evaluations.push(ResultRef {
        digest: obj.digest(),
        kind: evaluator.clone(),
        generation: s.generation,
        candidate: s.candidate,
        sequence: tx.first_seq,
        outcome: out.verdict.as_str().into(),
        facts,
    });
    tx.put(records::PACK_RESULTS, &results_key(tx, pack), &res)?;
    super::execution::add_result_edge(
        tx,
        obj.digest(),
        s.candidate,
        crate::protocol::ActiveEdgeKind::Evaluates,
    )?;
    tx.emit(
        "evaluation.completed",
        json!({"pack": pack, "evaluation": obj.digest(), "evaluator": evaluator, "verdict": out.verdict, "generation": s.generation}),
        vec![pack.to_string(), obj.digest().to_string()],
    );
    disqualify(tx, &mut p)?;
    Ok(CommandResult {
        digest: Some(obj.digest()),
        state: Some(out.verdict.as_str().into()),
        generation: Some(s.generation),
        ..Default::default()
    })
}

/// Policies gating a pack: Namespace mandatory policies first, then the pack's own.
pub(crate) fn gate_policies(
    tx: &mut Tx<'_>,
    p: &ChangePack,
) -> Result<Vec<(Digest, PolicyDocument)>> {
    let ns: crate::protocol::Namespace =
        tx.require(records::NAMESPACE, &tx.ns.to_string(), "namespace")?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for d in ns.mandatory_policies.iter().chain(&p.required_policies) {
        if seen.insert(*d) {
            let (_, doc): (_, PolicyDocument) = tx.require_object(d, ObjectKind::PolicyDocument)?;
            out.push((*d, doc));
        }
    }
    Ok(out)
}

/// Evaluates the gate policies over the current facts and records a PolicyDecision.
pub(crate) fn decide(
    tx: &mut Tx<'_>,
    p: &ChangePack,
    s: &Subject,
    res: &mut PackResults,
) -> Result<(Digest, DecisionOutcome)> {
    let policies = gate_policies(tx, p)?;
    let facts = verification::normalize(res, s);
    let refs: Vec<(Digest, &PolicyDocument)> = policies.iter().map(|(d, doc)| (*d, doc)).collect();
    let (outcome, rules) = crate::policy::evaluate(&refs, &facts);
    let decision = PolicyDecision {
        pack: p.id,
        generation: s.generation,
        candidate: s.candidate,
        policies: policies.iter().map(|(d, _)| *d).collect(),
        facts,
        outcome,
        rules,
        evaluated_at: tx.now,
    };
    let obj = tx.object(ObjectKind::PolicyDecision, None, &decision, false)?;
    let label = match outcome {
        DecisionOutcome::Allow => "ALLOW",
        DecisionOutcome::Deny => "DENY",
    };
    res.decisions.push(ResultRef {
        digest: obj.digest(),
        kind: "policy".into(),
        generation: s.generation,
        candidate: s.candidate,
        sequence: tx.first_seq,
        outcome: label.into(),
        facts: Facts::new(),
    });
    Ok((obj.digest(), outcome))
}

pub(crate) fn refresh_qualification(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    pack: PackId,
    generation: u64,
) -> Result<CommandResult> {
    authz(tx, ctx, "verification.run", None)?;
    let (mut p, s) = load_sealed(tx, pack, generation)?;
    let mut res = results(tx, pack)?;
    let (decision, outcome) = decide(tx, &p, &s, &mut res)?;
    tx.put(records::PACK_RESULTS, &results_key(tx, pack), &res)?;
    tx.emit(
        "qualification.evaluated",
        json!({"pack": pack, "decision": decision, "outcome": outcome, "generation": s.generation}),
        vec![pack.to_string(), decision.to_string()],
    );
    match outcome {
        DecisionOutcome::Allow => {
            p.state = PackState::Qualified;
            p.qualification = Some(QualificationInfo {
                generation: s.generation,
                candidate: s.candidate,
                decision,
            });
            packs::save(tx, &mut p, false)?;
            tx.emit(
                "changepack.qualified",
                json!({"pack": pack, "decision": decision, "generation": s.generation}),
                vec![pack.to_string()],
            );
        }
        DecisionOutcome::Deny => disqualify(tx, &mut p)?,
    }
    Ok(CommandResult {
        digest: Some(decision),
        state: Some(p.state.as_str().into()),
        generation: Some(s.generation),
        ..Default::default()
    })
}
