//! Baselines and accepted composition (spec/baseline.md, spec/composition.md).

use std::collections::BTreeMap;

use openaevc_composition::{compose, Composition, MemberInfo};
use openaevc_core::{names, IdGeneratorExt};
use openaevc_extension_contract::wire::{ComposeMember, ComposeOutput, Operation};
use openaevc_protocol::{
    err, Baseline, BaselineId, Candidate, CommandResult, CompositionEdge, DecisionOutcome, Digest,
    ErrorCode, FactValue, Facts, Metadata, ObjectKind, PolicyDocument, PromotedPack, ProtocolError,
};
use serde_json::json;

use crate::records;
use crate::tx::Tx;
use crate::{authz, ext, Ctx, Result};

/// Digests in the closure of `root` that are not present (and valid) in the Namespace.
pub(crate) fn missing_closure(tx: &Tx<'_>, root: Digest) -> Result<Vec<Digest>> {
    let missing = std::cell::RefCell::new(Vec::new());
    openaevc_composition::closure(&[root], |d| match tx.load_object(d)? {
        Some(o) => o.references(),
        None => {
            missing.borrow_mut().push(*d);
            Ok(vec![])
        }
    })?;
    Ok(missing.into_inner())
}

/// Loads member PromotedPacks (visible in the Namespace). With `local`, each member must have
/// been promoted in this Namespace: an imported `promoted_pack` is inert data that can be
/// validated but never becomes accepted state here (AEVC-XCH-0003, AEVC-BSL-0002).
pub(crate) fn load_members(
    tx: &Tx<'_>,
    members: &[Digest],
    local: bool,
) -> Result<Vec<(MemberInfo, PromotedPack)>> {
    let mut out = Vec::new();
    for d in members {
        let o = tx
            .load_object(d)?
            .ok_or_else(|| err::not_found(format!("member {d} not found")).with_object(d))?;
        if o.kind() != ObjectKind::PromotedPack {
            return Err(err::invalid(format!(
                "member {d} is a {}, not a promoted pack",
                o.kind().as_str()
            ))
            .with_object(d));
        }
        let p: PromotedPack = o.body()?;
        if local {
            let promoted_here = tx
                .peek::<openaevc_protocol::ChangePack>(
                    records::PACK,
                    &records::key(&tx.ns, p.pack),
                )?
                .and_then(|c| c.promotion)
                .is_some_and(|i| i.promoted_pack == *d);
            if !promoted_here {
                return Err(
                    err::invalid(format!("member {d} was not promoted in this namespace"))
                        .with_object(d),
                );
            }
        }
        out.push((
            MemberInfo {
                digest: *d,
                dependencies: p.dependencies.clone(),
                conflicts_with: p.conflicts_with.clone(),
                revision: p.revision.clone(),
            },
            p,
        ));
    }
    Ok(out)
}

/// Outcome of the extension composition validators.
pub(crate) struct Validation {
    pub facts: Facts,
    pub validators: BTreeMap<String, String>,
    pub conflicts: Vec<String>,
}

/// Runs the composition validators of every registered extension used by the members.
/// Validators of extensions not registered here are reported as `skipped`.
pub(crate) fn run_validators(
    tx: &Tx<'_>,
    members: &[(MemberInfo, PromotedPack)],
    edges: &[CompositionEdge],
) -> Result<Validation> {
    let mut v = Validation {
        facts: Facts::new(),
        validators: BTreeMap::new(),
        conflicts: vec![],
    };
    let mut used: BTreeMap<String, ()> = BTreeMap::new();
    for (_, p) in members {
        for x in &p.extensions {
            used.insert(x.id.clone(), ());
        }
    }
    let active = ext::active_extensions(tx)?;
    let mut compose_members: Option<Vec<ComposeMember>> = None;
    for id in used.keys() {
        let Some(rec) = active.iter().find(|r| &r.manifest.id == id) else {
            v.validators.insert(format!("{id}/*"), "skipped".into());
            continue;
        };
        for validator in &rec.manifest.composition_validators {
            if compose_members.is_none() {
                let mut list = Vec::new();
                for (m, p) in members {
                    let (_, c): (_, Candidate) =
                        tx.require_object(&p.candidate, ObjectKind::Candidate)?;
                    list.push(ComposeMember {
                        digest: m.digest,
                        pack: p.pack,
                        effects: c.effects,
                    });
                }
                compose_members = Some(list);
            }
            let op = Operation::Compose {
                validator: validator.clone(),
                config: None,
                members: compose_members.clone().unwrap_or_default(),
                edges: edges.to_vec(),
            };
            let (out, collected, _) = ext::invoke(tx, rec, op, None, &[], &[])?;
            let out: ComposeOutput = ext::decode(rec, out)?;
            ext::merge_facts(&mut v.facts, out.facts)?;
            ext::merge_facts(&mut v.facts, collected.facts)?;
            v.validators.insert(
                validator.clone(),
                if out.valid { "passed" } else { "failed" }.into(),
            );
            v.conflicts.extend(
                out.conflicts
                    .into_iter()
                    .map(|c| format!("{validator}: {} vs {}: {}", c.a, c.b, c.reason)),
            );
        }
    }
    Ok(v)
}

pub(crate) fn composition_facts(c: &Composition, v: &Validation) -> Facts {
    let mut f = v.facts.clone();
    f.insert(
        "composition.members".into(),
        FactValue::Int(c.members.len() as i64),
    );
    f.insert(
        "composition.edges".into(),
        FactValue::Int(c.edges.len() as i64),
    );
    f.insert(
        "composition.heads".into(),
        FactValue::Int(c.heads.len() as i64),
    );
    f
}

pub(crate) fn create(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    members: Vec<Digest>,
    edges: Vec<CompositionEdge>,
    policies: Vec<Digest>,
    metadata: Metadata,
) -> Result<CommandResult> {
    authz(tx, ctx, "baseline.create", None)?;
    names::validate_keys(&metadata)?;
    let infos = load_members(tx, &members, true)?;
    let comp = compose(
        &infos.iter().map(|(m, _)| m.clone()).collect::<Vec<_>>(),
        &edges,
    )?;
    let v = run_validators(tx, &infos, &comp.edges)?;
    if !v.conflicts.is_empty() {
        return Err(ProtocolError::new(
            ErrorCode::CompositionInvalid,
            format!("composition validators failed: {}", v.conflicts.join("; ")),
        ));
    }
    let facts = composition_facts(&comp, &v);
    let mut docs = Vec::new();
    for d in &policies {
        let doc = super::namespace::registered_policy(tx, d)?;
        docs.push((*d, doc));
    }
    let refs: Vec<(Digest, &PolicyDocument)> = docs.iter().map(|(d, doc)| (*d, doc)).collect();
    let (outcome, rules) = openaevc_policy::evaluate(&refs, &facts);
    if outcome == DecisionOutcome::Deny {
        let failed: Vec<String> = rules
            .iter()
            .filter(|r| !r.passed)
            .map(|r| r.rule.clone())
            .collect();
        return Err(ProtocolError::new(
            ErrorCode::PolicyDenied,
            format!("composition policy rules failed: {}", failed.join(", ")),
        ));
    }
    let id: BaselineId = tx.rt.ids.next();
    let mut policies = policies;
    policies.sort();
    policies.dedup();
    let baseline = Baseline {
        id,
        members: comp.members.clone(),
        edges: comp.edges.clone(),
        heads: comp.heads.clone(),
        policies,
        facts,
        graph_digest: comp.graph_digest,
        metadata,
    };
    let obj = tx.object(ObjectKind::Baseline, Some(id.to_string()), &baseline, false)?;
    tx.put(records::BASELINE, &records::key(&tx.ns, id), &obj.digest())?;
    tx.emit(
        "baseline.created",
        json!({"baseline": id, "digest": obj.digest(), "graph_digest": comp.graph_digest, "members": comp.members.len()}),
        vec![id.to_string(), obj.digest().to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        digest: Some(obj.digest()),
        ..Default::default()
    })
}

/// Independently re-validates a Baseline object from immutable objects (read-only).
pub(crate) fn validate(tx: &Tx<'_>, digest: Digest) -> Result<serde_json::Value> {
    let (_, b): (_, Baseline) = tx.require_object(&digest, ObjectKind::Baseline)?;
    let mut problems = Vec::new();
    let mut validators = BTreeMap::new();
    let mut graph = None;
    let missing = missing_closure(tx, digest)?;
    if !missing.is_empty() {
        problems.push(format!(
            "closure is incomplete: {} object(s) missing, first {}",
            missing.len(),
            missing[0]
        ));
    }
    match load_members(tx, &b.members, false) {
        Err(e) => problems.push(e.message),
        Ok(infos) => {
            let caller_edges: Vec<CompositionEdge> = b
                .edges
                .iter()
                .filter(|e| e.relation.is_none())
                .cloned()
                .collect();
            match compose(
                &infos.iter().map(|(m, _)| m.clone()).collect::<Vec<_>>(),
                &caller_edges,
            ) {
                Err(e) => problems.push(e.message),
                Ok(c) => {
                    if c.members != b.members
                        || c.edges != b.edges
                        || c.heads != b.heads
                        || c.graph_digest != b.graph_digest
                    {
                        problems.push(
                            "stored graph does not match the recomputed canonical graph".into(),
                        );
                    }
                    graph = Some(c.graph_digest);
                    match run_validators(tx, &infos, &c.edges) {
                        Ok(v) => {
                            validators = v.validators;
                            problems.extend(v.conflicts);
                        }
                        Err(e) => problems.push(e.message),
                    }
                }
            }
        }
    }
    Ok(
        json!({"digest": digest, "valid": problems.is_empty(), "graph_digest": graph, "problems": problems, "validators": validators}),
    )
}

pub(crate) fn digest_of_id(tx: &Tx<'_>, id: BaselineId) -> Result<Digest> {
    tx.peek::<Digest>(records::BASELINE, &records::key(&tx.ns, id))?
        .ok_or_else(|| err::not_found(format!("baseline {id} not found")).with_object(id))
}
