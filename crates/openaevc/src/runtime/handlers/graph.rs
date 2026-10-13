//! Work units and the Active Change Graph (spec/active-change-graph.md).

use std::collections::BTreeMap;

use crate::core::{graph, names, IdGeneratorExt};
use crate::protocol::{
    err, ActiveEdge, ActiveEdgeKind, AnyId, ChangePack, CommandResult, ErrorCode, ExecutionId,
    Metadata, NodeRef, PackId, PackState, ProtocolError, WorkUnit, WorkUnitId, WorkUnitState,
};
use serde_json::{json, Value};

use super::packs;
use crate::runtime::records;
use crate::runtime::tx::Tx;
use crate::runtime::{authz, Ctx, Result};

pub(crate) fn edges(tx: &Tx<'_>) -> Result<Vec<ActiveEdge>> {
    Ok(tx
        .peek(records::EDGES, &tx.ns.to_string())?
        .unwrap_or_default())
}

/// Normalized "x waits on y" edges (DEPENDS_ON x->y, BLOCKS y->x).
pub(crate) fn wait_edges(all: &[ActiveEdge]) -> Vec<(NodeRef, NodeRef)> {
    all.iter()
        .filter_map(|e| match e.kind {
            ActiveEdgeKind::DependsOn => Some((e.from.clone(), e.to.clone())),
            ActiveEdgeKind::Blocks => Some((e.to.clone(), e.from.clone())),
            _ => None,
        })
        .collect()
}

/// Pack that owns a dependency node (the pack itself, or a work unit's pack).
pub(crate) fn owner(tx: &Tx<'_>, n: &NodeRef) -> Result<Option<PackId>> {
    Ok(match n {
        NodeRef::Id(AnyId::ChangePackId(id)) => Some(PackId::Change(*id)),
        NodeRef::Id(AnyId::RevisionPackId(id)) => Some(PackId::Revision(*id)),
        NodeRef::Id(AnyId::WorkUnitId(w)) => {
            tx.peek(records::WORK_UNIT, &records::key(&tx.ns, w))?
        }
        _ => None,
    })
}

fn exists(tx: &Tx<'_>, n: &NodeRef) -> Result<bool> {
    Ok(match owner(tx, n)? {
        Some(p) => tx
            .peek::<ChangePack>(records::PACK, &records::key(&tx.ns, p))?
            .is_some(),
        None => false,
    })
}

fn add_edge(tx: &mut Tx<'_>, edge: ActiveEdge) -> Result<()> {
    if !edge.kind.is_dependency() {
        return Err(err::invalid(format!(
            "{:?} edges are runtime-owned and cannot be added by clients",
            edge.kind
        )));
    }
    for n in [&edge.from, &edge.to] {
        if !exists(tx, n)? {
            return Err(ProtocolError::new(
                ErrorCode::DependencyMissing,
                format!("dependency node {n} not found"),
            )
            .with_object(n));
        }
    }
    let mut all = edges(tx)?;
    if all
        .iter()
        .any(|e| e.from == edge.from && e.to == edge.to && e.kind == edge.kind)
    {
        return Err(err::exists("edge already exists"));
    }
    let new_wait = match edge.kind {
        ActiveEdgeKind::Blocks => (edge.to.clone(), edge.from.clone()),
        _ => (edge.from.clone(), edge.to.clone()),
    };
    if let Some(cycle) = graph::cycle_with_edge(&wait_edges(&all), new_wait) {
        return Err(ProtocolError::new(
            ErrorCode::DependencyCycle,
            "dependency would create a cycle",
        )
        .with_cycle(cycle.iter().map(ToString::to_string).collect()));
    }
    all.push(edge);
    tx.put(records::EDGES, &tx.ns.to_string(), &all)
}

pub(crate) fn add_work_unit(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    pack: PackId,
    expected: u64,
    kind: String,
    spec: Option<Value>,
    depends_on: Vec<NodeRef>,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.mutate", None)?;
    names::validate_namespaced(&kind)?;
    let mut p = packs::load_mutable(tx, pack, expected)?;
    let id: WorkUnitId = tx.rt.ids.next();
    p.work_units.push(WorkUnit {
        id,
        kind: kind.clone(),
        spec,
        state: WorkUnitState::Open,
    });
    tx.put(records::WORK_UNIT, &records::key(&tx.ns, id), &pack)?;
    for target in depends_on {
        add_edge(
            tx,
            ActiveEdge {
                from: id.into(),
                to: target,
                kind: ActiveEdgeKind::DependsOn,
                annotations: Metadata::new(),
            },
        )?;
    }
    packs::save(tx, &mut p, true)?;
    tx.emit(
        "workunit.added",
        json!({"pack": pack, "work_unit": id, "kind": kind, "generation": p.generation}),
        vec![pack.to_string(), id.to_string()],
    );
    Ok(CommandResult {
        id: Some(id.to_string()),
        generation: Some(p.generation),
        ..Default::default()
    })
}

pub(crate) fn update_work_unit(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    pack: PackId,
    expected: u64,
    wu: WorkUnitId,
    spec: Option<Value>,
    state: Option<WorkUnitState>,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.mutate", None)?;
    let mut p = packs::load_mutable(tx, pack, expected)?;
    let active = tx
        .peek::<Option<ExecutionId>>(records::WU_EXECUTION, &records::key(&tx.ns, wu))?
        .flatten();
    let unit = p
        .work_units
        .iter_mut()
        .find(|w| w.id == wu)
        .ok_or_else(|| err::not_found(format!("work unit {wu} not found in {pack}")))?;
    if let Some(s) = spec {
        unit.spec = Some(s);
    }
    if let Some(s) = state {
        if s == WorkUnitState::Completed {
            return Err(err::invalid(
                "work units complete only through their execution",
            ));
        }
        if active.is_some() {
            return Err(err::conflict(format!(
                "work unit {wu} has an active execution"
            )));
        }
        unit.state = s;
    }
    packs::save(tx, &mut p, true)?;
    tx.emit(
        "workunit.updated",
        json!({"pack": pack, "work_unit": wu, "generation": p.generation}),
        vec![pack.to_string(), wu.to_string()],
    );
    Ok(CommandResult {
        id: Some(wu.to_string()),
        generation: Some(p.generation),
        ..Default::default()
    })
}

fn owning_node_check(
    tx: &Tx<'_>,
    pack: PackId,
    kind: ActiveEdgeKind,
    from: &NodeRef,
    to: &NodeRef,
) -> Result<()> {
    let waiting = if kind == ActiveEdgeKind::Blocks {
        to
    } else {
        from
    };
    if owner(tx, waiting)? != Some(pack) {
        return Err(err::invalid(format!(
            "the waiting node {waiting} must belong to pack {pack}"
        )));
    }
    Ok(())
}

pub(crate) fn add_dependency(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    pack: PackId,
    expected: u64,
    from: NodeRef,
    to: NodeRef,
    kind: ActiveEdgeKind,
    annotations: Metadata,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.mutate", None)?;
    names::validate_keys(&annotations)?;
    let mut p = packs::load_mutable(tx, pack, expected)?;
    if !kind.is_dependency() {
        return Err(err::invalid(format!("{kind:?} edges are runtime-owned")));
    }
    owning_node_check(tx, pack, kind, &from, &to)?;
    add_edge(
        tx,
        ActiveEdge {
            from: from.clone(),
            to: to.clone(),
            kind,
            annotations,
        },
    )?;
    packs::save(tx, &mut p, true)?;
    tx.emit(
        "dependency.added",
        json!({"from": from, "to": to, "kind": kind, "pack": pack, "generation": p.generation}),
        vec![from.to_string(), to.to_string(), pack.to_string()],
    );
    Ok(CommandResult {
        generation: Some(p.generation),
        ..Default::default()
    })
}

pub(crate) fn remove_dependency(
    tx: &mut Tx<'_>,
    ctx: &Ctx,
    pack: PackId,
    expected: u64,
    from: NodeRef,
    to: NodeRef,
    kind: ActiveEdgeKind,
) -> Result<CommandResult> {
    authz(tx, ctx, "changepack.mutate", None)?;
    let mut p = packs::load_mutable(tx, pack, expected)?;
    owning_node_check(tx, pack, kind, &from, &to)?;
    let mut all = edges(tx)?;
    let before = all.len();
    all.retain(|e| !(e.from == from && e.to == to && e.kind == kind));
    if all.len() == before {
        return Err(err::not_found("dependency edge not found"));
    }
    tx.put(records::EDGES, &tx.ns.to_string(), &all)?;
    packs::save(tx, &mut p, true)?;
    tx.emit(
        "dependency.removed",
        json!({"from": from, "to": to, "kind": kind, "pack": pack, "generation": p.generation}),
        vec![from.to_string(), to.to_string(), pack.to_string()],
    );
    Ok(CommandResult {
        generation: Some(p.generation),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------------------------
// Readiness

/// Why a node is not yet satisfied, or `None` when it is.
fn unsatisfied(
    tx: &Tx<'_>,
    packs: &BTreeMap<PackId, ChangePack>,
    n: &NodeRef,
) -> Result<Option<String>> {
    let Some(pid) = owner(tx, n)? else {
        return Ok(Some("unknown node".into()));
    };
    let Some(p) = packs.get(&pid) else {
        return Ok(Some("unknown pack".into()));
    };
    Ok(match n {
        NodeRef::Id(AnyId::WorkUnitId(w)) => {
            match p.work_units.iter().find(|u| &u.id == w).map(|u| u.state) {
                Some(WorkUnitState::Completed) => None,
                Some(s) => Some(format!("work unit is {s:?}").to_uppercase()),
                None => Some("work unit missing".into()),
            }
        }
        _ => match p.state {
            PackState::Sealed | PackState::Qualified | PackState::Promoted => None,
            s => Some(format!("pack is {}", s.as_str())),
        },
    })
}

pub(crate) fn all_packs(tx: &Tx<'_>) -> Result<BTreeMap<PackId, ChangePack>> {
    Ok(tx
        .peek_list::<ChangePack>(records::PACK, &records::prefix(&tx.ns))?
        .into_iter()
        .map(|(_, p)| (p.id, p))
        .collect())
}

/// Ready (`true`) or blocked (`false`) open work units, optionally restricted to one pack.
pub(crate) fn work_status(tx: &Tx<'_>, only: Option<PackId>, ready: bool) -> Result<Vec<Value>> {
    let packs = all_packs(tx)?;
    let waits = wait_edges(&edges(tx)?);
    let mut out = Vec::new();
    for p in packs.values().filter(|p| only.is_none_or(|o| o == p.id)) {
        for w in p
            .work_units
            .iter()
            .filter(|w| w.state == WorkUnitState::Open)
        {
            let wn = NodeRef::from(w.id);
            let pn = NodeRef::from(p.id);
            let mut waiting = Vec::new();
            for (x, y) in waits.iter().filter(|(x, _)| *x == wn || *x == pn) {
                if let Some(reason) = unsatisfied(tx, &packs, y)? {
                    waiting.push(json!({"node": y, "via": x, "reason": reason}));
                }
            }
            let executing = tx
                .peek::<Option<ExecutionId>>(records::WU_EXECUTION, &records::key(&tx.ns, w.id))?
                .flatten();
            if p.state != PackState::Open {
                waiting.push(json!({"node": p.id, "via": w.id, "reason": format!("pack is {}", p.state.as_str())}));
            }
            let is_ready = waiting.is_empty() && executing.is_none();
            if ready && is_ready {
                out.push(json!({"work_unit": w.id, "pack": p.id, "kind": w.kind, "generation": p.generation}));
            } else if !ready && !waiting.is_empty() {
                out.push(json!({"work_unit": w.id, "pack": p.id, "waiting_on": waiting}));
            }
        }
    }
    Ok(out)
}
