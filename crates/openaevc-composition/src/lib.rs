//! Baseline composition (spec/baseline.md, spec/composition.md).
//!
//! A Baseline commits to a canonical graph: sorted member PromotedPack digests plus a sorted edge
//! list made of edges derived from the members (dependencies → `REQUIRES`, revision relations →
//! `REVISION_RELATION`) and caller-supplied ordering edges (`REQUIRES`, `ORDERS_AFTER`). The
//! graph digest is SHA-256 of `canonical({members, edges})`.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use openaevc_protocol::{
    CompositionEdge, CompositionEdgeKind, Digest, ErrorCode, ProtocolError, RevisionInfo,
    RevisionRelation,
};
use serde::Serialize;

/// Composition-relevant facts of one member PromotedPack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub digest: Digest,
    pub dependencies: Vec<Digest>,
    pub conflicts_with: Vec<Digest>,
    pub revision: Option<RevisionInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composition {
    pub members: Vec<Digest>,
    pub edges: Vec<CompositionEdge>,
    pub heads: Vec<Digest>,
    /// Deterministic topological order (dependencies first).
    pub order: Vec<Digest>,
    pub graph_digest: Digest,
}

fn invalid(msg: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorCode::CompositionInvalid, msg)
}

#[derive(Serialize)]
struct CanonicalGraph<'a> {
    members: &'a [Digest],
    edges: &'a [CompositionEdge],
}

pub fn graph_digest(
    members: &[Digest],
    edges: &[CompositionEdge],
) -> Result<Digest, ProtocolError> {
    openaevc_crypto::digest_of(&CanonicalGraph { members, edges })
}

/// Validates and canonicalizes a composition (core graph rules only; extension validators and
/// policy run separately).
pub fn compose(
    members: &[MemberInfo],
    caller_edges: &[CompositionEdge],
) -> Result<Composition, ProtocolError> {
    if members.is_empty() {
        return Err(invalid("a Baseline needs at least one member"));
    }
    let mut set = BTreeSet::new();
    for m in members {
        if !set.insert(m.digest) {
            return Err(
                invalid(format!("member {} is listed twice", m.digest)).with_object(m.digest)
            );
        }
    }
    let mut edges: BTreeSet<CompositionEdge> = BTreeSet::new();
    let mut superseded_by: BTreeMap<Digest, Digest> = BTreeMap::new();
    for m in members {
        for d in &m.dependencies {
            if !set.contains(d) {
                return Err(ProtocolError::new(
                    ErrorCode::DependencyMissing,
                    format!("member {} requires {d}, which is not a member", m.digest),
                )
                .with_object(d));
            }
            edges.insert(CompositionEdge {
                from: m.digest,
                to: *d,
                kind: CompositionEdgeKind::Requires,
                relation: None,
            });
        }
        if let Some(c) = m.conflicts_with.iter().find(|c| set.contains(c)) {
            return Err(invalid(format!(
                "members {} and {c} are declared conflicting",
                m.digest
            ))
            .with_object(c));
        }
        if let Some(rev) = &m.revision {
            for t in &rev.targets {
                let present = set.contains(t);
                if !present && rev.relation != RevisionRelation::Supersedes {
                    return Err(invalid(format!(
                        "revision {} {:?} target {t}, which is not a member",
                        m.digest, rev.relation
                    ))
                    .with_object(t));
                }
                if rev.relation == RevisionRelation::Supersedes {
                    if let Some(other) = superseded_by.insert(*t, m.digest) {
                        return Err(invalid(format!(
                            "ambiguous lineage: {t} is superseded by both {other} and {}",
                            m.digest
                        ))
                        .with_object(t));
                    }
                }
                if present {
                    edges.insert(CompositionEdge {
                        from: m.digest,
                        to: *t,
                        kind: CompositionEdgeKind::RevisionRelation,
                        relation: Some(rev.relation),
                    });
                }
            }
        }
    }
    for e in caller_edges {
        if !matches!(
            e.kind,
            CompositionEdgeKind::Requires | CompositionEdgeKind::OrdersAfter
        ) || e.relation.is_some()
        {
            return Err(invalid(format!(
                "callers may only add REQUIRES or ORDERS_AFTER edges, not {:?}",
                e.kind
            )));
        }
        if !set.contains(&e.from) || !set.contains(&e.to) {
            return Err(invalid("composition edges must connect members"));
        }
        edges.insert(e.clone());
    }
    let members: Vec<Digest> = set.into_iter().collect();
    let edges: Vec<CompositionEdge> = edges.into_iter().collect();
    let pairs: Vec<(Digest, Digest)> = edges.iter().map(|e| (e.from, e.to)).collect();
    let order = openaevc_core::graph::topo_order(&members, &pairs).map_err(|cycle| {
        ProtocolError::new(
            ErrorCode::DependencyCycle,
            "composition graph contains a cycle",
        )
        .with_cycle(cycle.iter().map(ToString::to_string).collect())
    })?;
    let heads = members
        .iter()
        .filter(|m| !superseded_by.contains_key(m))
        .copied()
        .collect();
    let graph_digest = graph_digest(&members, &edges)?;
    Ok(Composition {
        members,
        edges,
        heads,
        order,
        graph_digest,
    })
}

/// Transitive closure of object references from `roots` (roots included), sorted.
pub fn closure(
    roots: &[Digest],
    refs: impl Fn(&Digest) -> Result<Vec<Digest>, ProtocolError>,
) -> Result<Vec<Digest>, ProtocolError> {
    let mut seen = BTreeSet::new();
    let mut queue: VecDeque<Digest> = roots.iter().copied().collect();
    while let Some(d) = queue.pop_front() {
        if seen.insert(d) {
            queue.extend(refs(&d)?);
        }
    }
    Ok(seen.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u8) -> Digest {
        Digest::sha256([n; 32])
    }

    fn m(n: u8) -> MemberInfo {
        MemberInfo {
            digest: d(n),
            dependencies: vec![],
            conflicts_with: vec![],
            revision: None,
        }
    }

    fn edge(from: u8, to: u8, kind: CompositionEdgeKind) -> CompositionEdge {
        CompositionEdge {
            from: d(from),
            to: d(to),
            kind,
            relation: None,
        }
    }

    #[test]
    fn canonical_graph_is_order_independent() {
        let mut a = m(1);
        a.dependencies = vec![d(2)];
        let x = compose(
            &[a.clone(), m(2), m(3)],
            &[edge(3, 2, CompositionEdgeKind::OrdersAfter)],
        )
        .unwrap();
        let y = compose(
            &[m(3), m(2), a],
            &[edge(3, 2, CompositionEdgeKind::OrdersAfter)],
        )
        .unwrap();
        assert_eq!(x, y);
        assert_eq!(
            x.members,
            vec![d(1), d(2), d(3)]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert!(x.edges.contains(&edge(1, 2, CompositionEdgeKind::Requires)));
        assert_eq!(x.heads.len(), 3);
    }

    #[test]
    fn missing_dependency_and_duplicates_rejected() {
        let mut a = m(1);
        a.dependencies = vec![d(9)];
        assert_eq!(
            compose(&[a], &[]).unwrap_err().code,
            ErrorCode::DependencyMissing
        );
        assert_eq!(
            compose(&[m(1), m(1)], &[]).unwrap_err().code,
            ErrorCode::CompositionInvalid
        );
        assert_eq!(
            compose(&[], &[]).unwrap_err().code,
            ErrorCode::CompositionInvalid
        );
    }

    #[test]
    fn declared_conflicts_cannot_both_be_members() {
        let mut a = m(1);
        a.conflicts_with = vec![d(2)];
        assert_eq!(
            compose(&[a.clone(), m(2)], &[]).unwrap_err().code,
            ErrorCode::CompositionInvalid
        );
        assert!(compose(&[a, m(3)], &[]).is_ok());
    }

    #[test]
    fn caller_edges_must_be_ordering_between_members() {
        assert_eq!(
            compose(
                &[m(1), m(2)],
                &[edge(1, 9, CompositionEdgeKind::OrdersAfter)]
            )
            .unwrap_err()
            .code,
            ErrorCode::CompositionInvalid
        );
        assert_eq!(
            compose(
                &[m(1), m(2)],
                &[edge(1, 2, CompositionEdgeKind::ConflictsWith)]
            )
            .unwrap_err()
            .code,
            ErrorCode::CompositionInvalid
        );
        assert_eq!(
            compose(
                &[m(1), m(2)],
                &[edge(1, 2, CompositionEdgeKind::RevisionRelation)]
            )
            .unwrap_err()
            .code,
            ErrorCode::CompositionInvalid
        );
    }

    #[test]
    fn cycles_are_reported() {
        let e = compose(
            &[m(1), m(2)],
            &[
                edge(1, 2, CompositionEdgeKind::OrdersAfter),
                edge(2, 1, CompositionEdgeKind::OrdersAfter),
            ],
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::DependencyCycle);
        assert!(e.cycle.len() >= 3);
    }

    #[test]
    fn revision_lineage_rules() {
        let rev = |n: u8, rel: RevisionRelation, t: u8| MemberInfo {
            revision: Some(RevisionInfo {
                relation: rel,
                targets: vec![d(t)],
            }),
            ..m(n)
        };
        // REVERTS/AMENDS require their target.
        assert_eq!(
            compose(&[rev(2, RevisionRelation::Reverts, 1)], &[])
                .unwrap_err()
                .code,
            ErrorCode::CompositionInvalid
        );
        let c = compose(&[m(1), rev(2, RevisionRelation::Reverts, 1)], &[]).unwrap();
        assert!(c
            .edges
            .iter()
            .any(|e| e.kind == CompositionEdgeKind::RevisionRelation
                && e.relation == Some(RevisionRelation::Reverts)));
        assert_eq!(c.heads.len(), 2);
        // SUPERSEDES may omit its target; when present the target is no longer a head.
        assert!(compose(&[rev(2, RevisionRelation::Supersedes, 1)], &[]).is_ok());
        let c = compose(&[m(1), rev(2, RevisionRelation::Supersedes, 1)], &[]).unwrap();
        assert_eq!(c.heads, vec![d(2)]);
        // Two members superseding the same target are ambiguous heads.
        let e = compose(
            &[
                m(1),
                rev(2, RevisionRelation::Supersedes, 1),
                rev(3, RevisionRelation::Supersedes, 1),
            ],
            &[],
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::CompositionInvalid);
    }

    #[test]
    fn closure_walks_references() {
        let refs = |x: &Digest| -> Result<Vec<Digest>, ProtocolError> {
            Ok(match x.as_bytes()[0] {
                1 => vec![d(2), d(3)],
                2 => vec![d(4)],
                3 => vec![d(4)],
                _ => vec![],
            })
        };
        assert_eq!(
            closure(&[d(1)], refs).unwrap(),
            vec![d(1), d(2), d(3), d(4)]
        );
        assert_eq!(closure(&[d(3)], refs).unwrap(), vec![d(3), d(4)]);
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn graph_digest_is_permutation_invariant(order in Just((1u8..6).collect::<Vec<_>>()).prop_shuffle()) {
            let members: Vec<MemberInfo> = order.iter().map(|n| m(*n)).collect();
            let sorted: Vec<MemberInfo> = (1u8..6).map(m).collect();
            prop_assert_eq!(compose(&members, &[]).unwrap().graph_digest, compose(&sorted, &[]).unwrap().graph_digest);
        }
    }
}
