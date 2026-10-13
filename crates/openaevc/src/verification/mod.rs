//! Evidence, verification and evaluation bookkeeping (spec/evidence.md, verification.md,
//! evaluation.md).
//!
//! Results are bound to one `(generation, candidate)` subject. Only results bound to the pack's
//! current sealed subject contribute facts; everything else is historical. For verifications
//! and evaluations the latest result of each kind wins (a rerun creates a new immutable result).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::protocol::{Digest, ErrorCode, FactValue, Facts, ProtocolError};
use serde::{Deserialize, Serialize};

/// Index entry for an evidence, verification, evaluation or decision object of a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultRef {
    pub digest: Digest,
    pub kind: String,
    pub generation: u64,
    pub candidate: Digest,
    /// Creation order within the pack (namespace event sequence).
    pub sequence: u64,
    /// Status (`PASS`...), verdict (`ALLOW`...) or decision outcome; empty for evidence.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: Facts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackResults {
    pub evidence: Vec<ResultRef>,
    pub verifications: Vec<ResultRef>,
    pub evaluations: Vec<ResultRef>,
    pub decisions: Vec<ResultRef>,
}

/// The sealed generation/candidate results must be bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subject {
    pub generation: u64,
    pub candidate: Digest,
}

pub fn bound(r: &ResultRef, s: &Subject) -> bool {
    r.generation == s.generation && r.candidate == s.candidate
}

/// `EVIDENCE_INVALID` unless `(generation, candidate)` is exactly the subject.
pub fn check_binding(generation: u64, candidate: Digest, s: &Subject) -> Result<(), ProtocolError> {
    if generation != s.generation || candidate != s.candidate {
        return Err(ProtocolError::new(
            ErrorCode::EvidenceInvalid,
            format!("bound to generation {generation} / {candidate}, but the sealed candidate is generation {} / {}", s.generation, s.candidate),
        ));
    }
    Ok(())
}

/// Latest bound result per kind, ordered by kind.
pub fn latest_per_kind<'a>(list: &'a [ResultRef], s: &Subject) -> Vec<&'a ResultRef> {
    let mut best: BTreeMap<&str, &ResultRef> = BTreeMap::new();
    for r in list.iter().filter(|r| bound(r, s)) {
        match best.get(r.kind.as_str()) {
            Some(b) if b.sequence >= r.sequence => {}
            _ => {
                best.insert(&r.kind, r);
            }
        }
    }
    best.into_values().collect()
}

/// Normalized policy facts for the subject.
pub fn normalize(results: &PackResults, s: &Subject) -> Facts {
    let mut f = Facts::new();
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    for e in results.evidence.iter().filter(|e| bound(e, s)) {
        *counts.entry(e.kind.as_str()).or_default() += 1;
    }
    for (k, n) in counts {
        f.insert(crate::policy::evidence_fact(k), FactValue::Int(n));
    }
    for v in latest_per_kind(&results.verifications, s) {
        f.extend(v.facts.clone());
        f.insert(
            crate::policy::verification_fact(&v.kind),
            FactValue::Text(v.outcome.clone()),
        );
    }
    for v in latest_per_kind(&results.evaluations, s) {
        f.extend(v.facts.clone());
        f.insert(
            crate::policy::evaluation_fact(&v.kind),
            FactValue::Text(v.outcome.clone()),
        );
    }
    f
}

/// Result objects a qualification decision rests on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inputs {
    pub verifications: Vec<Digest>,
    pub evaluations: Vec<Digest>,
    pub evidence: Vec<Digest>,
}

pub fn inputs(results: &PackResults, s: &Subject) -> Inputs {
    Inputs {
        verifications: latest_per_kind(&results.verifications, s)
            .into_iter()
            .map(|r| r.digest)
            .collect(),
        evaluations: latest_per_kind(&results.evaluations, s)
            .into_iter()
            .map(|r| r.digest)
            .collect(),
        evidence: results
            .evidence
            .iter()
            .filter(|e| bound(e, s))
            .map(|e| e.digest)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u8) -> Digest {
        Digest::sha256([n; 32])
    }

    fn r(kind: &str, generation: u64, candidate: u8, seq: u64, outcome: &str) -> ResultRef {
        ResultRef {
            digest: d(seq as u8 + 100),
            kind: kind.into(),
            generation,
            candidate: d(candidate),
            sequence: seq,
            outcome: outcome.into(),
            facts: Facts::new(),
        }
    }

    #[test]
    fn binding_requires_exact_generation_and_candidate() {
        let s = Subject {
            generation: 2,
            candidate: d(1),
        };
        assert!(bound(&r("k.v", 2, 1, 1, "PASS"), &s));
        assert!(!bound(&r("k.v", 1, 1, 1, "PASS"), &s));
        assert!(!bound(&r("k.v", 2, 9, 1, "PASS"), &s));
        assert_eq!(
            check_binding(1, d(1), &s).unwrap_err().code,
            ErrorCode::EvidenceInvalid
        );
    }

    #[test]
    fn facts_use_latest_bound_result_per_kind() {
        let s = Subject {
            generation: 2,
            candidate: d(1),
        };
        let mut later = r("kv.expect", 2, 1, 5, "PASS");
        later.facts.insert("kv.count".into(), FactValue::Int(3));
        let results = PackResults {
            evidence: vec![
                r("kv.snapshot", 2, 1, 1, ""),
                r("kv.snapshot", 2, 1, 2, ""),
                r("kv.snapshot", 1, 1, 0, ""),
            ],
            verifications: vec![
                r("kv.expect", 2, 1, 3, "FAIL"),
                later,
                r("kv.expect", 1, 1, 9, "FAIL"),
                r("kv.other", 1, 1, 1, "PASS"),
            ],
            evaluations: vec![r("kv.size", 2, 1, 4, "ALLOW")],
            decisions: vec![],
        };
        let f = normalize(&results, &s);
        assert_eq!(
            f[&crate::policy::verification_fact("kv.expect")],
            FactValue::Text("PASS".into())
        );
        assert!(
            !f.contains_key(&crate::policy::verification_fact("kv.other")),
            "other generation ignored"
        );
        assert_eq!(
            f[&crate::policy::evaluation_fact("kv.size")],
            FactValue::Text("ALLOW".into())
        );
        assert_eq!(
            f[&crate::policy::evidence_fact("kv.snapshot")],
            FactValue::Int(2)
        );
        assert_eq!(f["kv.count"], FactValue::Int(3));
        let used = inputs(&results, &s);
        assert_eq!(used.verifications.len(), 1);
        assert_eq!(used.evidence.len(), 2);
    }
}
