//! Domain logic of the `reference-kv` extension: a tiny generic key-value domain that exercises
//! resources, effects, preconditions, verification, evaluation and composition conflicts
//! without any software assumptions.
//!
//! * resource `kv.entry` (locator = key)
//! * effects `kv.set {value: string}` and `kv.delete {}`, both requiring action `kv.write`
//! * preconditions `{"absent": true}`, `{"present": true}`, `{"equals": "v"}`, evaluated against
//!   the candidate's earlier effects on the same key
//! * verifier `kv.expect` config `{key, value}` or `{key, absent: true}`
//! * evaluator `kv.size` config `{max_keys}`
//! * composition validator `kv.terminal-values`: two members that are not ordered relative to
//!   each other must not leave the same key in different terminal states
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

pub use openaevc_extension_contract::wire::{
    ComposeMember, ComposeOutput, CompositionConflict, EvaluateOutput, VerifyOutput,
};
use openaevc_protocol::{
    AppliedEffect, CompositionEdge, CompositionEdgeKind, Digest, EffectProposal, EvaluationVerdict,
    FactValue, Facts, Finding, ResourceRef, VerificationStatus,
};
use serde_json::{json, Value};

pub const ID: &str = "org.openaevc.reference.kv";

/// Terminal state per key: `Some(value)` or `None` for deleted.
pub fn terminal(effects: &[AppliedEffect]) -> BTreeMap<String, Option<String>> {
    let mut out = BTreeMap::new();
    for e in effects.iter().filter(|e| e.target.kind == "kv.entry") {
        let v = match e.kind.as_str() {
            "kv.set" => e
                .payload
                .get("value")
                .and_then(Value::as_str)
                .map(str::to_owned),
            _ => None,
        };
        out.insert(e.target.locator.clone(), v);
    }
    out
}

fn current(prior: &[AppliedEffect], key: &str) -> Option<String> {
    terminal(prior).remove(key).flatten()
}

/// Validates shape and preconditions of a proposal.
pub fn validate(e: &EffectProposal, prior: &[AppliedEffect]) -> Result<(), String> {
    if e.target.kind != "kv.entry" || e.target.extension != ID {
        return Err("kv effects target kv.entry resources of this extension".into());
    }
    if e.target.locator.is_empty() {
        return Err("key must not be empty".into());
    }
    match e.kind.as_str() {
        "kv.set" => {
            let ok = e
                .payload
                .as_object()
                .is_some_and(|m| m.len() == 1 && m.get("value").is_some_and(Value::is_string));
            if !ok {
                return Err("kv.set payload must be {\"value\": string}".into());
            }
        }
        "kv.delete" => {
            if e.payload != json!({}) {
                return Err("kv.delete payload must be {}".into());
            }
        }
        other => return Err(format!("unknown effect kind {other}")),
    }
    let now = current(prior, &e.target.locator);
    for p in &e.preconditions {
        let holds = if p == &json!({"absent": true}) {
            now.is_none()
        } else if p == &json!({"present": true}) {
            now.is_some()
        } else if let Some(v) = p
            .as_object()
            .filter(|m| m.len() == 1)
            .and_then(|m| m.get("equals"))
            .and_then(Value::as_str)
        {
            now.as_deref() == Some(v)
        } else {
            return Err(format!("unknown precondition {p}"));
        };
        if !holds {
            return Err(format!(
                "precondition {p} does not hold for key {}",
                e.target.locator
            ));
        }
    }
    Ok(())
}

/// Outcome recorded with an applied effect.
pub fn outcome(e: &EffectProposal, prior: &[AppliedEffect]) -> Value {
    let mut m = serde_json::Map::new();
    if let Some(prev) = current(prior, &e.target.locator) {
        m.insert("previous".into(), Value::String(prev));
    }
    match e.kind.as_str() {
        "kv.set" => {
            m.insert("value".into(), e.payload["value"].clone());
        }
        _ => {
            m.insert("deleted".into(), Value::Bool(true));
        }
    }
    Value::Object(m)
}

pub fn facts(effects: &[AppliedEffect]) -> Facts {
    let keys: BTreeSet<String> = terminal(effects).into_keys().collect();
    let mut f = Facts::new();
    f.insert("kv.count".into(), FactValue::Int(effects.len() as i64));
    f.insert("kv.keys".into(), FactValue::Set(keys));
    f
}

/// `kv.expect` verifier.
pub fn expect(effects: &[AppliedEffect], config: &Value) -> Result<VerifyOutput, String> {
    let key = config
        .get("key")
        .and_then(Value::as_str)
        .ok_or("kv.expect config needs a \"key\"")?;
    let want = match (
        config.get("value").and_then(Value::as_str),
        config.get("absent").and_then(Value::as_bool),
    ) {
        (Some(v), None) => Some(v.to_owned()),
        (None, Some(true)) => None,
        _ => return Err("kv.expect config needs either \"value\" or \"absent\": true".into()),
    };
    let got = terminal(effects).remove(key).flatten();
    let pass = got == want;
    let resource = ResourceRef {
        kind: "kv.entry".into(),
        locator: key.into(),
        version: None,
        extension: ID.into(),
    };
    let finding = Finding {
        code: if pass {
            "kv.match".into()
        } else {
            "kv.mismatch".into()
        },
        message: format!("key {key}: expected {want:?}, found {got:?}"),
        resource: Some(resource),
    };
    Ok(VerifyOutput {
        status: if pass {
            VerificationStatus::Pass
        } else {
            VerificationStatus::Fail
        },
        findings: vec![finding],
        facts: facts(effects),
    })
}

/// `kv.size` evaluator.
pub fn size(effects: &[AppliedEffect], config: &Value) -> Result<EvaluateOutput, String> {
    let max = config
        .get("max_keys")
        .and_then(Value::as_i64)
        .ok_or("kv.size config needs \"max_keys\"")?;
    let n = terminal(effects).len() as i64;
    Ok(EvaluateOutput {
        verdict: if n <= max {
            EvaluationVerdict::Allow
        } else {
            EvaluationVerdict::Deny
        },
        metrics: BTreeMap::from([("kv.keys".to_string(), n)]),
        facts: Facts::new(),
    })
}

/// `kv.terminal-values` composition validator.
pub fn compose(members: &[ComposeMember], edges: &[CompositionEdge]) -> ComposeOutput {
    let order: Vec<(Digest, Digest)> = edges
        .iter()
        .filter(|e| e.kind != CompositionEdgeKind::ConflictsWith)
        .map(|e| (e.from, e.to))
        .collect();
    let reach = |a: &Digest, b: &Digest| {
        let mut seen = BTreeSet::new();
        let mut stack = vec![*a];
        while let Some(n) = stack.pop() {
            for (x, y) in &order {
                if *x == n && seen.insert(*y) {
                    if y == b {
                        return true;
                    }
                    stack.push(*y);
                }
            }
        }
        false
    };
    let states: Vec<(Digest, BTreeMap<String, Option<String>>)> = members
        .iter()
        .map(|m| (m.digest, terminal(&m.effects)))
        .collect();
    let mut conflicts = Vec::new();
    for (i, (da, sa)) in states.iter().enumerate() {
        for (db, sb) in &states[i + 1..] {
            if reach(da, db) || reach(db, da) {
                continue;
            }
            for (k, va) in sa {
                if let Some(vb) = sb.get(k) {
                    if va != vb {
                        conflicts.push(CompositionConflict {
                            a: *da,
                            b: *db,
                            reason: format!("key {k}: {va:?} vs {vb:?}"),
                        });
                    }
                }
            }
        }
    }
    let mut f = Facts::new();
    f.insert("kv.members".into(), FactValue::Int(members.len() as i64));
    ComposeOutput {
        valid: conflicts.is_empty(),
        conflicts,
        facts: f,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaevc_protocol::Provenance;
    use serde_json::json;

    fn eff(
        kind: &str,
        key: &str,
        payload: serde_json::Value,
        pre: Vec<serde_json::Value>,
    ) -> EffectProposal {
        EffectProposal {
            kind: kind.into(),
            target: ResourceRef {
                kind: "kv.entry".into(),
                locator: key.into(),
                version: None,
                extension: ID.into(),
            },
            payload,
            preconditions: pre,
            outputs: vec![],
        }
    }

    fn applied(p: &EffectProposal) -> AppliedEffect {
        AppliedEffect {
            id: "eff_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            work_unit: "wku_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            kind: p.kind.clone(),
            target: p.target.clone(),
            payload: p.payload.clone(),
            preconditions: p.preconditions.clone(),
            outputs: vec![],
            outcome: json!({}),
            provenance: Provenance {
                actor: "pri_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
                caller: "pri_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
                provider: "p.x".into(),
                worker: None,
                harness: "h.x".into(),
                extension: None,
                grants: vec![],
                request_id: "req_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
                pack: "cpk_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
                generation: 1,
                execution: "exe_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
                runtime_instance: "rti_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
                inputs: vec![],
            },
        }
    }

    #[test]
    fn validates_payload_shapes() {
        assert!(validate(&eff("kv.set", "a", json!({"value": "1"}), vec![]), &[]).is_ok());
        assert!(validate(&eff("kv.set", "a", json!({"value": 1}), vec![]), &[]).is_err());
        assert!(validate(
            &eff("kv.set", "a", json!({"value": "1", "x": 1}), vec![]),
            &[]
        )
        .is_err());
        assert!(validate(&eff("kv.delete", "a", json!({}), vec![]), &[]).is_ok());
        assert!(validate(&eff("kv.drop", "a", json!({}), vec![]), &[]).is_err());
        let mut wrong = eff("kv.set", "a", json!({"value": "1"}), vec![]);
        wrong.target.kind = "other.thing".into();
        assert!(validate(&wrong, &[]).is_err());
    }

    #[test]
    fn preconditions_check_candidate_state() {
        let set = eff("kv.set", "a", json!({"value": "1"}), vec![]);
        let prior = vec![applied(&set)];
        assert!(validate(
            &eff(
                "kv.set",
                "a",
                json!({"value": "2"}),
                vec![json!({"equals": "1"})]
            ),
            &prior
        )
        .is_ok());
        assert!(validate(
            &eff(
                "kv.set",
                "a",
                json!({"value": "2"}),
                vec![json!({"equals": "9"})]
            ),
            &prior
        )
        .is_err());
        assert!(validate(
            &eff(
                "kv.set",
                "a",
                json!({"value": "2"}),
                vec![json!({"absent": true})]
            ),
            &prior
        )
        .is_err());
        assert!(validate(
            &eff(
                "kv.set",
                "a",
                json!({"value": "2"}),
                vec![json!({"absent": true})]
            ),
            &[]
        )
        .is_ok());
        assert!(validate(
            &eff("kv.delete", "a", json!({}), vec![json!({"present": true})]),
            &prior
        )
        .is_ok());
        assert!(validate(
            &eff("kv.delete", "a", json!({}), vec![json!({"bogus": 1})]),
            &prior
        )
        .is_err());
    }

    #[test]
    fn terminal_state_folds_effects_in_order() {
        let effects = vec![
            applied(&eff("kv.set", "a", json!({"value": "1"}), vec![])),
            applied(&eff("kv.set", "b", json!({"value": "x"}), vec![])),
            applied(&eff("kv.set", "a", json!({"value": "2"}), vec![])),
            applied(&eff("kv.delete", "b", json!({}), vec![])),
        ];
        let s = terminal(&effects);
        assert_eq!(s.get("a"), Some(&Some("2".to_string())));
        assert_eq!(s.get("b"), Some(&None));
    }

    #[test]
    fn expectation_verifier() {
        let effects = vec![applied(&eff("kv.set", "a", json!({"value": "1"}), vec![]))];
        assert_eq!(
            expect(&effects, &json!({"key": "a", "value": "1"}))
                .unwrap()
                .status,
            VerificationStatus::Pass
        );
        assert_eq!(
            expect(&effects, &json!({"key": "a", "value": "2"}))
                .unwrap()
                .status,
            VerificationStatus::Fail
        );
        assert_eq!(
            expect(&effects, &json!({"key": "z", "absent": true}))
                .unwrap()
                .status,
            VerificationStatus::Pass
        );
        assert!(expect(&effects, &json!({"nokey": 1})).is_err());
    }

    #[test]
    fn size_evaluator() {
        let effects = vec![
            applied(&eff("kv.set", "a", json!({"value": "1"}), vec![])),
            applied(&eff("kv.set", "b", json!({"value": "1"}), vec![])),
        ];
        assert_eq!(
            size(&effects, &json!({"max_keys": 2})).unwrap().verdict,
            EvaluationVerdict::Allow
        );
        let out = size(&effects, &json!({"max_keys": 1})).unwrap();
        assert_eq!(out.verdict, EvaluationVerdict::Deny);
        assert_eq!(out.metrics["kv.keys"], 2);
    }

    #[test]
    fn terminal_value_conflicts_unless_ordered() {
        let d = |n: u8| Digest::sha256([n; 32]);
        let m = |n: u8, v: &str| ComposeMember {
            digest: d(n),
            pack: "cpk_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            effects: vec![applied(&eff("kv.set", "k", json!({"value": v}), vec![]))],
        };
        let members = vec![m(1, "a"), m(2, "b"), m(3, "a")];
        let out = compose(&members, &[]);
        assert!(!out.valid);
        assert_eq!(out.conflicts.len(), 2, "1-2 and 2-3 conflict; 1-3 agree");
        let ordered = vec![
            CompositionEdge {
                from: d(2),
                to: d(1),
                kind: CompositionEdgeKind::OrdersAfter,
                relation: None,
            },
            CompositionEdge {
                from: d(3),
                to: d(2),
                kind: CompositionEdgeKind::OrdersAfter,
                relation: None,
            },
        ];
        assert!(compose(&members, &ordered).valid);
    }
}
