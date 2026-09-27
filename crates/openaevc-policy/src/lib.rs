//! Deterministic policy evaluation (spec/policy.md).
//!
//! Evaluation is a pure function of the policy documents and a canonical fact map: no I/O, no
//! clock, no randomness. Normalized fact names used by the built-in conditions:
//!
//! * `verification.<kind>.status` = `"PASS" | "FAIL" | "INCONCLUSIVE" | "ERROR"`
//! * `evaluation.<kind>.verdict` = `"ALLOW" | "WARN" | "DENY" | "UNKNOWN"`
//! * `evidence.<kind>.count` = number of candidate-bound evidence objects of that kind
//!
//! A missing fact makes every comparison false except `ne` (which is `not eq`).
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use openaevc_core::names;
use openaevc_protocol::{
    err, DecisionOutcome, Digest, Expr, FactValue, Facts, PolicyDocument, ProtocolError, RuleResult,
};

/// Maximum expression nesting accepted by [`validate`].
pub const MAX_DEPTH: usize = 64;

pub fn verification_fact(kind: &str) -> String {
    format!("verification.{kind}.status")
}

pub fn evaluation_fact(kind: &str) -> String {
    format!("evaluation.{kind}.verdict")
}

pub fn evidence_fact(kind: &str) -> String {
    format!("evidence.{kind}.count")
}

fn int(f: &Facts, name: &str) -> Option<i64> {
    match f.get(name) {
        Some(FactValue::Int(i)) => Some(*i),
        _ => None,
    }
}

/// Evaluates one expression against facts.
pub fn eval(e: &Expr, f: &Facts) -> bool {
    match e {
        Expr::All(v) => v.iter().all(|x| eval(x, f)),
        Expr::Any(v) => v.iter().any(|x| eval(x, f)),
        Expr::Not(x) => !eval(x, f),
        Expr::Eq(c) => f.get(&c.fact) == Some(&c.value),
        Expr::Ne(c) => f.get(&c.fact) != Some(&c.value),
        Expr::Lt(c) => int(f, &c.fact).is_some_and(|v| v < c.value),
        Expr::Le(c) => int(f, &c.fact).is_some_and(|v| v <= c.value),
        Expr::Gt(c) => int(f, &c.fact).is_some_and(|v| v > c.value),
        Expr::Ge(c) => int(f, &c.fact).is_some_and(|v| v >= c.value),
        Expr::In(c) => f.get(&c.fact).is_some_and(|v| c.values.contains(v)),
        Expr::Contains(c) => {
            matches!(f.get(&c.fact), Some(FactValue::Set(s)) if s.contains(&c.value))
        }
        Expr::Exists(c) => f.contains_key(&c.fact),
        Expr::Verifier(c) => {
            f.get(&verification_fact(&c.kind)) == Some(&FactValue::Text(c.status.as_str().into()))
        }
        Expr::Evaluator(c) => {
            f.get(&evaluation_fact(&c.kind)) == Some(&FactValue::Text(c.verdict.as_str().into()))
        }
        Expr::Evidence(c) => int(f, &evidence_fact(&c.kind)).is_some_and(|n| n >= 1),
    }
}

/// Evaluates every rule of every policy. The outcome is ALLOW only if all rules pass.
pub fn evaluate(
    policies: &[(Digest, &PolicyDocument)],
    facts: &Facts,
) -> (DecisionOutcome, Vec<RuleResult>) {
    let rules: Vec<RuleResult> = policies
        .iter()
        .flat_map(|(d, doc)| {
            doc.rules.iter().map(move |r| RuleResult {
                policy: *d,
                rule: r.id.clone(),
                passed: eval(&r.expr, facts),
            })
        })
        .collect();
    let outcome = if rules.iter().all(|r| r.passed) {
        DecisionOutcome::Allow
    } else {
        DecisionOutcome::Deny
    };
    (outcome, rules)
}

fn validate_expr(e: &Expr, depth: usize) -> Result<(), ProtocolError> {
    if depth > MAX_DEPTH {
        return Err(err::invalid("policy expression nests too deeply"));
    }
    match e {
        Expr::All(v) | Expr::Any(v) => v.iter().try_for_each(|x| validate_expr(x, depth + 1)),
        Expr::Not(x) => validate_expr(x, depth + 1),
        Expr::Eq(c) | Expr::Ne(c) => names::validate_namespaced(&c.fact),
        Expr::Lt(c) | Expr::Le(c) | Expr::Gt(c) | Expr::Ge(c) => {
            names::validate_namespaced(&c.fact)
        }
        Expr::In(c) => names::validate_namespaced(&c.fact),
        Expr::Contains(c) => names::validate_namespaced(&c.fact),
        Expr::Exists(c) => names::validate_namespaced(&c.fact),
        Expr::Verifier(c) => names::validate_namespaced(&c.kind),
        Expr::Evaluator(c) => names::validate_namespaced(&c.kind),
        Expr::Evidence(c) => names::validate_namespaced(&c.kind),
    }
}

/// Structural validation: namespaced name, unique non-empty rule IDs, namespaced fact names,
/// bounded depth.
pub fn validate(doc: &PolicyDocument) -> Result<(), ProtocolError> {
    names::validate_namespaced(&doc.name)?;
    let mut ids = BTreeSet::new();
    if doc.rules.is_empty()
        || !doc
            .rules
            .iter()
            .all(|r| !r.id.is_empty() && ids.insert(r.id.as_str()))
    {
        return Err(err::invalid(
            "policy needs rules with unique, non-empty ids",
        ));
    }
    doc.rules.iter().try_for_each(|r| validate_expr(&r.expr, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaevc_protocol::*;
    use serde_json::json;

    fn facts(v: serde_json::Value) -> Facts {
        serde_json::from_value(v).unwrap()
    }

    fn expr(v: serde_json::Value) -> Expr {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn operators() {
        let f = facts(json!({"a.n": 5, "a.s": "x", "a.b": true, "a.set": ["p", "q"]}));
        let t = |e: serde_json::Value| eval(&expr(e), &f);
        assert!(t(json!({"eq": {"fact": "a.n", "value": 5}})));
        assert!(!t(json!({"eq": {"fact": "a.missing", "value": 5}})));
        assert!(t(json!({"ne": {"fact": "a.s", "value": "y"}})));
        assert!(t(json!({"ne": {"fact": "a.missing", "value": "y"}})));
        assert!(t(json!({"lt": {"fact": "a.n", "value": 6}})));
        assert!(t(json!({"le": {"fact": "a.n", "value": 5}})));
        assert!(!t(json!({"gt": {"fact": "a.n", "value": 5}})));
        assert!(t(json!({"ge": {"fact": "a.n", "value": 5}})));
        assert!(
            !t(json!({"lt": {"fact": "a.s", "value": 6}})),
            "non-integer compare is false"
        );
        assert!(t(json!({"in": {"fact": "a.s", "values": ["x", "z"]}})));
        assert!(t(json!({"contains": {"fact": "a.set", "value": "q"}})));
        assert!(!t(json!({"contains": {"fact": "a.s", "value": "x"}})));
        assert!(t(json!({"exists": {"fact": "a.b"}})));
        assert!(t(json!({"all": []})));
        assert!(!t(json!({"any": []})));
        assert!(t(json!({"not": {"exists": {"fact": "a.zzz"}}})));
    }

    #[test]
    fn verifier_evaluator_evidence_conditions_read_normalized_facts() {
        let f = facts(json!({
            "verification.kv.expect.status": "PASS",
            "evaluation.kv.size.verdict": "WARN",
            "evidence.kv.snapshot.count": 2
        }));
        assert!(eval(
            &expr(json!({"verifier": {"kind": "kv.expect", "status": "PASS"}})),
            &f
        ));
        assert!(!eval(
            &expr(json!({"verifier": {"kind": "kv.other", "status": "PASS"}})),
            &f
        ));
        assert!(eval(
            &expr(json!({"evaluator": {"kind": "kv.size", "verdict": "WARN"}})),
            &f
        ));
        assert!(eval(
            &expr(json!({"evidence": {"kind": "kv.snapshot"}})),
            &f
        ));
        assert!(!eval(&expr(json!({"evidence": {"kind": "kv.none"}})), &f));
    }

    fn doc(rules: Vec<(&str, serde_json::Value)>) -> PolicyDocument {
        PolicyDocument {
            name: "org.example.gates".into(),
            description: None,
            rules: rules
                .into_iter()
                .map(|(id, e)| PolicyRule {
                    id: id.into(),
                    expr: expr(e),
                })
                .collect(),
        }
    }

    #[test]
    fn decision_requires_every_rule_of_every_policy() {
        let a = doc(vec![("ok", json!({"exists": {"fact": "a.x"}}))]);
        let b = doc(vec![("fails", json!({"exists": {"fact": "a.y"}}))]);
        let (da, db) = (Digest::sha256([1; 32]), Digest::sha256([2; 32]));
        let f = facts(json!({"a.x": true}));
        let (outcome, rules) = evaluate(&[(da, &a)], &f);
        assert_eq!(outcome, DecisionOutcome::Allow);
        assert_eq!(rules.len(), 1);
        let (outcome, rules) = evaluate(&[(da, &a), (db, &b)], &f);
        assert_eq!(outcome, DecisionOutcome::Deny);
        assert_eq!(rules.iter().filter(|r| !r.passed).count(), 1);
        assert_eq!(rules[1].policy, db);
    }

    #[test]
    fn no_policies_means_allow() {
        assert_eq!(evaluate(&[], &Facts::new()).0, DecisionOutcome::Allow);
    }

    #[test]
    fn validation_rejects_bad_documents() {
        assert!(validate(&doc(vec![("r", json!({"exists": {"fact": "a.x"}}))])).is_ok());
        assert!(validate(&doc(vec![])).is_err());
        assert!(validate(&doc(vec![
            ("r", json!({"all": []})),
            ("r", json!({"all": []}))
        ]))
        .is_err());
        assert!(validate(&doc(vec![(
            "r",
            json!({"exists": {"fact": "nonamespace"}})
        )]))
        .is_err());
        let mut d = doc(vec![("r", json!({"all": []}))]);
        d.name = "bad".into();
        assert!(validate(&d).is_err());
        let mut deep = json!({"exists": {"fact": "a.x"}});
        for _ in 0..70 {
            deep = json!({"not": deep});
        }
        assert!(validate(&doc(vec![("r", deep)])).is_err(), "depth limit");
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn evaluation_is_deterministic_and_negation_consistent(n in -5i64..5, bound in -5i64..5) {
            let f = facts(json!({"a.n": n}));
            let e = expr(json!({"lt": {"fact": "a.n", "value": bound}}));
            let first = eval(&e, &f);
            prop_assert_eq!(first, eval(&e, &f));
            prop_assert_eq!(first, !eval(&Expr::Not(Box::new(e)), &f));
            prop_assert_eq!(first, n < bound);
        }
    }
}
