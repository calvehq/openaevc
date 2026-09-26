//! Declarative, deterministic policy documents (spec/policy.md).
//!
//! Policy answers "does the protocol evidence satisfy the gates for this transition?". It is a
//! closed boolean expression language over normalized facts: no scripting, no I/O, no clock
//! other than the explicit evaluation timestamp. Policy can never grant authority.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{EvaluationVerdict, FactValue, VerificationStatus};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Namespaced policy name, e.g. `org.example.release-gates`.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// All rules must hold for the document to allow.
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub expr: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FactCompare {
    pub fact: String,
    pub value: FactValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntCompare {
    pub fact: String,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FactIn {
    pub fact: String,
    pub values: Vec<FactValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FactContains {
    pub fact: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FactName {
    pub fact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifierCondition {
    pub kind: String,
    pub status: VerificationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorCondition {
    pub kind: String,
    pub verdict: EvaluationVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCondition {
    pub kind: String,
}

/// Policy expression. JSON form is a single-key object naming the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Expr {
    All(Vec<Expr>),
    Any(Vec<Expr>),
    Not(Box<Expr>),
    Eq(FactCompare),
    Ne(FactCompare),
    Lt(IntCompare),
    Le(IntCompare),
    Gt(IntCompare),
    Ge(IntCompare),
    In(FactIn),
    Contains(FactContains),
    Exists(FactName),
    /// Latest candidate-bound verification of `kind` has `status`.
    Verifier(VerifierCondition),
    /// Latest candidate-bound evaluation of `kind` has `verdict`.
    Evaluator(EvaluatorCondition),
    /// At least one candidate-bound evidence object of `kind` exists.
    Evidence(EvidenceCondition),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn expression_json_shape() {
        let e: Expr = serde_json::from_value(json!({
            "all": [
                {"verifier": {"kind": "kv.expect", "status": "PASS"}},
                {"not": {"evaluator": {"kind": "kv.size", "verdict": "DENY"}}},
                {"any": [{"exists": {"fact": "org.x.ok"}}, {"eq": {"fact": "org.x.n", "value": 2}}]},
                {"ge": {"fact": "org.x.n", "value": 1}},
                {"in": {"fact": "org.x.s", "values": ["a", "b"]}},
                {"contains": {"fact": "org.x.set", "value": "a"}},
                {"evidence": {"kind": "kv.snapshot"}}
            ]
        }))
        .unwrap();
        let back = serde_json::to_value(&e).unwrap();
        assert_eq!(back["all"][0]["verifier"]["status"], "PASS");
        assert!(serde_json::from_value::<Expr>(json!({"script": "rm -rf"})).is_err());
    }
}
