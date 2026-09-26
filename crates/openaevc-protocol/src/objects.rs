//! Immutable protocol objects and their envelope (spec/object-model.md).
//!
//! Every immutable object is an [`ObjectEnvelope`] encoded canonically. Its digest is the
//! SHA-256 of those canonical bytes (signatures included, so stored bytes are fixed forever).
//! Signatures cover the *signing digest*: the canonical encoding of the envelope with the
//! `signatures` field omitted, in the `object` signature domain.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AppliedEffect, BaselineId, CommandResult, Digest, EvaluationId, EvidenceId, ExecutionId,
    ExtensionRef, Facts, GrantId, Metadata, NamespaceId, NodeRef, ObservationId, PackId,
    PrincipalId, PromotionId, ProtocolVersion, PublicKey, RequestId, ResourceRef, RevisionInfo,
    RevisionRelation, RuntimeInstanceId, Sequence, SignatureEntry, Timestamp, VerificationId,
    WorkUnitId,
};

macro_rules! object_kinds {
    ($($variant:ident => $text:literal,)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all = "snake_case")]
        pub enum ObjectKind {
            $($variant,)*
        }

        impl ObjectKind {
            pub const ALL: &'static [ObjectKind] = &[$(ObjectKind::$variant,)*];

            pub fn as_str(&self) -> &'static str {
                match self {
                    $(ObjectKind::$variant => $text,)*
                }
            }
        }
    };
}

object_kinds! {
    Blob => "blob",
    CapabilityGrant => "capability_grant",
    Revocation => "revocation",
    PolicyDocument => "policy_document",
    PolicyDecision => "policy_decision",
    ExtensionManifest => "extension_manifest",
    Candidate => "candidate",
    Observation => "observation",
    Evidence => "evidence",
    VerificationResult => "verification_result",
    EvaluationResult => "evaluation_result",
    PromotedPack => "promoted_pack",
    PromotionRecord => "promotion_record",
    Receipt => "receipt",
    Baseline => "baseline",
    JournalCheckpoint => "journal_checkpoint",
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObjectEnvelope {
    pub kind: ObjectKind,
    pub protocol_version: ProtocolVersion,
    pub namespace: NamespaceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Namespace event sequence of the event that created the object.
    pub created_seq: Sequence,
    pub creator: PrincipalId,
    pub body: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<SignatureEntry>,
}

// ---------------------------------------------------------------------------------------------
// Bodies

/// Opaque bytes (evidence payloads, large observation payloads).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub media_type: String,
    #[serde(with = "crate::b64::serde_bytes")]
    #[schemars(with = "String")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    pub grant: GrantId,
    pub grant_digest: Digest,
    pub revoked_by: PrincipalId,
    pub revoked_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Frozen candidate state of a sealed pack generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub pack: PackId,
    pub generation: u64,
    pub effects: Vec<AppliedEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub id: ObservationId,
    pub execution: ExecutionId,
    pub pack: PackId,
    pub generation: u64,
    pub work_unit: WorkUnitId,
    pub producer: PrincipalId,
    pub observed_at: Timestamp,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_resources: Vec<ResourceRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_effects: Vec<crate::EffectId>,
    pub provenance: crate::Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SchemaRef {
    pub id: String,
    pub version: String,
}

/// Immutable, content-addressed evidence bound to one candidate/generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub id: EvidenceId,
    pub kind: String,
    pub producer: PrincipalId,
    pub pack: PackId,
    pub generation: u64,
    pub candidate: Digest,
    /// Digest of the Blob object holding the payload.
    pub payload: Digest,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<NodeRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<ExtensionRef>,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStatus {
    Pass,
    Fail,
    Inconclusive,
    Error,
}

impl VerificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationStatus::Pass => "PASS",
            VerificationStatus::Fail => "FAIL",
            VerificationStatus::Inconclusive => "INCONCLUSIVE",
            VerificationStatus::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvaluationVerdict {
    Allow,
    Warn,
    Deny,
    Unknown,
}

impl EvaluationVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvaluationVerdict::Allow => "ALLOW",
            EvaluationVerdict::Warn => "WARN",
            EvaluationVerdict::Deny => "DENY",
            EvaluationVerdict::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceRef>,
}

/// Who ran a verification/evaluation and in which request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunProvenance {
    pub caller: PrincipalId,
    pub request_id: RequestId,
    pub runtime_instance: RuntimeInstanceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerificationResult {
    pub id: VerificationId,
    pub pack: PackId,
    pub generation: u64,
    pub candidate: Digest,
    pub verifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<ExtensionRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    pub status: VerificationStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: Facts,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
    pub provenance: RunProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub id: EvaluationId,
    pub pack: PackId,
    pub generation: u64,
    pub candidate: Digest,
    pub evaluator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<ExtensionRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    pub verdict: EvaluationVerdict,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metrics: BTreeMap<String, i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: Facts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Digest>,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
    pub provenance: RunProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionOutcome {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleResult {
    pub policy: Digest,
    pub rule: String,
    pub passed: bool,
}

/// Canonical result of evaluating policies over facts for one candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub pack: PackId,
    pub generation: u64,
    pub candidate: Digest,
    pub policies: Vec<Digest>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: Facts,
    pub outcome: DecisionOutcome,
    pub rules: Vec<RuleResult>,
    pub evaluated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromotionRecord {
    pub id: PromotionId,
    pub pack: PackId,
    pub generation: u64,
    pub candidate: Digest,
    pub policy_decision: Digest,
    pub promoted_by: PrincipalId,
    pub promoted_at: Timestamp,
    pub request_id: RequestId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectSummary {
    pub kind: String,
    pub target: ResourceRef,
}

/// Immutable accepted snapshot of a promoted ChangePack or RevisionPack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromotedPack {
    pub pack: PackId,
    pub generation: u64,
    pub candidate: Digest,
    pub effects: Vec<EffectSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceRef>,
    /// PromotedPack digests this pack requires.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts_with: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<RevisionInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifications: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluations: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Digest>,
    pub policy_decisions: Vec<Digest>,
    pub promotion_record: Digest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ExtensionRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
    /// Digest of the canonical list of the candidate effects' provenance records.
    pub provenance_root: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompositionEdgeKind {
    Requires,
    OrdersAfter,
    ConflictsWith,
    RevisionRelation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompositionEdge {
    pub from: Digest,
    pub to: Digest,
    pub kind: CompositionEdgeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<RevisionRelation>,
}

/// Immutable commitment to a validated composition graph of promoted packs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub id: BaselineId,
    /// PromotedPack digests, sorted.
    pub members: Vec<Digest>,
    /// Canonical edge list, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<CompositionEdge>,
    /// Members that are lineage heads (not superseded by another member), sorted.
    pub heads: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<Digest>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: Facts,
    /// Digest of the canonical `{members, edges}` graph.
    pub graph_digest: Digest,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalCheckpoint {
    pub sequence: Sequence,
    pub event_hash: Digest,
    pub runtime_key: PublicKey,
    pub runtime_instance: RuntimeInstanceId,
    pub created_at: Timestamp,
}

/// Canonical command receipt, signed by the runtime key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub request_id: RequestId,
    pub command: String,
    pub caller: PrincipalId,
    pub envelope_digest: Digest,
    pub result: CommandResult,
    pub first_seq: Sequence,
    pub last_seq: Sequence,
    pub runtime_instance: RuntimeInstanceId,
    pub completed_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_kind_names() {
        assert_eq!(serde_json::to_value(ObjectKind::PromotedPack).unwrap(), json!("promoted_pack"));
        assert_eq!(ObjectKind::JournalCheckpoint.as_str(), "journal_checkpoint");
        assert_eq!(ObjectKind::ALL.len(), 16);
    }

    #[test]
    fn envelope_omits_empty_signatures_and_id() {
        let env = ObjectEnvelope {
            kind: ObjectKind::Blob,
            protocol_version: crate::PROTOCOL_VERSION,
            namespace: "ns_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            id: None,
            created_seq: 1,
            creator: "pri_agjdus24nvyadaareizuivlgo4".parse().unwrap(),
            body: json!({"media_type": "text/plain", "data": "aGk"}),
            signatures: vec![],
        };
        let v = serde_json::to_value(&env).unwrap();
        assert!(v.get("signatures").is_none());
        assert!(v.get("id").is_none());
        let bytes = openaevc_canonical_test::to_canonical(&env).unwrap();
        let back: ObjectEnvelope = openaevc_canonical_test::from_canonical(&bytes).unwrap();
        assert_eq!(back, env);
    }
}
