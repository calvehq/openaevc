//! Commands, queries, receipts, events and request envelopes (spec/transport.md, events.md).
//!
//! Commands and queries are tagged unions (`"type"`), wrapped in a signed [`Envelope`]. The
//! same envelope and semantics are used embedded and over the daemon transport.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocol::{
    ActiveEdgeKind, BaselineId, Blob, CompositionEdge, Digest, EffectId, EffectProposal, EventId,
    ExecutionId, ExecutionState, GrantId, HostCapability, Lease, LeaseId, Metadata, NamespaceId,
    NewPrincipal, NodeRef, ObjectKind, PackId, PolicyDocument, PrincipalId, ProtocolVersion,
    ProviderDescriptor, PublicKey, RequestId, ResourceRef, ResourceSelector, RevisionRelation,
    RuntimeInstanceId, SchemaRef, Sequence, Signature, SignedGrant, Timestamp, VersionRange,
    WorkUnitId, WorkUnitState, WorkerInfo,
};

fn is_false(b: &bool) -> bool {
    !*b
}

/// Descriptive fields shared by `CreateChangePack` and `CreateRevisionPack`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_refs: Vec<ResourceRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_policies: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_bindings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts_with: Vec<Digest>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
}

/// Execution admission request (spec/execution.md §ExecutionRequest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub pack: PackId,
    pub expected_generation: u64,
    pub work_unit: WorkUnitId,
    pub provider: String,
    pub harness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<WorkerInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_resources: Vec<ResourceSelector>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_effects: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<Digest>,
    pub timeout_ms: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub budget: BTreeMap<String, i64>,
    pub max_attempts: u32,
    pub idempotency_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_of: Option<ExecutionId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Command {
    /// Create a Namespace with its root principals (runtime administrators only).
    CreateNamespace {
        root_principals: Vec<NewPrincipal>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        metadata: Metadata,
    },
    RegisterPrincipal {
        principal: NewPrincipal,
    },
    IssueCapabilityGrant {
        grant: SignedGrant,
    },
    RevokeCapabilityGrant {
        grant: GrantId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Store an immutable PolicyDocument; `mandatory` adds it to the Namespace gates.
    RegisterPolicy {
        document: PolicyDocument,
        #[serde(default, skip_serializing_if = "is_false")]
        mandatory: bool,
    },
    /// Load, handshake and register an extension from a configured extension directory.
    RegisterExtension {
        entrypoint: String,
        artifact_digest: Digest,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        approved_host_capabilities: Vec<HostCapability>,
    },
    UnregisterExtension {
        extension: String,
    },
    RegisterProvider {
        provider: ProviderDescriptor,
    },
    CreateChangePack {
        #[serde(default)]
        spec: PackSpec,
    },
    CreateRevisionPack {
        relation: RevisionRelation,
        targets: Vec<Digest>,
        #[serde(default)]
        spec: PackSpec,
    },
    /// Structural update; absent fields are unchanged. Produces a new generation.
    UpdateChangePack {
        pack: PackId,
        expected_generation: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        intent: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource_refs: Option<Vec<ResourceRef>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        required_policies: Option<Vec<Digest>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extension_bindings: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        conflicts_with: Option<Vec<Digest>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<Metadata>,
    },
    AddWorkUnit {
        pack: PackId,
        expected_generation: u64,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        spec: Option<Value>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        depends_on: Vec<NodeRef>,
    },
    UpdateWorkUnit {
        pack: PackId,
        expected_generation: u64,
        work_unit: WorkUnitId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        spec: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<WorkUnitState>,
    },
    AddActiveDependency {
        pack: PackId,
        expected_generation: u64,
        from: NodeRef,
        to: NodeRef,
        kind: ActiveEdgeKind,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        annotations: Metadata,
    },
    RemoveActiveDependency {
        pack: PackId,
        expected_generation: u64,
        from: NodeRef,
        to: NodeRef,
        kind: ActiveEdgeKind,
    },
    SealChangePack {
        pack: PackId,
        expected_generation: u64,
    },
    ReopenChangePack {
        pack: PackId,
        expected_generation: u64,
    },
    AbandonChangePack {
        pack: PackId,
        expected_generation: u64,
    },
    QuarantineChangePack {
        pack: PackId,
        reason: String,
    },
    ReleaseQuarantine {
        pack: PackId,
    },
    StartExecution {
        request: ExecutionRequest,
    },
    /// Renew the lease. With a resumable provider, also the recovery proof for an expired lease.
    HeartbeatExecution {
        execution: ExecutionId,
        lease: LeaseId,
        generation: u64,
    },
    CancelExecution {
        execution: ExecutionId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    SubmitEffectProposal {
        execution: ExecutionId,
        lease: LeaseId,
        effect: EffectProposal,
    },
    AppendObservation {
        execution: ExecutionId,
        lease: LeaseId,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        payload: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blob: Option<Blob>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        related_resources: Vec<ResourceRef>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        related_effects: Vec<EffectId>,
    },
    CompleteExecution {
        execution: ExecutionId,
        lease: LeaseId,
    },
    FailExecution {
        execution: ExecutionId,
        lease: LeaseId,
        reason: String,
    },
    RegisterEvidence {
        pack: PackId,
        generation: u64,
        candidate: Digest,
        kind: String,
        payload: Blob,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema: Option<SchemaRef>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sources: Vec<NodeRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extension: Option<String>,
    },
    RunVerification {
        pack: PackId,
        generation: u64,
        verifier: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<Value>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        evidence: Vec<Digest>,
    },
    RunEvaluation {
        pack: PackId,
        generation: u64,
        evaluator: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<Value>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<Digest>,
    },
    RefreshQualification {
        pack: PackId,
        generation: u64,
    },
    PromoteChangePack {
        pack: PackId,
        generation: u64,
    },
    CreateBaseline {
        members: Vec<Digest>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        edges: Vec<CompositionEdge>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        policies: Vec<Digest>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        metadata: Metadata,
    },
    /// Import canonical object bytes by digest (object exchange).
    PutImmutableObject {
        digest: Digest,
        #[serde(with = "crate::protocol::b64::serde_bytes")]
        #[schemars(with = "String")]
        bytes: Vec<u8>,
    },
}

impl Command {
    pub const NAMES: &'static [&'static str] = &[
        "CreateNamespace",
        "RegisterPrincipal",
        "IssueCapabilityGrant",
        "RevokeCapabilityGrant",
        "RegisterPolicy",
        "RegisterExtension",
        "UnregisterExtension",
        "RegisterProvider",
        "CreateChangePack",
        "CreateRevisionPack",
        "UpdateChangePack",
        "AddWorkUnit",
        "UpdateWorkUnit",
        "AddActiveDependency",
        "RemoveActiveDependency",
        "SealChangePack",
        "ReopenChangePack",
        "AbandonChangePack",
        "QuarantineChangePack",
        "ReleaseQuarantine",
        "StartExecution",
        "HeartbeatExecution",
        "CancelExecution",
        "SubmitEffectProposal",
        "AppendObservation",
        "CompleteExecution",
        "FailExecution",
        "RegisterEvidence",
        "RunVerification",
        "RunEvaluation",
        "RefreshQualification",
        "PromoteChangePack",
        "CreateBaseline",
        "PutImmutableObject",
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Command::CreateNamespace { .. } => "CreateNamespace",
            Command::RegisterPrincipal { .. } => "RegisterPrincipal",
            Command::IssueCapabilityGrant { .. } => "IssueCapabilityGrant",
            Command::RevokeCapabilityGrant { .. } => "RevokeCapabilityGrant",
            Command::RegisterPolicy { .. } => "RegisterPolicy",
            Command::RegisterExtension { .. } => "RegisterExtension",
            Command::UnregisterExtension { .. } => "UnregisterExtension",
            Command::RegisterProvider { .. } => "RegisterProvider",
            Command::CreateChangePack { .. } => "CreateChangePack",
            Command::CreateRevisionPack { .. } => "CreateRevisionPack",
            Command::UpdateChangePack { .. } => "UpdateChangePack",
            Command::AddWorkUnit { .. } => "AddWorkUnit",
            Command::UpdateWorkUnit { .. } => "UpdateWorkUnit",
            Command::AddActiveDependency { .. } => "AddActiveDependency",
            Command::RemoveActiveDependency { .. } => "RemoveActiveDependency",
            Command::SealChangePack { .. } => "SealChangePack",
            Command::ReopenChangePack { .. } => "ReopenChangePack",
            Command::AbandonChangePack { .. } => "AbandonChangePack",
            Command::QuarantineChangePack { .. } => "QuarantineChangePack",
            Command::ReleaseQuarantine { .. } => "ReleaseQuarantine",
            Command::StartExecution { .. } => "StartExecution",
            Command::HeartbeatExecution { .. } => "HeartbeatExecution",
            Command::CancelExecution { .. } => "CancelExecution",
            Command::SubmitEffectProposal { .. } => "SubmitEffectProposal",
            Command::AppendObservation { .. } => "AppendObservation",
            Command::CompleteExecution { .. } => "CompleteExecution",
            Command::FailExecution { .. } => "FailExecution",
            Command::RegisterEvidence { .. } => "RegisterEvidence",
            Command::RunVerification { .. } => "RunVerification",
            Command::RunEvaluation { .. } => "RunEvaluation",
            Command::RefreshQualification { .. } => "RefreshQualification",
            Command::PromoteChangePack { .. } => "PromoteChangePack",
            Command::CreateBaseline { .. } => "CreateBaseline",
            Command::PutImmutableObject { .. } => "PutImmutableObject",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Query {
    GetRuntimeInfo {},
    GetNamespace {},
    GetPrincipal {
        principal: PrincipalId,
    },
    GetGrant {
        grant: GrantId,
    },
    Authorize {
        principal: PrincipalId,
        action: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<ResourceRef>,
    },
    GetChangePack {
        pack: PackId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation: Option<u64>,
    },
    GetRevisionPack {
        pack: PackId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation: Option<u64>,
    },
    GetActiveChangeGraph {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pack: Option<PackId>,
    },
    GetNode {
        node: NodeRef,
    },
    GetDependencyClosure {
        node: NodeRef,
        #[serde(default, skip_serializing_if = "is_false")]
        reverse: bool,
    },
    GetAffectedNodes {
        node: NodeRef,
    },
    GetReadyWork {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pack: Option<PackId>,
    },
    GetBlockedWork {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pack: Option<PackId>,
    },
    GetExecution {
        execution: ExecutionId,
    },
    ListExecutions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pack: Option<PackId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<ExecutionState>,
    },
    GetEvidence {
        digest: Digest,
    },
    GetVerification {
        digest: Digest,
    },
    GetEvaluation {
        digest: Digest,
    },
    GetPolicyDecision {
        digest: Digest,
    },
    GetPromotedPack {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pack: Option<PackId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        digest: Option<Digest>,
    },
    GetBaseline {
        baseline: BaselineId,
    },
    ValidateBaseline {
        digest: Digest,
    },
    GetBaselineClosure {
        baseline: BaselineId,
    },
    GetObjectClosure {
        digest: Digest,
    },
    GetPackClosure {
        digest: Digest,
    },
    GetObject {
        digest: Digest,
    },
    HasObject {
        digests: Vec<Digest>,
    },
    ComputeMissingObjects {
        digests: Vec<Digest>,
    },
    ListObjectDigests {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<ObjectKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
    },
    ListEvents {
        #[serde(default)]
        after: Sequence,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        kinds: Vec<String>,
    },
    GetJournalCheckpoint {},
    ListExtensions {},
}

impl Query {
    pub const NAMES: &'static [&'static str] = &[
        "GetRuntimeInfo",
        "GetNamespace",
        "GetPrincipal",
        "GetGrant",
        "Authorize",
        "GetChangePack",
        "GetRevisionPack",
        "GetActiveChangeGraph",
        "GetNode",
        "GetDependencyClosure",
        "GetAffectedNodes",
        "GetReadyWork",
        "GetBlockedWork",
        "GetExecution",
        "ListExecutions",
        "GetEvidence",
        "GetVerification",
        "GetEvaluation",
        "GetPolicyDecision",
        "GetPromotedPack",
        "GetBaseline",
        "ValidateBaseline",
        "GetBaselineClosure",
        "GetObjectClosure",
        "GetPackClosure",
        "GetObject",
        "HasObject",
        "ComputeMissingObjects",
        "ListObjectDigests",
        "ListEvents",
        "GetJournalCheckpoint",
        "ListExtensions",
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Query::GetRuntimeInfo { .. } => "GetRuntimeInfo",
            Query::GetNamespace { .. } => "GetNamespace",
            Query::GetPrincipal { .. } => "GetPrincipal",
            Query::GetGrant { .. } => "GetGrant",
            Query::Authorize { .. } => "Authorize",
            Query::GetChangePack { .. } => "GetChangePack",
            Query::GetRevisionPack { .. } => "GetRevisionPack",
            Query::GetActiveChangeGraph { .. } => "GetActiveChangeGraph",
            Query::GetNode { .. } => "GetNode",
            Query::GetDependencyClosure { .. } => "GetDependencyClosure",
            Query::GetAffectedNodes { .. } => "GetAffectedNodes",
            Query::GetReadyWork { .. } => "GetReadyWork",
            Query::GetBlockedWork { .. } => "GetBlockedWork",
            Query::GetExecution { .. } => "GetExecution",
            Query::ListExecutions { .. } => "ListExecutions",
            Query::GetEvidence { .. } => "GetEvidence",
            Query::GetVerification { .. } => "GetVerification",
            Query::GetEvaluation { .. } => "GetEvaluation",
            Query::GetPolicyDecision { .. } => "GetPolicyDecision",
            Query::GetPromotedPack { .. } => "GetPromotedPack",
            Query::GetBaseline { .. } => "GetBaseline",
            Query::ValidateBaseline { .. } => "ValidateBaseline",
            Query::GetBaselineClosure { .. } => "GetBaselineClosure",
            Query::GetObjectClosure { .. } => "GetObjectClosure",
            Query::GetPackClosure { .. } => "GetPackClosure",
            Query::GetObject { .. } => "GetObject",
            Query::HasObject { .. } => "HasObject",
            Query::ComputeMissingObjects { .. } => "ComputeMissingObjects",
            Query::ListObjectDigests { .. } => "ListObjectDigests",
            Query::ListEvents { .. } => "ListEvents",
            Query::GetJournalCheckpoint { .. } => "GetJournalCheckpoint",
            Query::ListExtensions { .. } => "ListExtensions",
        }
    }
}

/// Signed request envelope. The signature covers the canonical encoding of the envelope with
/// `signature` omitted, in the `request` signature domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "{T}Envelope")]
pub struct Envelope<T> {
    pub protocol_version: ProtocolVersion,
    pub request_id: RequestId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<NamespaceId>,
    pub caller: PrincipalId,
    /// ACTOR principal linked to `caller` on whose behalf the request is made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_as: Option<PrincipalId>,
    pub nonce: String,
    pub issued_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    pub body: T,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

pub type CommandEnvelope = Envelope<Command>;
pub type QueryEnvelope = Envelope<Query>;

/// Result data of a successful command (also embedded in its receipt).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
}

/// What a command returns: the result plus the digest of its signed receipt object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandReceipt {
    pub receipt: Digest,
    pub request_id: RequestId,
    pub result: CommandResult,
    pub first_seq: Sequence,
    pub last_seq: Sequence,
}

/// Journal event (spec/events.md). `hash = SHA-256(canonical(event without hash) ||
/// previous_hash bytes)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub id: EventId,
    pub namespace: NamespaceId,
    pub sequence: Sequence,
    pub runtime_instance: RuntimeInstanceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<PrincipalId>,
    pub kind: String,
    pub body: Value,
    /// Typed IDs / digests this event concerns (subscription filtering).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<String>,
    pub timestamp: Timestamp,
    pub previous_hash: Digest,
    pub hash: Digest,
}

/// Subscription filter. Delivery is at-least-once; consumers deduplicate by sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventFilter {
    pub namespace: NamespaceId,
    /// Deliver events with sequence strictly greater than this cursor.
    #[serde(default)]
    pub after: Sequence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
    /// Match events whose subjects include this ID/digest (object, execution or pack).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<String>,
}

impl EventFilter {
    pub fn matches(&self, e: &Event) -> bool {
        e.namespace == self.namespace
            && e.sequence > self.after
            && (self.kinds.is_empty() || self.kinds.iter().any(|k| k == &e.kind))
            && (self.subjects.is_empty() || self.subjects.iter().any(|s| e.subjects.contains(s)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImplementationInfo {
    pub name: String,
    pub version: String,
}

/// Answer to `GetRuntimeInfo` and `GET /v1/info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInfo {
    pub protocol: VersionRange,
    pub contract: VersionRange,
    pub implementation: ImplementationInfo,
    pub runtime_instance: RuntimeInstanceId,
    pub runtime_key: PublicKey,
    pub replay_window_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn commands_are_type_tagged() {
        let c: Command = serde_json::from_value(json!({
            "type": "SealChangePack",
            "pack": "cpk_agjdus24nvyadaareizuivlgo4",
            "expected_generation": 3
        }))
        .unwrap();
        assert_eq!(c.name(), "SealChangePack");
        assert!(serde_json::from_value::<Command>(json!({"type": "DropDatabase"})).is_err());
        assert!(serde_json::from_value::<Command>(json!({
            "type": "SealChangePack", "pack": "cpk_agjdus24nvyadaareizuivlgo4",
            "expected_generation": 3, "force": true
        }))
        .is_err());
    }

    #[test]
    fn every_command_and_query_name_is_listed() {
        assert_eq!(Command::NAMES.len(), 34);
        assert_eq!(Query::NAMES.len(), 32);
        assert!(Command::NAMES.contains(&"PromoteChangePack"));
        assert!(Query::NAMES.contains(&"GetBaselineClosure"));
    }

    #[test]
    fn queries_are_type_tagged() {
        let q: Query = serde_json::from_value(json!({"type": "GetRuntimeInfo"})).unwrap();
        assert_eq!(q.name(), "GetRuntimeInfo");
    }

    #[test]
    fn event_filter_defaults() {
        let f: EventFilter =
            serde_json::from_value(json!({"namespace": "ns_agjdus24nvyadaareizuivlgo4"})).unwrap();
        assert_eq!(f.after, 0);
        assert!(f.kinds.is_empty());
    }
}
