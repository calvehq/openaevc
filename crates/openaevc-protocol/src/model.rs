//! Domain-neutral runtime model: resources, effects, packs, work, executions, principals.
//!
//! Nothing here assumes a particular domain. Resource and effect kinds are namespaced names
//! owned by extensions (for example `kv.entry` / `kv.set`); the runtime only controls whether
//! they may be proposed, validated, applied, recorded and accepted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::{
    AnyId, ChangePackId, Digest, EffectId, ExecutionId, GrantId, LeaseId, NamespaceId,
    ObservationId, PrincipalId, PublicKey, RequestId, RevisionPackId, RuntimeInstanceId, Signature,
    Timestamp, WorkUnitId,
};

/// Namespaced metadata / extension map. Keys MUST be namespaced names (spec/namespace.md).
pub type Metadata = BTreeMap<String, Value>;

// ---------------------------------------------------------------------------------------------
// Pack identity

/// A ChangePack or RevisionPack identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PackId {
    Change(ChangePackId),
    Revision(RevisionPackId),
}

impl PackId {
    pub fn is_revision(&self) -> bool {
        matches!(self, PackId::Revision(_))
    }
}

impl fmt::Display for PackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackId::Change(id) => id.fmt(f),
            PackId::Revision(id) => id.fmt(f),
        }
    }
}

impl fmt::Debug for PackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for PackId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.parse::<AnyId>().map_err(|e| e.to_string())? {
            AnyId::ChangePackId(id) => Ok(PackId::Change(id)),
            AnyId::RevisionPackId(id) => Ok(PackId::Revision(id)),
            other => Err(format!("{other} is not a pack identifier")),
        }
    }
}

impl From<PackId> for AnyId {
    fn from(p: PackId) -> AnyId {
        match p {
            PackId::Change(id) => AnyId::ChangePackId(id),
            PackId::Revision(id) => AnyId::RevisionPackId(id),
        }
    }
}

macro_rules! text_serde {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = std::borrow::Cow::<str>::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

text_serde!(PackId);

/// A node in the Active Change Graph: a typed identifier or an object digest.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeRef {
    Id(AnyId),
    Digest(Digest),
}

impl fmt::Display for NodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeRef::Id(id) => id.fmt(f),
            NodeRef::Digest(d) => d.fmt(f),
        }
    }
}

impl fmt::Debug for NodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for NodeRef {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        if s.starts_with("sha256:") {
            return s
                .parse()
                .map(NodeRef::Digest)
                .map_err(|e: crate::digest::DigestParseError| e.to_string());
        }
        s.parse()
            .map(NodeRef::Id)
            .map_err(|e: crate::id::IdParseError| e.to_string())
    }
}

text_serde!(NodeRef);

impl<T: Into<AnyId>> From<T> for NodeRef {
    fn from(id: T) -> Self {
        NodeRef::Id(id.into())
    }
}

// ---------------------------------------------------------------------------------------------
// Resources and effects

/// Address of a domain resource. The locator is opaque to the runtime and interpreted by the
/// owning extension. Resources are always scoped to the Namespace of the object holding them.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    pub kind: String,
    pub locator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Digest>,
    /// Extension responsible for interpreting this resource kind.
    pub extension: String,
}

/// Registered extension identity bound into provenance and promoted objects.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ExtensionRef {
    pub id: String,
    pub version: String,
    pub manifest_digest: Digest,
}

/// A structured proposed change submitted by a worker through its harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectProposal {
    pub kind: String,
    pub target: ResourceRef,
    /// Extension-defined canonical payload.
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<ResourceRef>,
}

/// Minimum provenance of an execution-affecting artifact (spec/observations.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub actor: PrincipalId,
    pub caller: PrincipalId,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<String>,
    pub harness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<ExtensionRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Digest>,
    pub request_id: RequestId,
    pub pack: PackId,
    pub generation: u64,
    pub execution: ExecutionId,
    pub runtime_instance: RuntimeInstanceId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<Digest>,
}

/// An effect accepted into a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppliedEffect {
    pub id: EffectId,
    pub work_unit: WorkUnitId,
    pub kind: String,
    pub target: ResourceRef,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<ResourceRef>,
    /// Extension-reported application outcome.
    pub outcome: Value,
    pub provenance: Provenance,
}

// ---------------------------------------------------------------------------------------------
// Facts

/// Normalized fact value consumed by policy (spec/policy.md). Untagged in JSON.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum FactValue {
    Bool(bool),
    Int(i64),
    Text(String),
    Set(BTreeSet<String>),
}

pub type Facts = BTreeMap<String, FactValue>;

// ---------------------------------------------------------------------------------------------
// Principals, grants

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalKind {
    Key,
    Runtime,
    Service,
    Actor,
}

/// A registered principal. KEY/RUNTIME/SERVICE principals authenticate with their key; an
/// ACTOR has no key and is acted as by the key principal it is linked to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: PrincipalId,
    pub namespace: NamespaceId,
    pub kind: PrincipalKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_to: Option<PrincipalId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
    pub registered_at: Timestamp,
}

/// New principal description used by `CreateNamespace` and `RegisterPrincipal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewPrincipal {
    pub kind: PrincipalKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_to: Option<PrincipalId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

/// Selects resources a grant applies to. `kind` is an exact kind, `*`, or a `prefix.*`
/// pattern; `locator_prefix` further restricts locators.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ResourceSelector {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator_prefix: Option<String>,
}

/// Unsigned body of a capability grant (spec/capabilities.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantBody {
    pub id: GrantId,
    pub namespace: NamespaceId,
    pub issuer: PrincipalId,
    pub subject: PrincipalId,
    /// Allowed actions: exact names, `*`, or `prefix.*`.
    pub actions: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceSelector>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraints: BTreeMap<String, Value>,
    pub not_before: Timestamp,
    pub expires_at: Timestamp,
    pub delegation_depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Digest>,
    pub nonce: String,
}

/// A grant plus the issuer's Ed25519 signature over `canonical(body)` in the `grant` domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedGrant {
    pub body: GrantBody,
    pub signature: Signature,
}

// ---------------------------------------------------------------------------------------------
// Namespace

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub id: NamespaceId,
    pub created_at: Timestamp,
    pub created_by: PrincipalId,
    pub root_principals: Vec<PrincipalId>,
    /// Mandatory promotion policies; every qualification evaluates all of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mandatory_policies: Vec<Digest>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
}

// ---------------------------------------------------------------------------------------------
// Packs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackState {
    Open,
    Sealed,
    Qualified,
    Promoted,
    Abandoned,
    Quarantined,
}

impl PackState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, PackState::Promoted | PackState::Abandoned)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PackState::Open => "OPEN",
            PackState::Sealed => "SEALED",
            PackState::Qualified => "QUALIFIED",
            PackState::Promoted => "PROMOTED",
            PackState::Abandoned => "ABANDONED",
            PackState::Quarantined => "QUARANTINED",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevisionRelation {
    Amends,
    Supersedes,
    Reverts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevisionInfo {
    pub relation: RevisionRelation,
    /// Digests of the target PromotedPack objects.
    pub targets: Vec<Digest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkUnitState {
    Open,
    Completed,
    Cancelled,
}

/// Generic unit of work. Products may present it as a task, job, action or assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkUnit {
    pub id: WorkUnitId,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<Value>,
    pub state: WorkUnitState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealInfo {
    pub generation: u64,
    pub candidate: Digest,
    pub sealed_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualificationInfo {
    pub generation: u64,
    pub candidate: Digest,
    pub decision: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuarantineInfo {
    pub previous_state: PackState,
    pub reason: String,
    pub by: PrincipalId,
    pub at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromotionInfo {
    pub promoted_pack: Digest,
    pub promotion_record: Digest,
}

/// Mutable pre-promotion work under a stable identity. Every structural change produces a new
/// generation; historical generations stay auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangePack {
    pub id: PackId,
    pub namespace: NamespaceId,
    pub generation: u64,
    pub state: PackState,
    pub created_by: PrincipalId,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_refs: Vec<ResourceRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub work_units: Vec<WorkUnit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_policies: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_bindings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts_with: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<RevisionInfo>,
    /// Effects accepted into the candidate so far (bound to `generation`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_effects: Vec<AppliedEffect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<SealInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<QualificationInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<QuarantineInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<PromotionInfo>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: Metadata,
}

// ---------------------------------------------------------------------------------------------
// Active Change Graph

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActiveEdgeKind {
    DependsOn,
    Blocks,
    Produces,
    Consumes,
    DerivedFrom,
    Verifies,
    Evaluates,
    RevisionOf,
}

impl ActiveEdgeKind {
    /// Edge kinds that must form a DAG.
    pub fn is_dependency(&self) -> bool {
        matches!(self, ActiveEdgeKind::DependsOn | ActiveEdgeKind::Blocks)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveEdge {
    pub from: NodeRef,
    pub to: NodeRef,
    pub kind: ActiveEdgeKind,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: Metadata,
}

// ---------------------------------------------------------------------------------------------
// Execution

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionState {
    Pending,
    Admitted,
    Starting,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Lost,
}

impl ExecutionState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ExecutionState::Succeeded
                | ExecutionState::Failed
                | ExecutionState::Cancelled
                | ExecutionState::Lost
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionState::Pending => "PENDING",
            ExecutionState::Admitted => "ADMITTED",
            ExecutionState::Starting => "STARTING",
            ExecutionState::Running => "RUNNING",
            ExecutionState::Succeeded => "SUCCEEDED",
            ExecutionState::Failed => "FAILED",
            ExecutionState::Cancelled => "CANCELLED",
            ExecutionState::Lost => "LOST",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub id: LeaseId,
    pub execution: ExecutionId,
    pub generation: u64,
    pub provider: String,
    pub expires_at: Timestamp,
    pub heartbeat_interval_ms: u64,
}

/// Registered execution provider (spec/execution.md §Provider contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderDescriptor {
    pub id: String,
    pub version: String,
    pub worker_kinds: Vec<String>,
    pub harnesses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_actions: Vec<String>,
    pub cancellation: bool,
    pub resumable: bool,
    pub heartbeat: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub limits: BTreeMap<String, i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_fields: Vec<String>,
    /// Principal that speaks for the provider (heartbeats, recovery proofs).
    pub principal: PrincipalId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerInfo {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub id: ExecutionId,
    pub namespace: NamespaceId,
    pub pack: PackId,
    pub generation: u64,
    pub work_unit: WorkUnitId,
    pub actor: PrincipalId,
    pub provider: String,
    pub harness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<WorkerInfo>,
    pub state: ExecutionState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_resources: Vec<ResourceSelector>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_effects: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ExtensionRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<Digest>,
    pub timeout_ms: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub budget: BTreeMap<String, i64>,
    pub max_attempts: u32,
    pub attempt: u32,
    pub idempotency_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_of: Option<ExecutionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
    pub request_id: RequestId,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<EffectId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<ObservationId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id<T: std::str::FromStr>(prefix: &str) -> T
    where
        T::Err: std::fmt::Debug,
    {
        format!("{prefix}_agjdus24nvyadaareizuivlgo4")
            .parse()
            .unwrap()
    }

    #[test]
    fn pack_id_accepts_both_pack_kinds() {
        let c: PackId = serde_json::from_value(json!("cpk_agjdus24nvyadaareizuivlgo4")).unwrap();
        assert!(matches!(c, PackId::Change(_)));
        let r: PackId = "rpk_agjdus24nvyadaareizuivlgo4".parse().unwrap();
        assert!(matches!(r, PackId::Revision(_)));
        assert!("exe_agjdus24nvyadaareizuivlgo4".parse::<PackId>().is_err());
    }

    #[test]
    fn states_serialize_screaming() {
        assert_eq!(
            serde_json::to_value(PackState::Qualified).unwrap(),
            json!("QUALIFIED")
        );
        assert_eq!(
            serde_json::to_value(ExecutionState::Lost).unwrap(),
            json!("LOST")
        );
        assert_eq!(
            serde_json::to_value(ActiveEdgeKind::DependsOn).unwrap(),
            json!("DEPENDS_ON")
        );
        assert_eq!(
            serde_json::to_value(PrincipalKind::Actor).unwrap(),
            json!("ACTOR")
        );
    }

    #[test]
    fn fact_values_are_untagged() {
        let f: Facts = serde_json::from_value(json!({
            "a.b": true, "a.c": 3, "a.d": "x", "a.e": ["p", "q"]
        }))
        .unwrap();
        assert_eq!(f["a.b"], FactValue::Bool(true));
        assert_eq!(f["a.c"], FactValue::Int(3));
        assert_eq!(f["a.d"], FactValue::Text("x".into()));
        assert!(matches!(&f["a.e"], FactValue::Set(s) if s.len() == 2));
    }

    #[test]
    fn node_ref_parses_ids_and_digests() {
        let n: NodeRef = "wku_agjdus24nvyadaareizuivlgo4".parse().unwrap();
        assert!(matches!(n, NodeRef::Id(AnyId::WorkUnitId(_))));
        let d: NodeRef = format!("sha256:{}", "0".repeat(64)).parse().unwrap();
        assert!(matches!(d, NodeRef::Digest(_)));
        assert!("nonsense".parse::<NodeRef>().is_err());
    }

    #[test]
    fn resource_ref_rejects_unknown_fields() {
        let ok = json!({"kind": "kv.entry", "locator": "a", "extension": "org.openaevc.kv"});
        serde_json::from_value::<ResourceRef>(ok).unwrap();
        let bad =
            json!({"kind": "kv.entry", "locator": "a", "extension": "org.openaevc.kv", "x": 1});
        assert!(serde_json::from_value::<ResourceRef>(bad).is_err());
    }

    #[test]
    fn terminal_states() {
        assert!(PackState::Promoted.is_terminal());
        assert!(PackState::Abandoned.is_terminal());
        assert!(!PackState::Sealed.is_terminal());
        assert!(ExecutionState::Lost.is_terminal());
        assert!(!ExecutionState::Running.is_terminal());
        let _: ExecutionId = id("exe");
    }
}
