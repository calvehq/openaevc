//! Runtime aggregate kinds, keys and record types (reference implementation detail).

use openaevc_protocol::{Digest, NamespaceId, SignedGrant};
use serde::{Deserialize, Serialize};

pub(crate) const NAMESPACE: &str = "namespace";
pub(crate) const PRINCIPAL: &str = "principal";
pub(crate) const GRANT: &str = "grant";
pub(crate) const CHECKPOINT: &str = "checkpoint";
pub(crate) const POLICY: &str = "policy";
pub(crate) const PACK: &str = "pack";
pub(crate) const PACK_GENERATION: &str = "pack_gen";
pub(crate) const EDGES: &str = "edges";
pub(crate) const WORK_UNIT: &str = "wu";
/// Active (non-terminal) execution per work unit.
pub(crate) const WU_EXECUTION: &str = "wu_exec";
pub(crate) const EXTENSION: &str = "extension";
pub(crate) const PROVIDER: &str = "provider";
pub(crate) const EXECUTION: &str = "execution";
/// Non-terminal executions of a Namespace (lease sweep index).
pub(crate) const ACTIVE_EXECUTIONS: &str = "active_exe";
pub(crate) const EXECUTION_IDEMPOTENCY: &str = "exe_idem";

pub(crate) fn generation_key(
    ns: &NamespaceId,
    pack: impl std::fmt::Display,
    generation: u64,
) -> String {
    format!("{ns}/{pack}/{generation:020}")
}

/// Key of a Namespace-scoped aggregate.
pub(crate) fn key(ns: &NamespaceId, id: impl std::fmt::Display) -> String {
    format!("{ns}/{id}")
}

pub(crate) fn prefix(ns: &NamespaceId) -> String {
    format!("{ns}/")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GrantRecord {
    pub digest: Digest,
    pub grant: SignedGrant,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CheckpointRecord {
    pub digest: Digest,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExtensionRecord {
    pub manifest: openaevc_protocol::ExtensionManifest,
    pub manifest_digest: Digest,
    /// Absolute path of the registered executable (never given to extensions or clients).
    pub program: String,
    pub approved: Vec<openaevc_protocol::HostCapability>,
    pub active: bool,
    pub registered_at: openaevc_protocol::Timestamp,
}

impl ExtensionRecord {
    pub fn reference(&self) -> openaevc_protocol::ExtensionRef {
        openaevc_protocol::ExtensionRef {
            id: self.manifest.id.clone(),
            version: self.manifest.version.clone(),
            manifest_digest: self.manifest_digest,
        }
    }
}
