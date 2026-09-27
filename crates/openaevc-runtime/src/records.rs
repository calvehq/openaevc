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
