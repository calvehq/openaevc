//! Runtime aggregate kinds, keys and record types (reference implementation detail).

use openaevc_protocol::{Digest, NamespaceId, SignedGrant};
use serde::{Deserialize, Serialize};

pub(crate) const NAMESPACE: &str = "namespace";
pub(crate) const PRINCIPAL: &str = "principal";
pub(crate) const GRANT: &str = "grant";
pub(crate) const CHECKPOINT: &str = "checkpoint";
pub(crate) const POLICY: &str = "policy";

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
