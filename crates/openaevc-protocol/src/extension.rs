//! Extension manifests and host capabilities (spec/extensions.md).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Digest, ProtocolVersion, PublicKey, VersionRange};

/// Extension contract version implemented by this crate (versioned independently of the
/// protocol).
pub const CONTRACT_VERSION: ProtocolVersion = ProtocolVersion::new(0, 1, 0);
pub const SUPPORTED_CONTRACT: VersionRange = VersionRange::new(CONTRACT_VERSION, CONTRACT_VERSION);

/// Privileged operations an extension may request through structured host calls.
/// Declarations in a manifest are requests; the runtime grants per invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
pub enum HostCapability {
    #[serde(rename = "resource.read")]
    ResourceRead,
    #[serde(rename = "resource.write")]
    ResourceWrite,
    #[serde(rename = "process.execute")]
    ProcessExecute,
    #[serde(rename = "network.connect")]
    NetworkConnect,
    #[serde(rename = "secret.read")]
    SecretRead,
    #[serde(rename = "clock.read")]
    ClockRead,
    #[serde(rename = "entropy.read")]
    EntropyRead,
}

impl HostCapability {
    pub const ALL: [HostCapability; 7] = [
        HostCapability::ResourceRead,
        HostCapability::ResourceWrite,
        HostCapability::ProcessExecute,
        HostCapability::NetworkConnect,
        HostCapability::SecretRead,
        HostCapability::ClockRead,
        HostCapability::EntropyRead,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceKindDecl {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectKindDecl {
    pub kind: String,
    pub resource_kind: String,
    /// Authority actions the actor must hold on the target resource to propose this effect.
    pub required_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Entrypoint {
    /// Executable path relative to the extension directory it was registered from.
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtensionManifest {
    /// Reverse-DNS stable identifier, e.g. `org.openaevc.reference.kv`.
    pub id: String,
    /// SemVer of the extension implementation.
    pub version: String,
    pub protocol: VersionRange,
    pub contract: VersionRange,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<PublicKey>,
    /// SHA-256 of the extension executable/artifact.
    pub artifact_digest: Digest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_kinds: Vec<ResourceKindDecl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effect_kinds: Vec<EffectKindDecl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluator_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub composition_validators: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_capabilities: Vec<HostCapability>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub schemas: BTreeMap<String, Digest>,
    pub execution_modes: Vec<String>,
    pub entrypoint: Entrypoint,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn host_capabilities_use_dotted_names() {
        assert_eq!(serde_json::to_value(HostCapability::ProcessExecute).unwrap(), json!("process.execute"));
        let c: HostCapability = serde_json::from_value(json!("resource.read")).unwrap();
        assert_eq!(c, HostCapability::ResourceRead);
    }
}
