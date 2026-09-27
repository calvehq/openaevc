//! Wire messages and length-prefixed canonical CBOR framing (spec/extensions.md §Wire).
//!
//! A frame is a 4-byte big-endian length followed by that many bytes of canonical CBOR encoding
//! one message. Frames above the receiver's limit are rejected without reading the body.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use openaevc_protocol::{
    AppliedEffect, CompositionEdge, Digest, EffectProposal, EvaluationVerdict, ExtensionManifest,
    FactValue, Facts, Finding, HostCapability, Metadata, PackId, ResourceRef, VerificationStatus,
    VersionRange,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Error reported across the wire (by the extension or by the host for a host call).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    pub code: String,
    pub message: String,
}

impl WireError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        WireError {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceInput {
    pub digest: Digest,
    pub kind: String,
    pub media_type: String,
    #[serde(with = "openaevc_protocol::b64::serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeMember {
    pub digest: Digest,
    pub pack: PackId,
    pub effects: Vec<AppliedEffect>,
}

/// Operations the host invokes on an extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// Check an effect proposal and its preconditions against effects already applied to the
    /// same resource in this candidate (`prior`, oldest first).
    ValidateEffect {
        effect: EffectProposal,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        prior: Vec<AppliedEffect>,
    },
    /// Apply a validated effect to the candidate; returns the outcome recorded with it.
    ApplyEffect {
        effect: EffectProposal,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        prior: Vec<AppliedEffect>,
    },
    Verify {
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<Value>,
        pack: PackId,
        generation: u64,
        candidate: Digest,
        effects: Vec<AppliedEffect>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        evidence: Vec<EvidenceInput>,
    },
    Evaluate {
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<Value>,
        facts: Facts,
        effects: Vec<AppliedEffect>,
    },
    Compose {
        validator: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<Value>,
        members: Vec<ComposeMember>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        edges: Vec<CompositionEdge>,
    },
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Operation::ValidateEffect { .. } => "validate_effect",
            Operation::ApplyEffect { .. } => "apply_effect",
            Operation::Verify { .. } => "verify",
            Operation::Evaluate { .. } => "evaluate",
            Operation::Compose { .. } => "compose",
        }
    }

    /// Host capabilities an invocation of this operation may be granted at most.
    pub fn allowed_capabilities(&self) -> &'static [HostCapability] {
        use HostCapability::*;
        match self {
            Operation::ValidateEffect { .. } | Operation::Evaluate { .. } => {
                &[ResourceRead, ClockRead]
            }
            Operation::ApplyEffect { .. } => &[
                ResourceRead,
                ResourceWrite,
                ProcessExecute,
                NetworkConnect,
                SecretRead,
                ClockRead,
                EntropyRead,
            ],
            Operation::Verify { .. } => &[
                ResourceRead,
                ProcessExecute,
                NetworkConnect,
                SecretRead,
                ClockRead,
                EntropyRead,
            ],
            Operation::Compose { .. } => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateOutput {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyOutput {
    pub outcome: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyOutput {
    pub status: VerificationStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: Facts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateOutput {
    pub verdict: EvaluationVerdict,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metrics: BTreeMap<String, i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: Facts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionConflict {
    pub a: Digest,
    pub b: Digest,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeOutput {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<CompositionConflict>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: Facts,
}

/// Structured host calls an extension may make during an invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "call", deny_unknown_fields)]
pub enum HostCall {
    /// Effects applied so far to an in-scope resource.
    #[serde(rename = "resource.read")]
    ResourceRead { resource: ResourceRef },
    /// Run a program (no shell) with a timeout; returns exit code and bounded output.
    #[serde(rename = "process.execute")]
    ProcessExecute {
        program: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
        timeout_ms: u64,
    },
    #[serde(rename = "evidence.attach")]
    EvidenceAttach {
        kind: String,
        media_type: String,
        #[serde(with = "openaevc_protocol::b64::serde_bytes")]
        data: Vec<u8>,
    },
    #[serde(rename = "fact.emit")]
    FactEmit { name: String, value: FactValue },
    /// Look up a top-level key of the invocation configuration.
    #[serde(rename = "config.resolve")]
    ConfigResolve { key: String },
    #[serde(rename = "clock.now")]
    ClockNow {},
    #[serde(rename = "entropy.random")]
    EntropyRandom { len: u32 },
    #[serde(rename = "log")]
    Log {
        level: String,
        message: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        fields: Metadata,
    },
}

impl HostCall {
    /// Capability the call requires, if any.
    pub fn required_capability(&self) -> Option<HostCapability> {
        match self {
            HostCall::ResourceRead { .. } => Some(HostCapability::ResourceRead),
            HostCall::ProcessExecute { .. } => Some(HostCapability::ProcessExecute),
            HostCall::ClockNow {} => Some(HostCapability::ClockRead),
            HostCall::EntropyRandom { .. } => Some(HostCapability::EntropyRead),
            _ => None,
        }
    }
}

/// Host → extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostMessage {
    Hello {
        protocol: VersionRange,
        contract: VersionRange,
    },
    Invoke {
        id: u64,
        deadline_ms: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        granted: Vec<HostCapability>,
        operation: Operation,
    },
    HostResult {
        invocation: u64,
        call: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ok: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<WireError>,
    },
    Cancel {
        id: u64,
    },
    Shutdown {},
}

/// Extension → host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionMessage {
    Hello {
        manifest: ExtensionManifest,
        protocol: VersionRange,
        contract: VersionRange,
    },
    HostCall {
        invocation: u64,
        call: u64,
        request: HostCall,
    },
    Result {
        id: u64,
        output: Value,
    },
    Error {
        id: u64,
        error: WireError,
    },
}

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    TooLarge(u32),
    Invalid(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "frame I/O error: {e}"),
            FrameError::TooLarge(n) => write!(f, "frame of {n} bytes exceeds the limit"),
            FrameError::Invalid(m) => write!(f, "invalid frame: {m}"),
        }
    }
}

impl std::error::Error for FrameError {}

pub fn write_frame<W: Write + ?Sized, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = openaevc_canonical::to_canonical(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Reads one frame. `Ok(None)` on clean end-of-stream before a frame starts.
pub fn read_frame<T: Serialize + DeserializeOwned, R: Read + ?Sized>(
    r: &mut R,
    max: usize,
) -> Result<Option<T>, FrameError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    let n = u32::from_be_bytes(len);
    if n as usize > max {
        return Err(FrameError::TooLarge(n));
    }
    let mut body = vec![0u8; n as usize];
    r.read_exact(&mut body).map_err(FrameError::Io)?;
    openaevc_canonical::from_canonical(&body)
        .map(Some)
        .map_err(|e| FrameError::Invalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frame_round_trip() {
        let msg = HostMessage::Cancel { id: 7 };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).unwrap();
        assert_eq!(&buf[..4], &((buf.len() - 4) as u32).to_be_bytes());
        let back: HostMessage = read_frame(&mut buf.as_slice(), 1024).unwrap().unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn clean_eof_is_none_and_truncation_is_error() {
        assert!(read_frame::<HostMessage, _>(&mut [].as_slice(), 1024)
            .unwrap()
            .is_none());
        let mut buf = Vec::new();
        write_frame(&mut buf, &HostMessage::Shutdown {}).unwrap();
        buf.pop();
        assert!(read_frame::<HostMessage, _>(&mut buf.as_slice(), 1024).is_err());
    }

    #[test]
    fn oversized_frames_rejected_before_reading_body() {
        let mut buf = 5000u32.to_be_bytes().to_vec();
        buf.extend(vec![0u8; 10]);
        let e = read_frame::<HostMessage, _>(&mut buf.as_slice(), 1024).unwrap_err();
        assert!(matches!(e, FrameError::TooLarge(5000)));
    }

    #[test]
    fn non_canonical_or_unknown_frames_rejected() {
        let body = openaevc_canonical::encode(&json!({"type": "Explode"})).unwrap();
        let mut buf = (body.len() as u32).to_be_bytes().to_vec();
        buf.extend(body);
        assert!(matches!(
            read_frame::<HostMessage, _>(&mut buf.as_slice(), 1024),
            Err(FrameError::Invalid(_))
        ));
        let mut garbage = 3u32.to_be_bytes().to_vec();
        garbage.extend([0xff, 0xff, 0xff]);
        assert!(matches!(
            read_frame::<HostMessage, _>(&mut garbage.as_slice(), 1024),
            Err(FrameError::Invalid(_))
        ));
    }

    #[test]
    fn operations_are_tagged() {
        let op: Operation = serde_json::from_value(
            json!({"op": "evaluate", "kind": "kv.size", "facts": {}, "effects": []}),
        )
        .unwrap();
        assert!(matches!(op, Operation::Evaluate { .. }));
        assert_eq!(op.name(), "evaluate");
        let call: HostCall = serde_json::from_value(json!({"call": "resource.read", "resource": {"kind": "kv.entry", "locator": "a", "extension": "org.x.y"}})).unwrap();
        assert_eq!(
            call.required_capability(),
            Some(openaevc_protocol::HostCapability::ResourceRead)
        );
    }
}
