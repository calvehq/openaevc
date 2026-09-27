//! Structured protocol errors (spec/errors.md). Errors are protocol data, not presentation
//! strings; `message` is diagnostic only and MUST NOT contain SQL, filesystem paths, secrets or
//! private keys.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

macro_rules! error_codes {
    ($($variant:ident => $text:literal, $cat:ident, $retry:literal;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
        pub enum ErrorCode {
            $($variant,)*
        }

        impl ErrorCode {
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$variant,)*];

            pub fn as_str(&self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => $text,)*
                }
            }

            pub fn category(&self) -> ErrorCategory {
                match self {
                    $(ErrorCode::$variant => ErrorCategory::$cat,)*
                }
            }

            pub fn retryable(&self) -> bool {
                match self {
                    $(ErrorCode::$variant => $retry,)*
                }
            }
        }
    };
}

error_codes! {
    InvalidArgument => "INVALID_ARGUMENT", Request, false;
    NotFound => "NOT_FOUND", Request, false;
    AlreadyExists => "ALREADY_EXISTS", Request, false;
    Unauthorized => "UNAUTHORIZED", Authority, false;
    Forbidden => "FORBIDDEN", Authority, false;
    CapabilityExpired => "CAPABILITY_EXPIRED", Authority, false;
    CapabilityRevoked => "CAPABILITY_REVOKED", Authority, false;
    ReplayDetected => "REPLAY_DETECTED", Authority, false;
    StaleGeneration => "STALE_GENERATION", Lifecycle, false;
    InvalidTransition => "INVALID_TRANSITION", Lifecycle, false;
    ImmutableObject => "IMMUTABLE_OBJECT", Lifecycle, false;
    Quarantined => "QUARANTINED", Lifecycle, false;
    DependencyCycle => "DEPENDENCY_CYCLE", Graph, false;
    DependencyMissing => "DEPENDENCY_MISSING", Graph, false;
    ExecutionNotReady => "EXECUTION_NOT_READY", Execution, true;
    ExecutionLost => "EXECUTION_LOST", Execution, false;
    ExtensionIncompatible => "EXTENSION_INCOMPATIBLE", Extension, false;
    ExtensionFailed => "EXTENSION_FAILED", Extension, true;
    EvidenceInvalid => "EVIDENCE_INVALID", Qualification, false;
    VerificationFailed => "VERIFICATION_FAILED", Qualification, false;
    PolicyDenied => "POLICY_DENIED", Qualification, false;
    NotQualified => "NOT_QUALIFIED", Qualification, false;
    CompositionInvalid => "COMPOSITION_INVALID", Graph, false;
    Conflict => "CONFLICT", Conflict, true;
    DigestMismatch => "DIGEST_MISMATCH", Integrity, false;
    CanonicalEncodingError => "CANONICAL_ENCODING_ERROR", Integrity, false;
    ProtocolVersionUnsupported => "PROTOCOL_VERSION_UNSUPPORTED", Request, false;
    StorageIntegrityError => "STORAGE_INTEGRITY_ERROR", Integrity, false;
    RecoveryRequired => "RECOVERY_REQUIRED", Internal, false;
    Internal => "INTERNAL", Internal, true;
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCategory {
    Request,
    Authority,
    Lifecycle,
    Graph,
    Execution,
    Extension,
    Qualification,
    Conflict,
    Integrity,
    Internal,
}

/// A lifecycle transition that was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransitionInfo {
    pub from: String,
    pub to: String,
}

/// Error reported by an extension, nested inside `EXTENSION_FAILED`/`EXTENSION_INCOMPATIBLE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtensionErrorInfo {
    pub extension_id: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[serde(deny_unknown_fields)]
#[error("{code}: {message}")]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub category: ErrorCategory,
    pub message: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition: Option<TransitionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_error: Option<ExtensionErrorInfo>,
    /// For `DEPENDENCY_CYCLE`: the minimal cycle, first node repeated at the end.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cycle: Vec<String>,
}

impl ProtocolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            category: code.category(),
            message: message.into(),
            retryable: code.retryable(),
            object_ids: Vec::new(),
            expected_generation: None,
            actual_generation: None,
            missing_action: None,
            transition: None,
            extension_error: None,
            cycle: Vec::new(),
        }
    }

    pub fn with_object(mut self, id: impl ToString) -> Self {
        self.object_ids.push(id.to_string());
        self
    }

    pub fn with_generations(mut self, expected: u64, actual: u64) -> Self {
        self.expected_generation = Some(expected);
        self.actual_generation = Some(actual);
        self
    }

    pub fn with_missing_action(mut self, action: impl Into<String>) -> Self {
        self.missing_action = Some(action.into());
        self
    }

    pub fn with_transition(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.transition = Some(TransitionInfo {
            from: from.into(),
            to: to.into(),
        });
        self
    }

    pub fn with_extension_error(mut self, info: ExtensionErrorInfo) -> Self {
        self.extension_error = Some(info);
        self
    }

    pub fn with_cycle(mut self, cycle: Vec<String>) -> Self {
        self.cycle = cycle;
        self
    }
}

/// Shorthand constructors, e.g. `err::not_found("...")`.
pub mod err {
    use super::{ErrorCode, ProtocolError};

    macro_rules! ctor {
        ($($f:ident => $c:ident),* $(,)?) => {
            $(pub fn $f(msg: impl Into<String>) -> ProtocolError { ProtocolError::new(ErrorCode::$c, msg) })*
        };
    }

    ctor! {
        invalid => InvalidArgument,
        not_found => NotFound,
        exists => AlreadyExists,
        unauthorized => Unauthorized,
        forbidden => Forbidden,
        transition => InvalidTransition,
        immutable => ImmutableObject,
        conflict => Conflict,
        internal => Internal,
        integrity => StorageIntegrityError,
        encoding => CanonicalEncodingError,
        extension_failed => ExtensionFailed,
        extension_incompatible => ExtensionIncompatible,
        composition => CompositionInvalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_serialize_screaming_snake() {
        let json = serde_json::to_string(&ErrorCode::StaleGeneration).unwrap();
        assert_eq!(json, "\"STALE_GENERATION\"");
        assert_eq!(ErrorCode::StaleGeneration.as_str(), "STALE_GENERATION");
        assert_eq!(ErrorCode::ALL.len(), 30);
    }

    #[test]
    fn retryability_and_category_are_derived_from_code() {
        let e = ProtocolError::new(ErrorCode::Conflict, "busy");
        assert!(e.retryable);
        assert_eq!(e.category, ErrorCategory::Conflict);
        let e = ProtocolError::new(ErrorCode::Forbidden, "no");
        assert!(!e.retryable);
        assert_eq!(e.category, ErrorCategory::Authority);
    }

    #[test]
    fn optional_fields_are_omitted_from_json() {
        let e = ProtocolError::new(ErrorCode::NotFound, "missing");
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 4, "{v}");
        let e = e.with_generations(3, 4);
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["expected_generation"], 3);
    }
}
