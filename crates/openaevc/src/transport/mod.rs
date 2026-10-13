//! OpenAEVC daemon transport (spec/transport.md).
//!
//! The server exposes exactly the runtime's command/query/event surface; it never makes
//! authorization decisions itself. Every request carries a signed envelope that the runtime
//! admits through the same path embedded callers use.
#![forbid(unsafe_code)]

pub mod client;
pub mod openapi;
pub mod server;

/// Header carrying a base64url canonical-CBOR signed envelope for GET/PUT endpoints.
pub const ENVELOPE_HEADER: &str = "openaevc-envelope";
pub const CBOR: &str = "application/cbor";
pub const JSON: &str = "application/json";

use crate::protocol::{ErrorCode, ProtocolError};

/// HTTP status for a protocol error code.
pub fn status_for(code: ErrorCode) -> u16 {
    use ErrorCode::*;
    match code {
        InvalidArgument
        | CanonicalEncodingError
        | ProtocolVersionUnsupported
        | DigestMismatch
        | EvidenceInvalid => 400,
        Unauthorized => 401,
        Forbidden | CapabilityExpired | CapabilityRevoked => 403,
        NotFound => 404,
        AlreadyExists | Conflict | StaleGeneration | ReplayDetected | InvalidTransition
        | ImmutableObject | Quarantined | DependencyCycle | DependencyMissing
        | ExecutionNotReady | ExecutionLost | NotQualified | CompositionInvalid | PolicyDenied
        | VerificationFailed => 409,
        ExtensionIncompatible => 422,
        ExtensionFailed => 502,
        StorageIntegrityError | RecoveryRequired => 503,
        Internal => 500,
    }
}

pub(crate) fn transport_error(msg: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ErrorCode::Internal, format!("transport: {}", msg.into()))
}
