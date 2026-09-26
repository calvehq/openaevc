//! Pure OpenAEVC protocol types. No I/O, no async runtime, no storage.
#![forbid(unsafe_code)]

pub mod api;
pub mod digest;
pub mod error;
pub mod extension;
pub mod id;
pub mod keys;
pub mod model;
pub mod objects;
pub mod policy;
mod schema;
pub mod time;
pub mod version;

pub use api::*;
pub use digest::Digest;
pub use error::{err, ErrorCategory, ErrorCode, ExtensionErrorInfo, ProtocolError, TransitionInfo};
pub use extension::*;
pub use id::*;
pub use keys::{b64, PublicKey, Signature, SignatureEntry};
pub use model::*;
pub use objects::*;
pub use policy::*;
pub use time::{Sequence, Timestamp};
pub use version::{ProtocolVersion, VersionRange, PROTOCOL_VERSION, SUPPORTED_PROTOCOL};
