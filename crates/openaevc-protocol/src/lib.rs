//! Pure OpenAEVC protocol types. No I/O, no async runtime, no storage.
#![forbid(unsafe_code)]

pub mod version;

pub use version::{ProtocolVersion, VersionRange, PROTOCOL_VERSION, SUPPORTED_PROTOCOL};
