//! OpenAEVC Extension Contract (spec/extensions.md): wire messages and framing, the reference
//! process host used by the runtime, and a helper for writing extensions in Rust.
#![forbid(unsafe_code)]

pub mod host;
pub mod server;
pub mod wire;
