//! Example flows behind the runnable examples in this directory. Each function is exercised by
//! `tests/examples.rs`, so the examples cannot silently rot.
#![forbid(unsafe_code)]

pub mod authority_flow;
pub mod baseline_composition;
pub mod common;
pub mod custom_extension;
pub mod embedded_runtime;
pub mod execute_verify_promote;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
