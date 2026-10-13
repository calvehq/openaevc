//! OpenAEVC: the open protocol and reference runtime for controlled change.
//!
//! One crate, one module per architectural layer. A module only uses modules below it, so
//! each can be split back into its own crate without changing its API:
//!
//! | Layer | Modules | Feature |
//! | ----- | ------- | ------- |
//! | 0 | [`protocol`] — identifiers, digests, objects, commands, queries, events, errors | always |
//! | 1 | [`canonical`] — deterministic CBOR; [`crypto`] — SHA-256 digests, Ed25519 signatures | always |
//! | 2 | [`core`] — immutable object envelopes, validation, events, clocks, IDs | always |
//! | 3 | [`authority`], [`policy`], [`extension`] (Extension Contract) | always |
//! | 3 | `store` — store traits, in-memory and SQLite + CAS backends | `store` |
//! | 4 | [`execution`], [`verification`], [`composition`] | always |
//! | 5 | `runtime` — the sole authoritative mutation boundary | `runtime` |
//! | 6 | `transport` — HTTP server and client, SSE, TLS | `transport` |
//!
//! The default build has no async runtime, storage engine or HTTP stack. `full` enables
//! every module. Features never change protocol semantics: they only add modules.
#![forbid(unsafe_code)]

pub mod protocol;

pub mod canonical;
pub mod crypto;

pub mod core;

pub mod authority;
pub mod extension;
pub mod policy;
#[cfg(feature = "store")]
pub mod store;

pub mod composition;
pub mod execution;
pub mod verification;

#[cfg(feature = "runtime")]
pub mod runtime;

#[cfg(feature = "transport")]
pub mod transport;
