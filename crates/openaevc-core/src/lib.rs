//! Reusable OpenAEVC protocol mechanisms (no async runtime, no storage).
#![forbid(unsafe_code)]

pub mod clock;
pub mod events;
pub mod lifecycle;
pub mod names;
pub mod object;
pub mod request;

pub use clock::{
    Clock, FixedClock, FromUuid, IdGenerator, IdGeneratorExt, SequentialIds, SystemClock, UuidV7Ids,
};
pub use object::{sign_envelope, signing_digest, validate_body, ImmutableObject};
