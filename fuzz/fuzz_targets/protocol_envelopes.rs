//! Object envelopes, command envelopes and JSON decoding must fail closed without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openaevc_protocol::{CommandEnvelope, QueryEnvelope};

fuzz_target!(|data: &[u8]| {
    let _ = openaevc_core::ImmutableObject::from_bytes(data, None);
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = openaevc_canonical::from_value::<CommandEnvelope>(v.clone());
        let _ = openaevc_canonical::from_value::<QueryEnvelope>(v);
    }
});
