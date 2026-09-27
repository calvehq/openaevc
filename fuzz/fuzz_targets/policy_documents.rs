//! Arbitrary policy documents validate or fail closed; valid ones evaluate deterministically.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openaevc_protocol::{Digest, Facts, PolicyDocument};

fuzz_target!(|data: &[u8]| {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else { return };
    let Ok(doc) = openaevc_canonical::from_value::<PolicyDocument>(v) else { return };
    if openaevc_policy::validate(&doc).is_ok() {
        let facts = Facts::new();
        let a = openaevc_policy::evaluate(&[(Digest::ZERO, &doc)], &facts);
        let b = openaevc_policy::evaluate(&[(Digest::ZERO, &doc)], &facts);
        assert_eq!(a, b);
    }
});
