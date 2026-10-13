//! Strict canonical CBOR decoding must never panic, and anything it accepts must re-encode to
//! the identical bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = openaevc::canonical::decode(data) {
        assert_eq!(openaevc::canonical::encode(&v).unwrap(), data);
    }
});
