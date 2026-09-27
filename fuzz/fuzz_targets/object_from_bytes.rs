//! Any bytes accepted as an immutable object re-validate identically: same digest, same bytes,
//! and references resolve without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openaevc_core::ImmutableObject;

fuzz_target!(|data: &[u8]| {
    if let Ok(o) = ImmutableObject::from_bytes(data, None) {
        assert_eq!(o.bytes(), data);
        let again = ImmutableObject::from_bytes(o.bytes(), Some(o.digest())).unwrap();
        assert_eq!(again.digest(), o.digest());
        let _ = o.references();
    }
});
