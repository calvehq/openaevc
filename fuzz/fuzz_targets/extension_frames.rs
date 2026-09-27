//! The host's frame reader never panics or over-allocates on hostile extension output.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openaevc_extension_contract::wire::{read_frame, ExtensionMessage};

fuzz_target!(|data: &[u8]| {
    let mut r = data;
    while let Ok(Some(_)) = read_frame::<ExtensionMessage, _>(&mut r, 64 * 1024) {}
});
