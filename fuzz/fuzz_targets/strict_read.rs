#![no_main]

use chaperone_core::strict::{self, ByteCap};
use libfuzzer_sys::fuzz_target;

const CAP: ByteCap = ByteCap::new(1024 * 1024);

fuzz_target!(|data: &[u8]| {
    // The strict reader must never panic. Every text it accepts must also
    // be plain JSON: strict JSON is a subset.
    if strict::read_value(data, CAP).is_ok() {
        assert!(serde_json::from_slice::<serde_json::Value>(data).is_ok());
    }
});
