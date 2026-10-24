//! bolero trial: the strict reader on random bytes. `cargo test` runs it
//! as a property test on stable. `cargo bolero test` runs it under
//! libFuzzer on nightly.

use chaperone_core::strict::{self, ByteCap};

#[test]
fn strict_read_never_panics() {
    bolero::check!().for_each(|data: &[u8]| {
        if strict::read_value(data, ByteCap::new(4096)).is_ok() {
            assert!(serde_json::from_slice::<serde_json::Value>(data).is_ok());
        }
    });
}
