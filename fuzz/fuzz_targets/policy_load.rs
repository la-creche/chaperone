#![no_main]

use std::sync::OnceLock;

use chaperone_core::{Policy, Setup};
use libfuzzer_sys::fuzz_target;

static SETUP: OnceLock<Option<Setup>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let Some(setup) = SETUP.get_or_init(chaperone_fuzz::setup) else {
        panic!("the fixture setup does not resolve");
    };
    let _ = Policy::load(data, setup, &[]);
});
