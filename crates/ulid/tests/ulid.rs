//! The ULID text: known values, the order of time, and the parse rules.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::time::Duration;

use chaperone_ulid::Ulid;

/// 1761400000.5 seconds after the Unix epoch.
const NOW: Duration = Duration::from_millis(1_761_400_000_500);

#[test]
fn known_inputs_give_known_ids() {
    assert_eq!(
        Ulid::new(NOW, [0; 10]).as_str(),
        "01K8DSY3ZM0000000000000000"
    );
    assert_eq!(
        Ulid::new(NOW, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).as_str(),
        "01K8DSY3ZM041061050R3GG28A"
    );
    assert_eq!(
        Ulid::new(Duration::ZERO, [0xff; 10]).as_str(),
        "0000000000ZZZZZZZZZZZZZZZZ"
    );
}

#[test]
fn a_later_time_sorts_after_an_earlier_one() {
    let earlier = Ulid::new(NOW, [0xff; 10]);
    let later = Ulid::new(NOW + Duration::from_millis(1), [0; 10]);
    assert!(later > earlier);
}

#[test]
fn a_minted_id_parses_back() {
    let minted = Ulid::mint().unwrap();
    assert_eq!(Ulid::parse(minted.as_str()), Some(minted));
}

#[test]
fn text_that_is_not_an_id_does_not_parse() {
    for bad in [
        "",
        "01K8DSY3ZM000000000000000",
        "01K8DSY3ZM00000000000000000",
        "01k8dsy3zm0000000000000000",
        "01K8DSY3ZM000000000000000I",
        "01K8DSY3ZM000000000000000U",
    ] {
        assert_eq!(Ulid::parse(bad), None, "{bad}");
    }
    assert!(Ulid::parse("01K8DSY3ZM041061050R3GG28A").is_some());
}
