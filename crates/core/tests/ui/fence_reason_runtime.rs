// A fence reason is fixed plugin text. It cannot come from an argument.
use chaperone_core::FenceReason;

fn reason_from(argument: &str) -> FenceReason {
    let text = format!("bad value {argument}");
    FenceReason::new(&text)
}

fn main() {}
