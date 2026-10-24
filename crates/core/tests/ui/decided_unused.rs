// Ignoring the result of CallAudit::decided is an error.
#![deny(unused_must_use)]

use chaperone_core::{CallAudit, Decision, Timestamp};

fn drop_both(audit: CallAudit) {
    audit.decided(Decision::Allow, Timestamp::from_unix_millis(0));
}

fn main() {}
