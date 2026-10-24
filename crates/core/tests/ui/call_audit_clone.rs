// A CallAudit is not Clone, so one call cannot yield two decision records.
use std::collections::BTreeMap;

use chaperone_core::{ArgumentsDigest, AuditTool, CallAudit, CallNumber, RunId, Timestamp};

fn audit(tool: AuditTool) -> CallAudit {
    CallAudit::new(
        RunId::from_bytes([0; 16]),
        CallNumber(1),
        Timestamp::from_unix_millis(0),
        None,
        tool,
        ArgumentsDigest::of(&BTreeMap::new()),
    )
}

fn two_records(tool: AuditTool) {
    let first = audit(tool);
    let _second = first.clone();
}

fn main() {}
