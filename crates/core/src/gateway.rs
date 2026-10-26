//! The values that cross the front door: the tools an app sees, the
//! outcome of one call and the faults. A front door plugin turns each
//! request into a call of the `Gateway` trait in `hook.rs`, and turns the
//! answer back into its own protocol. It decides nothing
//! (`plugins/adapter/AGENTS.md`).

use std::collections::BTreeMap;

use crate::decide::{DenyReason, GateId};
use crate::exposed::ExposedName;
use crate::value::ArgValue;

/// One tool in the list that an app sees.
#[derive(Debug, Clone, PartialEq)]
pub struct ListedTool {
    pub name: ExposedName,
    pub description: Option<String>,
    /// The JSON Schema of the tool's arguments, as the upstream states it.
    pub input_schema: BTreeMap<String, ArgValue>,
}

/// Why chaperone could not run an allowed call, or could not decide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallFault {
    /// The requested name is not a valid exposed name.
    UnknownTool,
    /// The upstream of an allowed call is not running.
    NotConnected,
    /// The call needs an approval, and no approval channel can answer yet.
    NoApprovalChannel,
    /// The decision did not return inside the bound that the `chaperone`
    /// program sets, or did not return at all (G2).
    NoDecision,
    /// chaperone could not write an audit record. It did not run the call or
    /// return its result (G6).
    AuditFailed,
    /// A lock of the call path is poisoned. chaperone refuses every call
    /// until it restarts (G2).
    Halted,
    /// The upstream did not answer inside the bound of `docs/design.md`
    /// 5.5 (G2).
    UpstreamTimeout,
    /// The upstream answered with a result that fails the check of
    /// `docs/design.md` 7.7.
    BadResult,
    /// The approval channel denied the gate inside the wait window
    /// (`docs/design.md` 5.3).
    ApprovalDenied,
    /// The approval channel answered with something that is not an answer,
    /// or did not answer in the life of the gate (`docs/design.md` 5.3).
    ApprovalFault,
}

impl CallFault {
    /// A stable code for an app and for the audit file.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownTool => "unknown_tool",
            Self::NotConnected => "not_connected",
            Self::NoApprovalChannel => "no_approval_channel",
            Self::NoDecision => "no_decision",
            Self::AuditFailed => "audit_failed",
            Self::Halted => "halted",
            Self::UpstreamTimeout => "upstream_timeout",
            Self::BadResult => "bad_result",
            Self::ApprovalDenied => "approval_denied",
            Self::ApprovalFault => "approval_fault",
        }
    }
}

/// The checked result of a call that an upstream ran (`docs/design.md`
/// 7.7): text blocks only, each secret value blanked, the upstream's error
/// flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamResult {
    pub content: Vec<String>,
    pub is_error: bool,
}

/// The answer to one tool call.
#[derive(Debug, Clone)]
pub enum CallOutcome {
    /// The upstream ran the call. The `ran` record is durable (G6).
    Ran(UpstreamResult),
    /// The decision denied the call.
    Denied(DenyReason),
    /// The call waits for an approval. Call again with the same arguments.
    Waiting(GateId),
    /// chaperone could not run the call.
    Failed(CallFault),
}

/// Whether chaperone can decide a call now (`docs/design.md` 7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// A valid policy is loaded.
    Serving,
    /// No valid policy is loaded, so every call is denied (G2).
    PolicyNotLoaded,
}

/// Why chaperone refuses to list tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    #[error("the credentials resolve to no app instance")]
    UnknownCredential,
    #[error("no valid policy is loaded")]
    PolicyNotLoaded,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn each_fault_has_its_own_code() {
        let faults = [
            CallFault::UnknownTool,
            CallFault::NotConnected,
            CallFault::NoApprovalChannel,
            CallFault::NoDecision,
            CallFault::AuditFailed,
            CallFault::Halted,
            CallFault::UpstreamTimeout,
            CallFault::BadResult,
            CallFault::ApprovalDenied,
            CallFault::ApprovalFault,
        ];
        let codes: BTreeSet<&str> = faults.iter().map(|fault| fault.code()).collect();
        assert_eq!(codes.len(), faults.len());
        assert_eq!(CallFault::NoDecision.code(), "no_decision");
    }
}
