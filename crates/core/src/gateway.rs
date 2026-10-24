//! The contract between a front door and chaperone. A front door plugin
//! receives an app's connection, turns each request into a [`Gateway`]
//! call, and turns the answer back into its own protocol. It decides
//! nothing (`plugins/adapter/AGENTS.md`).

use std::collections::BTreeMap;
use std::future::Future;

use crate::decide::{DenyReason, GateId};
use crate::exposed::ExposedName;
use crate::hook::Credentials;
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
        }
    }
}

/// The answer to one tool call. Build step 5 adds `Ran`, with the checked
/// upstream result.
#[derive(Debug, Clone)]
pub enum CallOutcome {
    /// The decision denied the call.
    Denied(DenyReason),
    /// The call waits for an approval. Call again with the same arguments.
    Waiting(GateId),
    /// chaperone could not run the call.
    Failed(CallFault),
}

/// Why chaperone refuses to list tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    #[error("the credentials resolve to no app instance")]
    UnknownCredential,
    #[error("no valid policy is loaded")]
    PolicyNotLoaded,
}

/// What a front door calls. chaperone implements it.
pub trait Gateway: Send + Sync + 'static {
    /// The tools that these credentials may see.
    fn list_tools(
        &self,
        credentials: &Credentials<'_>,
    ) -> impl Future<Output = Result<Vec<ListedTool>, ListError>> + Send;

    /// Decide and, if allowed, run one call. `name` is the exposed name as
    /// the app sent it.
    fn call_tool(
        &self,
        credentials: &Credentials<'_>,
        name: &str,
        arguments: BTreeMap<String, ArgValue>,
    ) -> impl Future<Output = CallOutcome> + Send;
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
        ];
        let codes: BTreeSet<&str> = faults.iter().map(|fault| fault.code()).collect();
        assert_eq!(codes.len(), faults.len());
        assert_eq!(CallFault::NoDecision.code(), "no_decision");
    }
}
