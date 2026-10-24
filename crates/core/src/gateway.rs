//! The contract between a front door and chaperone. A front door plugin
//! receives an app's connection, turns each request into a [`Gateway`]
//! call, and turns the answer back into its own protocol. It decides
//! nothing (`plugins/adapter/AGENTS.md`).

use std::collections::BTreeMap;
use std::future::Future;

use serde_json::value::RawValue;

use crate::decide::{DenyReason, GateId};
use crate::exposed::ExposedName;
use crate::hook::Credentials;
use crate::strict::{self, ByteCap, StrictError};
use crate::value::ArgValue;

/// One tool in the list that an app sees.
#[derive(Debug, Clone, PartialEq)]
pub struct ListedTool {
    pub name: ExposedName,
    pub description: Option<String>,
    /// The JSON Schema of the tool's arguments, as the upstream states it.
    pub input_schema: BTreeMap<String, ArgValue>,
}

/// The result an upstream returned for one call: an MCP `CallToolResult`,
/// as strict JSON text. chaperone passes it on unchanged, except that it
/// blanks each exact secret value (G9).
#[derive(Debug, Clone)]
pub struct ToolOutput(Box<RawValue>);

/// The largest upstream result chaperone passes on.
pub const OUTPUT_CAP: ByteCap = ByteCap::new(4 * 1024 * 1024);

impl ToolOutput {
    /// Read an upstream result.
    ///
    /// # Errors
    ///
    /// Returns a [`StrictError`] when the bytes are not strict JSON.
    pub fn read(bytes: &[u8]) -> Result<Self, StrictError> {
        strict::read(bytes, OUTPUT_CAP).map(Self)
    }

    /// The result as JSON text.
    #[must_use]
    pub fn as_json(&self) -> &str {
        self.0.get()
    }
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
    /// chaperone could not write the audit line, so it did not run the call (G6).
    AuditFailed,
}

impl CallFault {
    /// A stable code for an app and for the audit file.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownTool => "unknown_tool",
            Self::NotConnected => "not_connected",
            Self::NoApprovalChannel => "no_approval_channel",
            Self::AuditFailed => "audit_failed",
        }
    }
}

/// The answer to one tool call.
#[derive(Debug, Clone)]
pub enum CallOutcome {
    /// The call ran. The upstream's result.
    Ran(ToolOutput),
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
