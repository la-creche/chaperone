//! The contract between a front door and chaperone. A front door plugin
//! receives an app's connection, turns each request into a [`Gateway`]
//! call, and turns the answer back into its own protocol. It decides
//! nothing (`plugins/adapter/AGENTS.md`).

use std::collections::BTreeMap;
use std::future::Future;

use serde::Deserialize;
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
/// as strict JSON text. [`ToolOutput::read`] checks the shape, so a value
/// of this type is a valid result. chaperone passes it on unchanged, except
/// that it blanks each exact secret value (G9).
#[derive(Debug, Clone)]
pub struct ToolOutput {
    raw: Box<RawValue>,
    is_error: bool,
}

/// The largest upstream result chaperone passes on.
pub const OUTPUT_CAP: ByteCap = ByteCap::new(4 * 1024 * 1024);

/// Why an upstream result is not a valid `CallToolResult`. The call then
/// fails (G2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutputError {
    #[error("the upstream result is not strict JSON: {0}")]
    Read(#[from] StrictError),
    #[error("the upstream result is not an MCP CallToolResult: {0}")]
    Shape(String),
}

/// The parts of a `CallToolResult` that chaperone checks. An unknown
/// top-level field is refused, so a result of a newer protocol fails
/// instead of passing unread.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultShape {
    #[serde(rename = "content")]
    _content: Vec<ContentShape>,
    #[serde(rename = "isError", default)]
    is_error: Option<bool>,
    #[serde(rename = "structuredContent", default)]
    _structured_content: Option<BTreeMap<String, serde::de::IgnoredAny>>,
    #[serde(rename = "_meta", default)]
    _meta: Option<BTreeMap<String, serde::de::IgnoredAny>>,
    #[serde(rename = "resultType", default)]
    _result_type: Option<ResultType>,
}

/// Only a complete result runs a call. An `input_required` result asks the
/// app for input, and chaperone does not pass that through yet.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResultType {
    Complete,
}

/// One content block. The tag must be a known type, and the fields that
/// the type needs must be present.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[expect(dead_code, reason = "the fields exist only to check the shape")]
enum ContentShape {
    Text {
        text: String,
    },
    Image {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    Audio {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    Resource {
        resource: BTreeMap<String, serde::de::IgnoredAny>,
    },
    ResourceLink {
        uri: String,
    },
}

impl ToolOutput {
    /// Read and check an upstream result.
    ///
    /// # Errors
    ///
    /// Returns an [`OutputError`] when the bytes are not strict JSON, or
    /// not an MCP `CallToolResult`.
    pub fn read(bytes: &[u8]) -> Result<Self, OutputError> {
        let raw: Box<RawValue> = strict::read(bytes, OUTPUT_CAP)?;
        let shape: ResultShape = serde_json::from_str(raw.get())
            .map_err(|error| OutputError::Shape(error.to_string()))?;
        Ok(Self {
            raw,
            is_error: shape.is_error.unwrap_or(false),
        })
    }

    /// The result as JSON text.
    #[must_use]
    pub fn as_json(&self) -> &str {
        self.raw.get()
    }

    /// The upstream's own error flag. The audit records it.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.is_error
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
    /// chaperone could not write an audit record, so it did not run the call or return its result (G6).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Result<ToolOutput, OutputError> {
        ToolOutput::read(text.as_bytes())
    }

    #[test]
    fn reads_a_valid_result_and_its_error_flag() {
        let ok = read(r#"{"content":[{"type":"text","text":"done"}]}"#).unwrap();
        assert!(!ok.is_error());
        let failed = read(
            r#"{"content":[{"type":"text","text":"no"}],"isError":true,"resultType":"complete",
                "structuredContent":{"a":1},"_meta":{}}"#,
        )
        .unwrap();
        assert!(failed.is_error());
    }

    #[test]
    fn refuses_a_value_that_is_not_a_result() {
        for bad in [
            "null",
            "[]",
            "{}",
            r#"{"content":{}}"#,
            r#"{"content":[{"type":"video"}]}"#,
            r#"{"content":[{"type":"text"}]}"#,
            r#"{"content":[],"extra":1}"#,
            r#"{"content":[],"resultType":"input_required"}"#,
            r#"{"content":[],"isError":"yes"}"#,
        ] {
            assert!(
                matches!(read(bad), Err(OutputError::Shape(_))),
                "{bad} should be refused"
            );
        }
        assert!(matches!(read("{"), Err(OutputError::Read(_))));
    }
}
