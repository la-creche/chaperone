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
use crate::mcp::{ProtocolVersion, ResultError, ResultSchemas};
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

/// The result an upstream returned for one call: an MCP `CallToolResult`
/// of the protocol version that the upstream negotiated, as strict JSON
/// text. [`ToolOutput::read`] checks it against the official schema of that
/// version, so a value of this type is a valid result. chaperone passes it
/// on unchanged, except that it blanks each exact secret value (G9).
#[derive(Clone)]
pub struct ToolOutput {
    raw: Box<RawValue>,
    version: ProtocolVersion,
    is_error: bool,
}

/// Shows the version, the error flag and the size, never the result text,
/// because the result can hold a secret before redaction (G9).
impl std::fmt::Debug for ToolOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolOutput")
            .field("version", &self.version)
            .field("is_error", &self.is_error)
            .field("bytes", &self.raw.get().len())
            .finish()
    }
}

/// The largest upstream result chaperone passes on.
pub const OUTPUT_CAP: ByteCap = ByteCap::new(4 * 1024 * 1024);

/// Why an upstream result is not valid. The call then fails (G2). Neither
/// variant holds text from the result (G9).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutputError {
    #[error("the upstream result is not strict JSON: {0}")]
    Read(#[from] StrictError),
    #[error("the upstream result is not valid: {0}")]
    Schema(#[from] ResultError),
    /// The schema allows any `resultType` string. The spec says only
    /// `complete` means the result holds the final content. chaperone
    /// refuses any other value, and refuses a missing value where the
    /// version requires one.
    #[error("not_complete: the upstream result is not a complete result")]
    NotComplete,
}

impl ToolOutput {
    /// Read an upstream result and check it against the `CallToolResult`
    /// schema of `version`.
    ///
    /// # Errors
    ///
    /// Returns an [`OutputError`] when the bytes are not strict JSON, or
    /// break the schema.
    pub fn read(
        bytes: &[u8],
        version: ProtocolVersion,
        schemas: &ResultSchemas,
    ) -> Result<Self, OutputError> {
        let raw: Box<RawValue> = strict::read(bytes, OUTPUT_CAP)?;
        let value: serde_json::Value =
            serde_json::from_str(raw.get()).map_err(|error| StrictError::shape(&error))?;
        schemas.check(version, &value)?;
        let complete = match value.get("resultType") {
            Some(result_type) => result_type.as_str() == Some("complete"),
            None => version != ProtocolVersion::V2026_07_28,
        };
        if !complete {
            return Err(OutputError::NotComplete);
        }
        // The schema makes `isError` a boolean when it is present.
        let is_error = value
            .get("isError")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        Ok(Self {
            raw,
            version,
            is_error,
        })
    }

    /// The result as JSON text.
    #[must_use]
    pub fn as_json(&self) -> &str {
        self.raw.get()
    }

    /// The protocol version of the result.
    #[must_use]
    pub fn version(&self) -> ProtocolVersion {
        self.version
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

    const SECRET: &str = "tok_live_do_not_log_this";

    fn schemas() -> ResultSchemas {
        ResultSchemas::compile().unwrap()
    }

    fn read(version: ProtocolVersion, text: &str) -> Result<ToolOutput, OutputError> {
        ToolOutput::read(text.as_bytes(), version, &schemas())
    }

    const TEXT: &str = r#"{"type":"text","text":"done"}"#;
    const IMAGE: &str = r#"{"type":"image","data":"aGk=","mimeType":"image/png"}"#;
    const AUDIO: &str = r#"{"type":"audio","data":"aGk=","mimeType":"audio/wav"}"#;
    const LINK: &str = r#"{"type":"resource_link","uri":"file:///a","name":"a"}"#;
    const EMBEDDED: &str = r#"{"type":"resource","resource":{"uri":"file:///a","text":"body"}}"#;

    fn result(version: ProtocolVersion, content: &str, extra: &str) -> String {
        let result_type = match version {
            ProtocolVersion::V2026_07_28 => r#","resultType":"complete""#,
            ProtocolVersion::V2025_06_18 | ProtocolVersion::V2025_11_25 => "",
        };
        format!(r#"{{"content":[{content}]{result_type}{extra}}}"#)
    }

    #[test]
    fn every_content_variant_passes_in_every_version() {
        for version in ProtocolVersion::ALL {
            for block in [TEXT, IMAGE, AUDIO, LINK, EMBEDDED] {
                let text = result(version, block, "");
                assert!(read(version, &text).is_ok(), "{version}: {text}");
            }
        }
    }

    #[test]
    fn the_error_flag_is_read() {
        let version = ProtocolVersion::V2026_07_28;
        let output = read(version, &result(version, TEXT, r#","isError":true"#)).unwrap();
        assert!(output.is_error());
        let output = read(version, &result(version, TEXT, "")).unwrap();
        assert!(!output.is_error());
    }

    #[test]
    fn structured_content_follows_each_version() {
        // 2026-07-28: any JSON value. Older versions: an object only.
        let new = ProtocolVersion::V2026_07_28;
        for value in ["[1,2]", "7", "\"text\"", "null", "{\"a\":1}"] {
            let text = result(new, "", &format!(r#","structuredContent":{value}"#));
            assert!(read(new, &text).is_ok(), "{text}");
        }
        for old in [ProtocolVersion::V2025_06_18, ProtocolVersion::V2025_11_25] {
            let object = result(old, "", r#","structuredContent":{"a":1}"#);
            assert!(read(old, &object).is_ok(), "{object}");
            let array = result(old, "", r#","structuredContent":[1,2]"#);
            assert!(read(old, &array).is_err(), "{array}");
        }
    }

    #[test]
    fn refuses_a_value_that_is_not_a_result() {
        for version in ProtocolVersion::ALL {
            for bad in [
                "null".to_owned(),
                "[]".to_owned(),
                "7".to_owned(),
                "{}".to_owned(),
                r#"{"content":{}}"#.to_owned(),
                result(version, r#"{"type":"video"}"#, ""),
                result(version, r#"{"type":"text"}"#, ""),
                result(version, r#"{"type":"resource_link","uri":"file:///a"}"#, ""),
                result(version, r#"{"type":"resource","resource":{}}"#, ""),
                result(version, TEXT, r#","isError":"yes""#),
            ] {
                assert!(
                    matches!(read(version, &bad), Err(OutputError::Schema(_))),
                    "{version}: {bad} should be refused"
                );
            }
        }
        assert!(matches!(
            read(ProtocolVersion::V2026_07_28, "{"),
            Err(OutputError::Read(_))
        ));
    }

    #[test]
    fn only_a_complete_result_type_passes() {
        let version = ProtocolVersion::V2026_07_28;
        // The schema requires the field in 2026-07-28.
        assert!(matches!(
            read(version, r#"{"content":[]}"#),
            Err(OutputError::Schema(_))
        ));
        let other = r#"{"content":[],"resultType":"input_required"}"#;
        assert_eq!(
            read(ProtocolVersion::V2026_07_28, other).unwrap_err(),
            OutputError::NotComplete
        );
        // Versions before 2026-07-28 do not define resultType at all.
        for old in [ProtocolVersion::V2025_06_18, ProtocolVersion::V2025_11_25] {
            assert!(matches!(read(old, other), Err(OutputError::Schema(_))));
        }
        // Older versions have no resultType, so absent means complete.
        assert!(read(ProtocolVersion::V2025_06_18, r#"{"content":[]}"#).is_ok());
    }

    #[test]
    fn debug_never_shows_result_text() {
        let version = ProtocolVersion::V2025_06_18;
        let text = format!(r#"{{"content":[{{"type":"text","text":"{SECRET}"}}]}}"#);
        let output = read(version, &text).unwrap();
        assert!(!format!("{output:?}").contains(SECRET), "{output:?}");
        let outcome = CallOutcome::Ran(output);
        assert!(!format!("{outcome:?}").contains(SECRET), "{outcome:?}");
    }

    #[test]
    fn an_unknown_top_level_field_is_refused() {
        for version in ProtocolVersion::ALL {
            let text = result(version, TEXT, r#","unexpected":true"#);
            assert!(
                matches!(read(version, &text), Err(OutputError::Schema(_))),
                "{version}"
            );
        }
    }

    #[test]
    fn an_error_never_shows_result_text() {
        let version = ProtocolVersion::V2026_07_28;
        for bad in [
            format!(r#"{{"content":[],"resultType":"{SECRET}"}}"#),
            format!(r#"{{"content":[{{"type":"{SECRET}"}}],"resultType":"complete"}}"#),
            format!(r#"{{"content":[],"resultType":"complete","isError":"{SECRET}"}}"#),
            format!(r#"{{"{SECRET}": 1, "{SECRET}": 2}}"#),
        ] {
            let error = read(version, &bad).unwrap_err();
            assert!(!error.to_string().contains(SECRET), "{error}");
            assert!(!format!("{error:?}").contains(SECRET), "{error:?}");
        }
    }
}
