//! The audit records and the audit-sink hook (G6).
//!
//! chaperone writes two records for a call that it decides: a `Decided`
//! record before it runs the call, and a final `Ran` or `Failed` record
//! before it returns. A call that fails before a decision has one `Failed`
//! record. The run ID and the call number together match the records of one
//! call, also across restarts that append to the same file.
//!
//! A record never holds a secret, a token or any text the app chose (G9).
//! The app chooses the tool name and the arguments. A record keeps a tool
//! name only when the policy configures that tool ([`AuditTool`]). It keeps
//! a SHA-256 of the arguments, never their values.

use std::collections::BTreeMap;
use std::fmt;

use crate::decide::Decision;
use crate::exposed::ExposedName;
use crate::gateway::CallFault;
use crate::ids::AppId;
use crate::policy::Policy;
use crate::time::Timestamp;
use crate::value::ArgValue;

/// The ID of one chaperone run. chaperone draws it from the OS random
/// source at each start. Core only carries it (G3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunId([u8; 16]);

impl RunId {
    /// Wrap 16 random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The ID as 32 lower-case hex characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The number of one call within one run. chaperone counts up from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallNumber(pub u64);

/// The tool of a call, as an audit record may hold it. Only
/// [`AuditTool::lookup`] builds one, so a record can never hold the text
/// that the app sent, unless the policy configures that exact tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTool(Option<ExposedName>);

impl AuditTool {
    /// The text an audit record shows for a tool the policy does not configure.
    pub const UNKNOWN: &'static str = "<unknown>";

    /// Keep `requested` only when it names a tool that some app instance of
    /// `policy` is granted. Replace any other text with [`Self::UNKNOWN`].
    /// A hash would not be safe: an app could send its bearer token as the
    /// name, and the SHA-256 of the token is the digest in `policy.json`.
    #[must_use]
    pub fn lookup(requested: &str, policy: &Policy) -> Self {
        let known = ExposedName::parse(requested)
            .ok()
            .filter(|name| policy.configures(name.upstream(), name.tool()));
        Self(known)
    }

    /// The tool as the audit file shows it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref().map_or(Self::UNKNOWN, ExposedName::as_str)
    }
}

/// What happened to a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// The decision, written before chaperone runs the call.
    Decided(Decision),
    /// The upstream ran the call. `is_error` is the upstream's own flag.
    Ran { is_error: bool },
    /// chaperone could not run the call.
    Failed(CallFault),
}

/// One audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub run: RunId,
    pub call: CallNumber,
    pub time: Timestamp,
    /// The app instance, or `None` when the credentials resolve to none.
    pub app: Option<AppId>,
    pub tool: AuditTool,
    /// The SHA-256 of the canonical arguments, as 64 hex characters.
    pub arguments_sha256: String,
    pub event: AuditEvent,
}

impl AuditRecord {
    /// The SHA-256 of the canonical arguments, as 64 hex characters.
    #[must_use]
    pub fn arguments_sha256(arguments: &BTreeMap<String, ArgValue>) -> String {
        use sha2::{Digest, Sha256};

        hex::encode(Sha256::digest(ArgValue::canonical_object(arguments)))
    }

    /// The text of a decision, for an audit record.
    #[must_use]
    pub fn decision_code(decision: &Decision) -> String {
        match decision {
            Decision::Allow => "allow".to_owned(),
            Decision::Deny(reason) => format!("deny:{}", reason.code()),
            Decision::Gate(id) => format!("gate:{id}"),
        }
    }
}

/// Why an audit sink could not write a record. The call then fails (G6).
#[derive(Debug, thiserror::Error)]
#[error("the audit sink could not write the record: {0}")]
pub struct AuditError(pub String);

/// The audit-sink hook. It fills the audit sink slot.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Write one record. Return only after the record is durable.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when the record is not durable.
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError>;
}
