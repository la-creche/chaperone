//! The audit record and the audit-sink hook (G6). chaperone writes one
//! record when it decides a call, before it runs the call, and one record
//! when the call ends, before it returns the result. A record never holds a
//! secret, a token or an argument value (G9). It holds a hash of the
//! arguments, so two records of the same call can be matched.

use std::collections::BTreeMap;

use crate::decide::Decision;
use crate::gateway::CallFault;
use crate::ids::AppId;
use crate::time::Timestamp;
use crate::value::ArgValue;

/// The number that ties the two records of one call together. chaperone
/// counts up from 1 at each start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallNumber(pub u64);

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

/// One audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub call: CallNumber,
    pub time: Timestamp,
    /// The app instance, or `None` when the credentials resolve to none.
    pub app: Option<AppId>,
    /// The tool name as the app sent it, cut to [`AuditRecord::TOOL_MAX`].
    pub tool: String,
    /// The SHA-256 of the canonical arguments, as 64 hex characters.
    pub arguments_sha256: String,
    pub event: AuditEvent,
}

impl AuditRecord {
    /// The longest tool name an audit line keeps, in bytes.
    pub const TOOL_MAX: usize = 128;

    /// The SHA-256 of the canonical arguments, as 64 hex characters.
    #[must_use]
    pub fn arguments_sha256(arguments: &BTreeMap<String, ArgValue>) -> String {
        use sha2::{Digest, Sha256};

        hex::encode(Sha256::digest(ArgValue::canonical_object(arguments)))
    }

    /// The text of a deny reason or a gate, for an audit line.
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
