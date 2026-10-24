//! The audit records and the audit-sink hook (G6).
//!
//! [`CallAudit`] is the only way to build an [`AuditRecord`]. Its methods
//! take `self`, so each path through a call yields exactly the records in
//! this table (`docs/design.md` 5.4):
//!
//! | Path | Records |
//! |---|---|
//! | The call fails before a decision | `Failed` |
//! | Deny | `Decided(Deny)` |
//! | Allow, then the call runs | `Decided(Allow)`, `Ran` |
//! | Allow, then the call cannot run | `Decided(Allow)`, `Failed` |
//! | Gate, then the window ends with no answer | `Decided(Gate)`, `Waiting` |
//! | Gate, then no approval channel can answer | `Decided(Gate)`, `Failed` |
//! | Gate, then the approval comes, then the call runs or fails | `Decided(Gate)`, then as Allow |
//!
//! A record never holds a secret, a token or any text the app chose (G9).
//! The app chooses the tool name and the arguments. A record keeps a tool
//! name only when the policy configures that tool ([`AuditTool`]), and the
//! arguments only as an [`ArgumentsDigest`].

use std::collections::BTreeMap;
use std::fmt;

use crate::decide::{Decision, GateId};
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

/// The SHA-256 of the canonical arguments of a call. Only
/// [`ArgumentsDigest::of`] builds one, so the field can hold nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArgumentsDigest([u8; 32]);

impl ArgumentsDigest {
    /// Hash the canonical text of `arguments`.
    #[must_use]
    pub fn of(arguments: &BTreeMap<String, ArgValue>) -> Self {
        use sha2::{Digest, Sha256};

        Self(Sha256::digest(ArgValue::canonical_object(arguments)).into())
    }

    /// The digest as 64 lower-case hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// What one record says happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// The decision. A `Deny` ends the call. An `Allow` or a `Gate` is
    /// followed by one final record.
    Decided(Decision),
    /// Final: the upstream ran the call. `is_error` is the upstream's flag.
    Ran { is_error: bool },
    /// Final: the gate's wait window ended, and the app was told to call
    /// again after the approval.
    Waiting(GateId),
    /// Final: chaperone could not run the call.
    Failed(CallFault),
}

/// One audit record. An audit sink reads it through the methods. Only
/// [`CallAudit`] builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    facts: CallFacts,
    event: AuditEvent,
}

impl AuditRecord {
    #[must_use]
    pub fn run(&self) -> RunId {
        self.facts.run
    }

    #[must_use]
    pub fn call(&self) -> CallNumber {
        self.facts.call
    }

    #[must_use]
    pub fn time(&self) -> Timestamp {
        self.facts.time
    }

    /// The app instance, or `None` when the credentials resolve to none.
    #[must_use]
    pub fn app(&self) -> Option<&AppId> {
        self.facts.app.as_ref()
    }

    #[must_use]
    pub fn tool(&self) -> &AuditTool {
        &self.facts.tool
    }

    #[must_use]
    pub fn arguments(&self) -> ArgumentsDigest {
        self.facts.arguments
    }

    #[must_use]
    pub fn event(&self) -> &AuditEvent {
        &self.event
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

/// The facts that every record of one call shares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CallFacts {
    run: RunId,
    call: CallNumber,
    time: Timestamp,
    app: Option<AppId>,
    tool: AuditTool,
    arguments: ArgumentsDigest,
}

/// The audit of one call, before its first record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct CallAudit(CallFacts);

/// What must follow a decision record.
#[derive(Debug)]
#[must_use]
pub enum AfterDecision {
    /// The call was denied. The decision record was the last one.
    Denied,
    /// The call may run. One final record follows.
    Allowed(AllowedCall),
    /// The call waits for an approval. One final record follows, or the
    /// approval turns it into an [`AllowedCall`].
    Gated(GatedCall),
}

/// An allowed call that still needs its final record.
#[derive(Debug)]
#[must_use]
pub struct AllowedCall(CallFacts);

/// A gated call that still needs its final record.
#[derive(Debug)]
#[must_use]
pub struct GatedCall(CallFacts, GateId);

impl CallAudit {
    /// The facts of one call. `tool` and `arguments` are the safe forms of
    /// what the app sent.
    pub fn new(
        run: RunId,
        call: CallNumber,
        time: Timestamp,
        app: Option<AppId>,
        tool: AuditTool,
        arguments: ArgumentsDigest,
    ) -> Self {
        Self(CallFacts {
            run,
            call,
            time,
            app,
            tool,
            arguments,
        })
    }

    /// The only record of a call that fails before a decision.
    #[must_use]
    pub fn failed_before_decision(self, fault: CallFault) -> AuditRecord {
        AuditRecord {
            facts: self.0,
            event: AuditEvent::Failed(fault),
        }
    }

    /// The decision record, and what must follow it.
    pub fn decided(self, decision: &Decision) -> (AuditRecord, AfterDecision) {
        let record = AuditRecord {
            facts: self.0.clone(),
            event: AuditEvent::Decided(decision.clone()),
        };
        let next = match decision {
            Decision::Deny(_) => AfterDecision::Denied,
            Decision::Allow => AfterDecision::Allowed(AllowedCall(self.0)),
            Decision::Gate(id) => AfterDecision::Gated(GatedCall(self.0, *id)),
        };
        (record, next)
    }
}

impl AllowedCall {
    /// Final: the upstream ran the call.
    #[must_use]
    pub fn ran(self, is_error: bool) -> AuditRecord {
        AuditRecord {
            facts: self.0,
            event: AuditEvent::Ran { is_error },
        }
    }

    /// Final: chaperone could not run the call.
    #[must_use]
    pub fn failed(self, fault: CallFault) -> AuditRecord {
        AuditRecord {
            facts: self.0,
            event: AuditEvent::Failed(fault),
        }
    }
}

impl GatedCall {
    /// Final: the wait window ended with no answer.
    #[must_use]
    pub fn waiting(self) -> AuditRecord {
        AuditRecord {
            event: AuditEvent::Waiting(self.1),
            facts: self.0,
        }
    }

    /// Final: chaperone could not get an approval.
    #[must_use]
    pub fn failed(self, fault: CallFault) -> AuditRecord {
        AuditRecord {
            facts: self.0,
            event: AuditEvent::Failed(fault),
        }
    }

    /// The approval came inside the window. The call goes on as allowed.
    pub fn approved(self) -> AllowedCall {
        AllowedCall(self.0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::DenyReason;

    fn audit() -> CallAudit {
        CallAudit::new(
            RunId::from_bytes([1; 16]),
            CallNumber(1),
            Timestamp::from_unix_millis(0),
            None,
            AuditTool(None),
            ArgumentsDigest::of(&BTreeMap::new()),
        )
    }

    fn events(records: &[AuditRecord]) -> Vec<&AuditEvent> {
        records.iter().map(AuditRecord::event).collect()
    }

    const GATE: GateId = GateId::from_bytes([2; 16]);

    #[test]
    fn a_deny_has_one_record() {
        let decision = Decision::Deny(DenyReason::ToolNotGranted);
        let (record, next) = audit().decided(&decision);
        assert!(matches!(next, AfterDecision::Denied));
        assert_eq!(events(&[record]), [&AuditEvent::Decided(decision)]);
    }

    #[test]
    fn an_allow_has_a_decision_and_one_final_record() {
        let (first, next) = audit().decided(&Decision::Allow);
        let AfterDecision::Allowed(call) = next else {
            panic!("an allow must need a final record");
        };
        let last = call.ran(false);
        assert_eq!(
            events(&[first, last]),
            [
                &AuditEvent::Decided(Decision::Allow),
                &AuditEvent::Ran { is_error: false }
            ]
        );
    }

    #[test]
    fn a_gate_ends_in_waiting_failed_or_an_allowed_run() {
        let gate = Decision::Gate(GATE);
        let gated = || match audit().decided(&gate) {
            (_, AfterDecision::Gated(call)) => call,
            (_, AfterDecision::Denied | AfterDecision::Allowed(_)) => {
                panic!("a gate must need a final record")
            }
        };
        assert_eq!(gated().waiting().event(), &AuditEvent::Waiting(GATE));
        assert_eq!(
            gated().failed(CallFault::NoApprovalChannel).event(),
            &AuditEvent::Failed(CallFault::NoApprovalChannel)
        );
        assert_eq!(
            gated().approved().ran(true).event(),
            &AuditEvent::Ran { is_error: true }
        );
    }

    #[test]
    fn a_failure_before_a_decision_has_one_record() {
        let record = audit().failed_before_decision(CallFault::UnknownTool);
        assert_eq!(record.event(), &AuditEvent::Failed(CallFault::UnknownTool));
    }

    #[test]
    fn the_digest_is_the_hash_of_the_canonical_arguments() {
        let digest = ArgumentsDigest::of(&BTreeMap::new());
        // SHA-256 of "{}".
        assert_eq!(
            digest.to_hex(),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }
}
