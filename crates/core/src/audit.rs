//! The audit records and the audit-sink hook (G6).
//!
//! [`CallAudit`] is the only way to build an [`AuditRecord`]. Its consuming
//! methods define the valid record sequences in `docs/design.md` section 5.4.
//! Each method writes its record through the [`AuditSink`] and hands out
//! the next state only after the write succeeds. No other code holds a
//! record to write, so no call can run before its decision record (G6).
//! The transition from a gated call to an allowed call arrives with the
//! approval answer type in build step 6.
//!
//! A record never holds a secret, a token or unconstrained app text (G9).
//! The tool is present only when the policy configures it. The arguments
//! are present only as an [`ArgumentsDigest`].

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;

use crate::decide::{Decision, DenyReason, GateId};
use crate::exposed::ExposedName;
use crate::gateway::CallFault;
use crate::ids::AppId;
use crate::policy::Policy;
use crate::time::Timestamp;
use crate::value::ArgValue;

/// The app instance of a call, as an audit record may hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditApp(Option<AppId>);

impl AuditApp {
    /// Keep `requested` only when it names an app instance in `policy`.
    #[must_use]
    pub fn lookup(requested: Option<&AppId>, policy: Option<&Policy>) -> Self {
        let known = policy
            .and_then(|policy| requested.filter(|app| policy.app(app).is_some()))
            .cloned();
        Self(known)
    }

    /// The app instance, or `None` when it is not in the policy.
    #[must_use]
    pub fn as_ref(&self) -> Option<&AppId> {
        self.0.as_ref()
    }
}

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
pub struct CallNumber(NonZeroU64);

impl CallNumber {
    /// The first call of a run.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// The next call number, or `None` when the counter is exhausted.
    #[must_use]
    pub fn checked_next(self) -> Option<Self> {
        self.0
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(Self)
    }

    /// The positive integer in this call number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// The tool of a call, as an audit record may hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTool(Option<ExposedName>);

impl AuditTool {
    /// The text for a tool that the policy does not configure.
    pub const UNKNOWN: &'static str = "<unknown>";

    /// Keep `requested` only when `policy` configures that exact tool.
    /// Replace all other text with [`Self::UNKNOWN`].
    #[must_use]
    pub fn lookup(requested: &str, policy: Option<&Policy>) -> Self {
        let known = policy.and_then(|policy| {
            ExposedName::parse(requested)
                .ok()
                .filter(|name| policy.configures(name.upstream(), name.tool()))
        });
        Self(known)
    }

    /// The tool as the audit file shows it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref().map_or(Self::UNKNOWN, ExposedName::as_str)
    }
}

/// The SHA-256 of the canonical arguments of a call.
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
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// A decision as an audit record may hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDecision {
    Allow,
    Deny(&'static str),
    Gate(GateId),
}

impl AuditDecision {
    fn from_decision(decision: &Decision) -> Self {
        match decision {
            Decision::Allow => Self::Allow,
            Decision::Deny(reason) => Self::Deny(reason.code()),
            Decision::Gate(id) => Self::Gate(*id),
        }
    }

    /// The stable decision code for an audit line.
    #[must_use]
    pub fn code(self) -> String {
        match self {
            Self::Allow => "allow".to_owned(),
            Self::Deny(reason) => format!("deny:{reason}"),
            Self::Gate(id) => format!("gate:{id}"),
        }
    }
}

/// What one record says happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// The decision. A deny ends the call. An allow or a gate needs a final
    /// record.
    Decided(AuditDecision),
    /// Final: the upstream ran the call. `is_error` is the upstream's flag.
    Ran { is_error: bool },
    /// Final: the gate's wait window ended without an answer.
    Waiting(GateId),
    /// Final: chaperone could not run the call.
    Failed(CallFault),
}

/// One audit record. Only [`CallAudit`] builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    facts: CallFacts,
    at: Timestamp,
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

    /// When the call started.
    #[must_use]
    pub fn started_at(&self) -> Timestamp {
        self.facts.started_at
    }

    /// When this record's event happened.
    #[must_use]
    pub fn time(&self) -> Timestamp {
        self.at
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
}

/// The facts that every record of one call shares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CallFacts {
    run: RunId,
    call: CallNumber,
    started_at: Timestamp,
    app: AuditApp,
    tool: AuditTool,
    arguments: ArgumentsDigest,
}

/// The audit of one call before its first record.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct CallAudit(CallFacts);

/// What must follow a decision record.
#[must_use]
pub enum AfterDecision {
    /// The call was denied. The decision record was the last one.
    Denied(DenyReason),
    /// The call may run. One final record follows.
    Allowed(AllowedCall),
    /// The call waits for an approval. One final record follows.
    Gated(GatedCall),
}

impl fmt::Debug for AfterDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(reason) => f.debug_tuple("Denied").field(&reason.code()).finish(),
            Self::Allowed(_) => f.write_str("Allowed(..)"),
            Self::Gated(call) => f.debug_tuple("Gated").field(&call.1).finish(),
        }
    }
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
    /// Build the safe audit facts of one call.
    pub fn new(
        run: RunId,
        call: CallNumber,
        started_at: Timestamp,
        app: AuditApp,
        tool: AuditTool,
        arguments: ArgumentsDigest,
    ) -> Self {
        Self(CallFacts {
            run,
            call,
            started_at,
            app,
            tool,
            arguments,
        })
    }

    /// Write the only record of a call that fails before a decision.
    ///
    /// # Errors
    ///
    /// Returns the [`AuditError`] of the sink. The record is then not
    /// durable, and chaperone returns no result (G6).
    pub fn failed_before_decision(
        self,
        fault: CallFault,
        at: Timestamp,
        sink: &dyn AuditSink,
    ) -> Result<(), AuditError> {
        sink.write(&AuditRecord {
            facts: self.0,
            at,
            event: AuditEvent::Failed(fault),
        })
    }

    /// Write the decision record. The state that must follow it exists only
    /// after the sink reports the record durable, so no call runs before
    /// its decision record (G6).
    ///
    /// # Errors
    ///
    /// Returns the [`AuditError`] of the sink. chaperone then does not run
    /// the call.
    pub fn decided(
        self,
        decision: Decision,
        at: Timestamp,
        sink: &dyn AuditSink,
    ) -> Result<AfterDecision, AuditError> {
        let record = AuditRecord {
            facts: self.0,
            at,
            event: AuditEvent::Decided(AuditDecision::from_decision(&decision)),
        };
        sink.write(&record)?;
        let AuditRecord { facts, .. } = record;
        Ok(match decision {
            Decision::Deny(reason) => AfterDecision::Denied(reason),
            Decision::Allow => AfterDecision::Allowed(AllowedCall(facts)),
            Decision::Gate(id) => AfterDecision::Gated(GatedCall(facts, id)),
        })
    }
}

impl AllowedCall {
    /// Final: the upstream ran the call.
    ///
    /// # Errors
    ///
    /// Returns the [`AuditError`] of the sink. chaperone then returns no
    /// result (G6).
    pub fn ran(
        self,
        is_error: bool,
        at: Timestamp,
        sink: &dyn AuditSink,
    ) -> Result<(), AuditError> {
        sink.write(&AuditRecord {
            facts: self.0,
            at,
            event: AuditEvent::Ran { is_error },
        })
    }

    /// Final: chaperone could not run the call.
    ///
    /// # Errors
    ///
    /// Returns the [`AuditError`] of the sink.
    pub fn failed(
        self,
        fault: CallFault,
        at: Timestamp,
        sink: &dyn AuditSink,
    ) -> Result<(), AuditError> {
        sink.write(&AuditRecord {
            facts: self.0,
            at,
            event: AuditEvent::Failed(fault),
        })
    }
}

impl GatedCall {
    /// Final: the wait window ended without an answer.
    ///
    /// # Errors
    ///
    /// Returns the [`AuditError`] of the sink.
    pub fn waiting(self, at: Timestamp, sink: &dyn AuditSink) -> Result<(), AuditError> {
        sink.write(&AuditRecord {
            facts: self.0,
            at,
            event: AuditEvent::Waiting(self.1),
        })
    }

    /// Final: chaperone could not get an approval.
    ///
    /// # Errors
    ///
    /// Returns the [`AuditError`] of the sink.
    pub fn failed(
        self,
        fault: CallFault,
        at: Timestamp,
        sink: &dyn AuditSink,
    ) -> Result<(), AuditError> {
        sink.write(&AuditRecord {
            facts: self.0,
            at,
            event: AuditEvent::Failed(fault),
        })
    }
}

/// Why an audit sink could not write a record. The call then fails (G6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// The operating system refused a write or a sync.
    #[error("the audit I/O failed ({0:?})")]
    Io(std::io::ErrorKind),
    /// A lock that guards the sink is poisoned.
    #[error("the audit sink lock is poisoned")]
    LockPoisoned,
    /// The sink could not encode the record.
    #[error("the audit record could not be encoded")]
    Encode,
}

/// The audit-sink hook. It fills the audit sink slot. Only [`CallAudit`]
/// and its states call it.
pub trait AuditSink: Send + Sync + fmt::Debug {
    /// Write one record. Return only after the record is durable.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when the record is not durable.
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use crate::hook::FenceReason;
    use crate::ids::PluginName;

    use super::*;

    const START: Timestamp = Timestamp::from_unix_millis(1_000);
    const END: Timestamp = Timestamp::from_unix_millis(61_000);
    const GATE: GateId = GateId::from_bytes([2; 16]);

    static_assertions::assert_not_impl_any!(CallAudit: Clone);
    static_assertions::assert_not_impl_any!(AllowedCall: Clone);
    static_assertions::assert_not_impl_any!(GatedCall: Clone);

    /// A sink that hands each written record to the test.
    #[derive(Debug)]
    struct ChannelSink(mpsc::Sender<AuditRecord>);

    impl AuditSink for ChannelSink {
        fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.send(record.clone()).map_err(|_| AuditError::Encode)
        }
    }

    /// A sink that refuses every record.
    #[derive(Debug)]
    struct RefusingSink;

    impl AuditSink for RefusingSink {
        fn write(&self, _: &AuditRecord) -> Result<(), AuditError> {
            Err(AuditError::Encode)
        }
    }

    fn sink() -> (ChannelSink, mpsc::Receiver<AuditRecord>) {
        let (sender, receiver) = mpsc::channel();
        (ChannelSink(sender), receiver)
    }

    fn audit() -> CallAudit {
        CallAudit::new(
            RunId::from_bytes([1; 16]),
            CallNumber::FIRST,
            START,
            AuditApp::lookup(None, None),
            AuditTool::lookup("token-looking-text", None),
            ArgumentsDigest::of(&BTreeMap::new()),
        )
    }

    #[test]
    fn unknown_tool_text_never_reaches_a_record() {
        let (sink, written) = sink();
        audit()
            .failed_before_decision(CallFault::UnknownTool, START, &sink)
            .unwrap();
        let record = written.recv().unwrap();
        assert_eq!(record.tool().as_str(), AuditTool::UNKNOWN);
        assert!(!format!("{record:?}").contains("token-looking-text"));
    }

    #[test]
    fn unconfigured_app_text_never_reaches_a_record() {
        let (sink, written) = sink();
        let app = AppId::try_new("token-looking-text").unwrap();
        CallAudit::new(
            RunId::from_bytes([1; 16]),
            CallNumber::FIRST,
            START,
            AuditApp::lookup(Some(&app), None),
            AuditTool::lookup("upstream__tool", None),
            ArgumentsDigest::of(&BTreeMap::new()),
        )
        .failed_before_decision(CallFault::UnknownTool, START, &sink)
        .unwrap();
        let record = written.recv().unwrap();
        assert_eq!(record.app(), None);
        assert!(!format!("{record:?}").contains("token-looking-text"));
    }

    #[test]
    fn a_deny_record_keeps_only_the_stable_code() {
        let (sink, written) = sink();
        let decision = Decision::Deny(DenyReason::Fence {
            plugin: PluginName::try_new("test-fence").unwrap(),
            reason: FenceReason::new("token-looking-text"),
        });
        let next = audit().decided(decision, START, &sink).unwrap();
        let record = written.recv().unwrap();
        assert_eq!(
            record.event(),
            &AuditEvent::Decided(AuditDecision::Deny("fence"))
        );
        assert!(!format!("{record:?} {next:?}").contains("token-looking-text"));
    }

    #[test]
    fn a_gate_ends_in_a_waiting_record() {
        let (sink, written) = sink();
        let next = audit().decided(Decision::Gate(GATE), START, &sink).unwrap();
        let AfterDecision::Gated(call) = next else {
            panic!("a gate must need a final record");
        };
        call.waiting(END, &sink).unwrap();
        let first = written.recv().unwrap();
        let last = written.recv().unwrap();
        assert_eq!(
            first.event(),
            &AuditEvent::Decided(AuditDecision::Gate(GATE))
        );
        assert_eq!(last.event(), &AuditEvent::Waiting(GATE));
        assert_eq!((last.started_at(), last.time()), (START, END));
    }

    #[test]
    fn an_allow_ends_in_a_ran_record_after_two_writes() {
        let (sink, written) = sink();
        let next = audit().decided(Decision::Allow, START, &sink).unwrap();
        let AfterDecision::Allowed(call) = next else {
            panic!("an allow must need a final record");
        };
        call.ran(false, END, &sink).unwrap();
        assert_eq!(
            written.recv().unwrap().event(),
            &AuditEvent::Decided(AuditDecision::Allow)
        );
        assert_eq!(
            written.recv().unwrap().event(),
            &AuditEvent::Ran { is_error: false }
        );
    }

    #[test]
    fn a_refused_write_gives_no_next_state() {
        assert_eq!(
            audit()
                .decided(Decision::Allow, START, &RefusingSink)
                .unwrap_err(),
            AuditError::Encode
        );
        assert_eq!(
            audit()
                .failed_before_decision(CallFault::UnknownTool, START, &RefusingSink)
                .unwrap_err(),
            AuditError::Encode
        );
    }

    #[test]
    fn the_digest_is_the_hash_of_the_canonical_arguments() {
        let digest = ArgumentsDigest::of(&BTreeMap::new());
        assert_eq!(
            digest.to_hex(),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn call_numbers_start_at_one_and_increase() {
        let first = CallNumber::FIRST;
        assert_eq!(first.get(), 1);
        assert_eq!(first.checked_next().map(CallNumber::get), Some(2));
    }
}
