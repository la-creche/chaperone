//! Every contract between chaperone and a compiled plugin, in one place.
//! `plugins/AGENTS.md` has the hook catalog.
//!
//! A decision plugin implements [`Identity`] or [`Fence`]. Both are pure
//! (G3): every input is an argument, and the result is a value. An adapter
//! plugin implements [`SecretSource`], [`AuditSink`] or [`Clock`]. The front
//! door is the one adapter that implements nothing: it calls [`Gateway`],
//! which chaperone implements. The result types of each trait stay in the
//! module that owns them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;

use serde::de::DeserializeOwned;

use serde::Deserialize;

use crate::audit::{AuditError, AuditRecord};
use crate::decide::GateId;
use crate::exposed::ExposedName;
use crate::gateway::{CallOutcome, Health, ListError, ListedTool};
use crate::ids::{AppId, PluginName, SecretName, ToolName};
use crate::policy::Policy;
use crate::secret::{Bearer, Secret, SecretError};
use crate::strict::{self, ByteCap, StrictError};
use crate::time::Timestamp;
use crate::value::ArgValue;

/// What an app presents with a call.
pub struct Credentials<'a> {
    /// The bearer token, if the request carried one.
    pub bearer: Option<&'a Bearer>,
    /// The request headers, with lower-case names.
    pub headers: &'a BTreeMap<String, String>,
}

/// A header value can be a credential (G9). `Debug` shows the names only.
impl fmt::Debug for Credentials<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("bearer", &self.bearer)
            .field("headers", &self.headers.keys())
            .finish()
    }
}

/// What a caller may reach, within its app instance's grant (G4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// The full grant of the app instance.
    Full,
    /// Only these tools of each upstream, and only where the grant also
    /// allows them.
    Only(BTreeMap<PluginName, BTreeSet<ToolName>>),
}

impl Reach {
    /// Whether `tool` of `upstream` is within this reach. The grant is
    /// checked separately.
    #[must_use]
    pub fn holds(&self, upstream: &PluginName, tool: &ToolName) -> bool {
        match self {
            Self::Full => true,
            Self::Only(tools) => tools
                .get(upstream)
                .is_some_and(|names| names.contains(tool)),
        }
    }
}

/// The result of the identity hook: one app instance and its reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub app: AppId,
    pub reach: Reach,
}

/// The identity hook. It fills the identity slot.
pub trait Identity: Send + Sync + fmt::Debug {
    /// Resolve the credentials to one app instance of `policy`, or to
    /// nothing. It may narrow the reach. It can never widen it.
    fn resolve(&self, credentials: &Credentials<'_>, policy: &Policy) -> Option<Caller>;
}

/// One tool call, as a fence sees it.
#[derive(Debug)]
pub struct ToolCall<'a> {
    pub app: &'a AppId,
    pub upstream: &'a PluginName,
    pub tool: &'a ToolName,
    pub arguments: &'a BTreeMap<String, ArgValue>,
    pub now: Timestamp,
}

/// Why a fence denies a call. The text is fixed when the fence is compiled,
/// so a fence cannot copy an argument value or a secret into it (G9). At
/// most [`FenceReason::MAX`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceReason(&'static str);

impl FenceReason {
    /// The longest reason, in bytes.
    pub const MAX: usize = 200;

    /// Wrap `text`, cut at a character boundary to [`Self::MAX`] bytes.
    #[must_use]
    pub fn new(text: &'static str) -> Self {
        let mut end = text.len().min(Self::MAX);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Self(&text[..end])
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0
    }
}

/// The result of one fence. There is no "allow" (G7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceVerdict {
    /// The fence has no objection.
    Pass,
    /// The fence refuses the call.
    Deny(FenceReason),
    /// The call needs a human approval.
    Gate,
}

/// A fence with its policy section for one app instance already read.
pub trait PreparedFence: Send + Sync + fmt::Debug {
    /// The verdict on one call. Like every decision hook, it is pure (G3).
    fn check(&self, call: &ToolCall<'_>) -> FenceVerdict;
}

/// The section of one plugin in one app instance of `policy.toml`, as
/// the strict reader read it. The plugin reads it into its own type.
#[derive(Debug)]
pub struct RawSection<'a>(&'a toml::Value);

impl<'a> RawSection<'a> {
    pub(crate) fn new(raw: &'a toml::Value) -> Self {
        Self(raw)
    }

    /// Read the section into `T`. Give `T` `#[serde(deny_unknown_fields)]`.
    ///
    /// # Errors
    ///
    /// Returns a [`SectionError`] when the section does not fit `T`.
    pub fn parse<T: DeserializeOwned>(&self) -> Result<T, SectionError> {
        T::deserialize(self.0.clone()).map_err(|error| SectionError(error.message().to_owned()))
    }
}

/// Why a plugin refuses its policy section. A policy with such a section
/// does not load (G2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SectionError(pub String);

/// Why a fence refuses the sections of two app instances together. The
/// rule is a fixed text of the fence (G9). A policy with such a pair does
/// not load (G2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the caller app {caller} and the target app {target} break a rule: {}",
    .rule.as_str()
)]
pub struct CrossAppError {
    pub caller: AppId,
    pub target: AppId,
    pub rule: FenceReason,
}

/// The fence hook. Any number of fences can be active.
pub trait Fence: Send + Sync + fmt::Debug {
    /// The section of one app instance, as [`Fence::prepare`] reads it.
    type Prepared: PreparedFence + 'static;

    /// The plugin name. It equals the name in `plugin.toml`.
    fn name(&self) -> &PluginName;

    /// Read this plugin's section for one app instance. `None` means the
    /// app instance has no section. The fence then decides what that means.
    ///
    /// # Errors
    ///
    /// Returns a [`SectionError`] when the section is not valid.
    fn prepare(&self, section: Option<RawSection<'_>>) -> Result<Self::Prepared, SectionError>;

    /// Check the prepared sections of every app instance together, by app
    /// ID. The policy load calls it once, after every [`Fence::prepare`].
    /// It can only refuse the policy. The default refuses nothing.
    ///
    /// # Errors
    ///
    /// Returns a [`CrossAppError`] when two app instances break a rule
    /// together.
    fn check_sections(
        &self,
        _sections: &BTreeMap<&AppId, &Self::Prepared>,
    ) -> Result<(), CrossAppError> {
        Ok(())
    }
}

/// The secret-source hook. It fills the secret source slot
/// (`docs/design.md` 7.2). chaperone reads each bound secret through it at
/// start.
pub trait SecretSource: Send + Sync + fmt::Debug {
    /// The secret `name`.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretError`] when the secret is missing, unsafe,
    /// invalid or unreadable.
    fn read(&self, name: &SecretName) -> Result<Secret, SecretError>;
}

/// The audit-sink hook. It fills the audit sink slot. Only `CallAudit` and
/// its states call it.
pub trait AuditSink: Send + Sync + fmt::Debug {
    /// Write one record. Return only after the record is durable.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when the record is not durable.
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

/// The clock hook. It fills the clock slot. The program reads the time
/// through it and passes the time to the decision as an argument (G3).
pub trait Clock: Send + Sync + fmt::Debug {
    fn now(&self) -> Timestamp;
}

/// The tool of the approval channel plugin that chaperone calls for each
/// gate (`docs/design.md` 5.3).
pub const APPROVE_TOOL: &str = "approve";

/// The largest answer of the approval hook chaperone reads.
pub const ANSWER_CAP: ByteCap = ByteCap::new(4 * 1024);

/// One request to the approval hook: the gate and the call it holds.
#[derive(Debug)]
pub struct ApprovalRequest<'a> {
    pub gate: GateId,
    pub app: &'a AppId,
    pub tool: &'a ExposedName,
    pub arguments: &'a BTreeMap<String, ArgValue>,
}

impl ApprovalRequest<'_> {
    /// The arguments of the `approve` call (`docs/design.md` 5.3).
    #[must_use]
    pub fn arguments(&self) -> BTreeMap<String, ArgValue> {
        BTreeMap::from([
            ("gate".to_owned(), ArgValue::String(self.gate.to_hex())),
            (
                "app".to_owned(),
                ArgValue::String(self.app.as_str().to_owned()),
            ),
            (
                "tool".to_owned(),
                ArgValue::String(self.tool.as_str().to_owned()),
            ),
            (
                "arguments".to_owned(),
                ArgValue::Object(self.arguments.clone()),
            ),
        ])
    }
}

/// Why the approval channel denied a gate. At most [`DenialReason::MAX`]
/// characters, cut from the plugin's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenialReason(String);

impl DenialReason {
    /// The longest reason, in characters.
    pub const MAX: usize = 200;

    /// Wrap `text`, cut to [`Self::MAX`] characters.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.chars().take(Self::MAX).collect())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The answer of the approval hook (`docs/design.md` 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateAnswer {
    Approved,
    Denied(DenialReason),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAnswer {
    answer: RawVerdict,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawVerdict {
    Approved,
    Denied,
}

/// Why the text of the approval hook is not an answer. The gate is then
/// denied for its life (G2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnswerError {
    #[error("the answer is not strict JSON of the answer shape: {0}")]
    Read(#[from] StrictError),
    #[error("an approved answer carries a reason")]
    ReasonOnApproved,
}

impl GateAnswer {
    /// Read the text block of the approval hook's result.
    ///
    /// # Errors
    ///
    /// Returns an [`AnswerError`] when the text is not one answer.
    pub fn read(bytes: &[u8]) -> Result<Self, AnswerError> {
        let raw: RawAnswer = strict::read(bytes, ANSWER_CAP)?;
        match (raw.answer, raw.reason) {
            (RawVerdict::Approved, None) => Ok(Self::Approved),
            (RawVerdict::Approved, Some(_)) => Err(AnswerError::ReasonOnApproved),
            (RawVerdict::Denied, reason) => Ok(Self::Denied(DenialReason::new(
                reason.as_deref().unwrap_or(""),
            ))),
        }
    }
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

    /// Whether a valid policy is loaded, for a health probe. It reveals no
    /// policy content.
    fn health(&self) -> impl Future<Output = Health> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_debug_shows_header_names_only() {
        let bearer = Bearer::new("SECRET-bearer".into());
        let headers = BTreeMap::from([("authorization".to_owned(), "SECRET-header".to_owned())]);
        let credentials = Credentials {
            bearer: Some(&bearer),
            headers: &headers,
        };
        let shown = format!("{credentials:?}");
        assert!(shown.contains("authorization"));
        assert!(!shown.contains("SECRET"), "{shown}");
    }

    #[test]
    fn an_answer_reads_approved_and_denied_and_refuses_the_rest() {
        assert_eq!(
            GateAnswer::read(br#"{"answer":"approved"}"#).unwrap(),
            GateAnswer::Approved
        );
        assert_eq!(
            GateAnswer::read(br#"{"answer":"denied","reason":"not today"}"#).unwrap(),
            GateAnswer::Denied(DenialReason::new("not today"))
        );
        assert_eq!(
            GateAnswer::read(br#"{"answer":"denied"}"#).unwrap(),
            GateAnswer::Denied(DenialReason::new(""))
        );
        for bad in [
            br#"{"answer":"maybe"}"#.as_slice(),
            br#"{"answer":"approved","reason":"x"}"#,
            br#"{"answer":"approved","extra":1}"#,
            br#"{"answer":"approved","answer":"approved"}"#,
            b"approved",
            b"",
        ] {
            assert!(
                GateAnswer::read(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_denial_reason_is_cut_to_the_cap() {
        let long = "x".repeat(DenialReason::MAX + 50);
        assert_eq!(DenialReason::new(&long).as_str().len(), DenialReason::MAX);
    }

    #[test]
    fn a_fence_reason_is_cut_at_a_character_boundary() {
        const LONG: &str = "éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé";
        assert!(LONG.len() > FenceReason::MAX);
        let reason = FenceReason::new(LONG);
        assert!(reason.as_str().len() <= FenceReason::MAX);
        assert!(reason.as_str().chars().all(|c| c == 'é'));
    }
}
