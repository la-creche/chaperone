//! The decision-hook traits: identity and fence. A decision plugin
//! implements one of them. Both are pure (G3): every input is an argument,
//! and the result is a value. `plugins/decision/AGENTS.md` has the rules.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::DeserializeOwned;
use serde_json::value::RawValue;

use crate::ids::{AppId, PluginName, ToolName};
use crate::policy::Policy;
use crate::secret::Bearer;
use crate::strict::StrictError;
use crate::time::Timestamp;
use crate::value::ArgValue;

/// What an app presents with a call. `Debug` shows the header names only,
/// because a header value can hold a secret (G9).
pub struct Credentials<'a> {
    /// The bearer token, if the request carried one.
    pub bearer: Option<&'a Bearer>,
    /// The request headers, with lower-case names.
    pub headers: &'a BTreeMap<String, String>,
}

impl fmt::Debug for Credentials<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("bearer", &self.bearer)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
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

/// One tool call, as a fence sees it. `Debug` shows the argument names
/// only, because an argument value can hold a secret (G9).
pub struct ToolCall<'a> {
    pub app: &'a AppId,
    pub upstream: &'a PluginName,
    pub tool: &'a ToolName,
    pub arguments: &'a BTreeMap<String, ArgValue>,
    pub now: Timestamp,
}

impl fmt::Debug for ToolCall<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolCall")
            .field("app", &self.app)
            .field("upstream", &self.upstream)
            .field("tool", &self.tool)
            .field("argument_names", &self.arguments.keys().collect::<Vec<_>>())
            .field("now", &self.now)
            .finish()
    }
}

/// Why a fence denies a call: fixed text that the plugin owns. It takes a
/// `&'static str`, so a reason cannot be built at run time from an
/// argument or a secret (G9). At most [`FenceReason::MAX`] bytes.
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
        Self(text.get(..end).unwrap_or_default())
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
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
    /// Judge one call.
    fn check(&self, call: &ToolCall<'_>) -> FenceVerdict;
}

/// The section of one plugin in one app instance of `policy.json`, as
/// strict JSON text. The plugin reads it into its own type.
#[derive(Debug)]
pub struct RawSection<'a>(&'a RawValue);

impl<'a> RawSection<'a> {
    pub(crate) fn new(raw: &'a RawValue) -> Self {
        Self(raw)
    }

    /// Read the section into `T`. Give `T` `#[serde(deny_unknown_fields)]`.
    ///
    /// # Errors
    ///
    /// Returns a [`SectionError`] when the section does not fit `T`.
    pub fn parse<T: DeserializeOwned>(&self) -> Result<T, SectionError> {
        serde_json::from_str(self.0.get())
            .map_err(|error| SectionError::Parse(StrictError::shape(&error)))
    }
}

/// Why a plugin refuses its policy section. A policy with such a section
/// does not load (G2). Like [`StrictError`], it holds no text from the
/// section, only a code and a location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SectionError {
    /// The section does not fit the plugin's type.
    #[error("{0}")]
    Parse(StrictError),
    /// The section fits the type, but breaks a rule of the plugin. The
    /// text is the plugin's own fixed message, never section text.
    #[error("invalid: {0}")]
    Invalid(&'static str),
}

/// The fence hook. Any number of fences can be active.
pub trait Fence: Send + Sync + fmt::Debug {
    /// The plugin name. It equals the name in `plugin.json`.
    fn name(&self) -> &PluginName;

    /// Read this plugin's section for one app instance. `None` means the
    /// app instance has no section. The fence then decides what that means.
    ///
    /// # Errors
    ///
    /// Returns a [`SectionError`] when the section is not valid.
    fn prepare(
        &self,
        section: Option<RawSection<'_>>,
    ) -> Result<Box<dyn PreparedFence>, SectionError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_section_error_never_shows_section_text() {
        const SECRET: &str = "tok_live_do_not_log_this";
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[expect(dead_code, reason = "the field exists only to check the shape")]
        struct Section {
            mode: Mode,
        }
        #[derive(Debug, serde::Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Mode {
            On,
        }
        for text in [
            format!(r#"{{"mode": "{SECRET}"}}"#),
            format!(r#"{{"mode": "on", "{SECRET}": 1}}"#),
        ] {
            let raw: Box<RawValue> = serde_json::from_str(&text).unwrap();
            let error = RawSection::new(&raw).parse::<Section>().unwrap_err();
            assert!(!error.to_string().contains(SECRET), "{error}");
            assert!(!format!("{error:?}").contains(SECRET), "{error:?}");
        }
    }

    #[test]
    fn debug_never_shows_header_or_argument_values() {
        const SECRET: &str = "tok_live_do_not_log_this";
        let headers = BTreeMap::from([("cookie".to_owned(), SECRET.to_owned())]);
        let bearer = Bearer::new(SECRET.to_owned());
        let credentials = Credentials {
            bearer: Some(&bearer),
            headers: &headers,
        };
        assert!(!format!("{credentials:?}").contains(SECRET));

        let arguments = BTreeMap::from([("token".to_owned(), ArgValue::String(SECRET.into()))]);
        let app = AppId::try_new("librechat").unwrap();
        let upstream = PluginName::try_new("vikunja").unwrap();
        let tool = ToolName::try_new("list_tasks").unwrap();
        let call = ToolCall {
            app: &app,
            upstream: &upstream,
            tool: &tool,
            arguments: &arguments,
            now: Timestamp::from_unix_millis(0),
        };
        let shown = format!("{call:?}");
        assert!(!shown.contains(SECRET), "{shown}");
        assert!(shown.contains("token"), "{shown}");
    }

    #[test]
    fn a_fence_reason_is_cut_at_a_character_boundary() {
        const LONG: &str = "éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé";
        let reason = FenceReason::new(LONG);
        assert!(reason.as_str().len() <= FenceReason::MAX);
        assert!(reason.as_str().chars().all(|c| c == 'é'));
    }
}
