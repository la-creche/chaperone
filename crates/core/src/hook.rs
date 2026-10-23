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
use crate::time::Timestamp;
use crate::value::ArgValue;

/// What an app presents with a call.
#[derive(Debug)]
pub struct Credentials<'a> {
    /// The bearer token, if the request carried one.
    pub bearer: Option<&'a Bearer>,
    /// The request headers, with lower-case names.
    pub headers: &'a BTreeMap<String, String>,
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

/// One tool call, as a fence sees it.
#[derive(Debug)]
pub struct ToolCall<'a> {
    pub app: &'a AppId,
    pub upstream: &'a PluginName,
    pub tool: &'a ToolName,
    pub arguments: &'a BTreeMap<String, ArgValue>,
    pub now: Timestamp,
}

/// Why a fence denies a call. At most [`FenceReason::MAX`] bytes. It must
/// not contain a secret or an argument value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceReason(String);

impl FenceReason {
    /// The longest reason, in bytes.
    pub const MAX: usize = 200;

    /// Wrap `text`, cut at a character boundary to [`Self::MAX`] bytes.
    #[must_use]
    pub fn new(text: &str) -> Self {
        let mut end = text.len().min(Self::MAX);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Self(text[..end].to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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
        serde_json::from_str(self.0.get()).map_err(|error| SectionError(error.to_string()))
    }
}

/// Why a plugin refuses its policy section. A policy with such a section
/// does not load (G2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SectionError(pub String);

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
    fn a_fence_reason_is_cut_at_a_character_boundary() {
        let long = "é".repeat(150);
        let reason = FenceReason::new(&long);
        assert!(reason.as_str().len() <= FenceReason::MAX);
        assert!(reason.as_str().chars().all(|c| c == 'é'));
    }
}
