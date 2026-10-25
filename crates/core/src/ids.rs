//! One distinct type per kind of name. [`Name::try_new`] checks the grammar
//! of the kind, so each value is valid by construction. JSON reads through
//! the same check.

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Why a text is not a valid name of its kind. The error does not keep the
/// text: a rejected name from a request can be a token (G9).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a valid {kind}: {rule}")]
pub struct NameError {
    kind: &'static str,
    rule: &'static str,
}

/// The grammar of one kind of name. Only this crate defines kinds.
pub trait NameKind: sealed::Sealed {
    /// The kind, as an error message names it.
    const KIND: &'static str;
    /// The grammar, as an error message states it.
    const RULE: &'static str;
    /// Whether `text` follows the grammar.
    fn is_valid(text: &str) -> bool;
}

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// A name of kind `K`. Use the aliases: [`AppId`], [`PluginName`],
/// [`SecretName`], [`ToolName`], [`ArgName`], [`SecretParam`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String", bound = "K: NameKind + Clone")]
pub struct Name<K> {
    text: String,
    kind: PhantomData<K>,
}

impl<K: NameKind> Name<K> {
    /// Check `text` and wrap a copy of it.
    ///
    /// # Errors
    ///
    /// Returns a [`NameError`] when `text` breaks the grammar of `K`.
    pub fn try_new(text: &str) -> Result<Self, NameError> {
        Self::try_from(text.to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl<K: NameKind> TryFrom<String> for Name<K> {
    type Error = NameError;

    fn try_from(text: String) -> Result<Self, NameError> {
        if K::is_valid(&text) {
            Ok(Self {
                text,
                kind: PhantomData,
            })
        } else {
            Err(NameError {
                kind: K::KIND,
                rule: K::RULE,
            })
        }
    }
}

impl<K: NameKind> FromStr for Name<K> {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, NameError> {
        Self::try_new(text)
    }
}

impl<K> From<Name<K>> for String {
    fn from(name: Name<K>) -> Self {
        name.text
    }
}

impl<K> fmt::Display for Name<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

const SLUG_MAX: usize = 64;
const SLUG_RULE: &str = "1 to 64 characters of a-z, 0-9, '-' and '_', starting with a-z or 0-9";

fn is_slug(text: &str) -> bool {
    let mut chars = text.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && text.len() <= SLUG_MAX
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

// The MCP guidance for tool names.
const TOOL_MAX: usize = 128;
const TOOL_RULE: &str = "1 to 128 characters of A-Z, a-z, 0-9, '_', '-' and '.'";

fn is_tool_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= TOOL_MAX
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AppIdKind {}

impl sealed::Sealed for AppIdKind {}

impl NameKind for AppIdKind {
    const KIND: &'static str = "app ID";
    const RULE: &'static str = SLUG_RULE;

    fn is_valid(text: &str) -> bool {
        is_slug(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PluginNameKind {}

impl sealed::Sealed for PluginNameKind {}

// The front door joins an upstream and a tool with "__", so a plugin name
// may not contain it (`docs/design.md` 7.6).
const PLUGIN_RULE: &str =
    "1 to 64 characters of a-z, 0-9, '-' and '_', starting with a-z or 0-9, with no \"__\"";

impl NameKind for PluginNameKind {
    const KIND: &'static str = "plugin name";
    const RULE: &'static str = PLUGIN_RULE;

    fn is_valid(text: &str) -> bool {
        is_slug(text) && !text.contains("__")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretNameKind {}

impl sealed::Sealed for SecretNameKind {}

impl NameKind for SecretNameKind {
    const KIND: &'static str = "secret name";
    const RULE: &'static str = SLUG_RULE;

    fn is_valid(text: &str) -> bool {
        is_slug(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ToolNameKind {}

impl sealed::Sealed for ToolNameKind {}

impl NameKind for ToolNameKind {
    const KIND: &'static str = "tool name";
    const RULE: &'static str = TOOL_RULE;

    fn is_valid(text: &str) -> bool {
        is_tool_name(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArgNameKind {}

impl sealed::Sealed for ArgNameKind {}

impl NameKind for ArgNameKind {
    const KIND: &'static str = "argument name";
    const RULE: &'static str = TOOL_RULE;

    fn is_valid(text: &str) -> bool {
        is_tool_name(text)
    }
}

const PARAM_MAX: usize = 64;
const PARAM_RULE: &str = "1 to 64 characters of A-Z, a-z, 0-9 and '_', not starting with a digit";

fn is_param(text: &str) -> bool {
    let first_ok = text
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    first_ok
        && text.len() <= PARAM_MAX
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretParamKind {}

impl sealed::Sealed for SecretParamKind {}

impl NameKind for SecretParamKind {
    const KIND: &'static str = "secret parameter";
    const RULE: &'static str = PARAM_RULE;

    fn is_valid(text: &str) -> bool {
        is_param(text)
    }
}

/// The ID of one app instance in the policy file.
pub type AppId = Name<AppIdKind>;
/// The name of one plugin. It equals the plugin's directory name.
pub type PluginName = Name<PluginNameKind>;
/// The name of one secret. It equals the secret's file name.
pub type SecretName = Name<SecretNameKind>;
/// The name of one tool of an upstream.
pub type ToolName = Name<ToolNameKind>;
/// The name of one top-level argument of a tool call.
pub type ArgName = Name<ArgNameKind>;
/// The name under which a plugin receives one secret. For a plugin with
/// the env exception, it is the name of the environment variable.
pub type SecretParam = Name<SecretParamKind>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slug_takes_lower_case_digits_dash_and_underscore() {
        assert!(AppId::try_new("librechat-1_a").is_ok());
        assert!(AppId::try_new("0app").is_ok());
    }

    #[test]
    fn a_slug_refuses_bad_text() {
        for bad in ["", "-x", "_x", "Upper", "a b", "a/b", "é", &"a".repeat(65)] {
            assert!(AppId::try_new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_plugin_name_refuses_a_double_underscore() {
        assert!(PluginName::try_new("ha_call").is_ok());
        assert!(PluginName::try_new("ha__call").is_err());
    }

    #[test]
    fn a_tool_name_takes_the_mcp_characters() {
        assert!(ToolName::try_new("listTasks.v2-x_y").is_ok());
        assert!(ToolName::try_new("a b").is_err());
        assert!(ToolName::try_new("").is_err());
        assert!(ToolName::try_new(&"a".repeat(129)).is_err());
    }

    #[test]
    fn a_name_reads_from_json_through_the_check() {
        let ok: Result<PluginName, _> = serde_json::from_str("\"ha-call\"");
        assert!(ok.is_ok());
        let bad: Result<PluginName, _> = serde_json::from_str("\"HA call\"");
        assert!(bad.is_err());
    }

    #[test]
    fn a_name_writes_to_json_as_its_text() {
        let name = PluginName::try_new("ha-call").unwrap();
        assert_eq!(serde_json::to_string(&name).unwrap(), "\"ha-call\"");
    }

    #[test]
    fn a_name_parses_with_from_str() {
        let name: ToolName = "ha_call".parse().unwrap();
        assert_eq!(name.as_str(), "ha_call");
    }

    #[test]
    fn the_error_names_the_kind_and_not_the_text() {
        let error = SecretName::try_new("SECRET-text").unwrap_err();
        let shown = format!("{error} {error:?}");
        assert!(shown.contains("secret name"));
        assert!(!shown.contains("SECRET"), "{shown}");
    }
}
