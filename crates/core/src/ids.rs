//! One newtype per kind of name. A constructor checks the grammar, so a value
//! of each type is valid by construction. Each type reads from JSON through
//! the same check.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// Why a text is not a valid name of its kind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{text:?} is not a valid {kind}: {rule}")]
pub struct NameError {
    kind: &'static str,
    text: String,
    rule: &'static str,
}

/// The grammar of a slug: an app ID, a plugin name or a secret name.
const SLUG_RULE: &str = "1 to 64 characters of a-z, 0-9, '-' and '_', starting with a-z or 0-9";
const SLUG_MAX: usize = 64;

/// The grammar of a tool name or an argument name. It follows the MCP
/// guidance for tool names.
const TOOL_RULE: &str = "1 to 128 characters of A-Z, a-z, 0-9, '_', '-' and '.'";
const TOOL_MAX: usize = 128;

fn is_slug(text: &str) -> bool {
    let mut chars = text.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok
        && text.len() <= SLUG_MAX
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn is_tool_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= TOOL_MAX
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident, $kind:literal, $valid:ident, $rule:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Check `text` and wrap it.
            ///
            /// # Errors
            ///
            /// Returns a [`NameError`] when `text` breaks the grammar.
            pub fn new(text: impl Into<String>) -> Result<Self, NameError> {
                let text = text.into();
                if $valid(&text) {
                    Ok(Self(text))
                } else {
                    Err(NameError { kind: $kind, text, rule: $rule })
                }
            }

            /// The name as text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::new(text).map_err(serde::de::Error::custom)
            }
        }
    };
}

name_type!(
    /// The ID of one app instance in the policy file.
    AppId, "app ID", is_slug, SLUG_RULE
);
name_type!(
    /// The name of one plugin. It equals the plugin's directory name.
    PluginName, "plugin name", is_slug, SLUG_RULE
);
name_type!(
    /// The name of one secret. It equals the secret's file name.
    SecretName, "secret name", is_slug, SLUG_RULE
);
name_type!(
    /// The name of one tool of an upstream.
    ToolName, "tool name", is_tool_name, TOOL_RULE
);
name_type!(
    /// The name of one top-level argument of a tool call.
    ArgName, "argument name", is_tool_name, TOOL_RULE
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slug_takes_lower_case_digits_dash_and_underscore() {
        assert!(AppId::new("librechat-1_a").is_ok());
        assert!(AppId::new("0app").is_ok());
    }

    #[test]
    fn a_slug_refuses_bad_text() {
        for bad in ["", "-x", "_x", "Upper", "a b", "a/b", "é", &"a".repeat(65)] {
            assert!(AppId::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_tool_name_takes_the_mcp_characters() {
        assert!(ToolName::new("listTasks.v2-x_y").is_ok());
        assert!(ToolName::new("a b").is_err());
        assert!(ToolName::new("").is_err());
        assert!(ToolName::new("a".repeat(129)).is_err());
    }

    #[test]
    fn a_name_reads_from_json_through_the_check() {
        let ok: Result<PluginName, _> = serde_json::from_str("\"ha-call\"");
        assert!(ok.is_ok());
        let bad: Result<PluginName, _> = serde_json::from_str("\"HA call\"");
        assert!(bad.is_err());
    }
}
