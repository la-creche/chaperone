//! The name under which an app sees an upstream tool: `<upstream>__<tool>`
//! (`docs/design.md` 7.6). LibreChat passes each MCP tool to the model as a
//! function named `<tool>_mcp_<server>`, and model APIs allow only
//! `A-Z a-z 0-9 _ -` in a function name, up to 64 characters. The limit of
//! [`ExposedName::MAX`] leaves room for that suffix.

use std::fmt;

use crate::ids::{PluginName, ToolName};

/// The text that joins an upstream and a tool. A plugin name cannot hold it.
pub const SEPARATOR: &str = "__";

/// Why a tool cannot be exposed, or a requested name is not valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExposedError {
    #[error("the exposed name is longer than {} characters", ExposedName::MAX)]
    TooLong,
    #[error("the exposed name has a character outside A-Z, a-z, 0-9, '_' and '-'")]
    Character,
    #[error("the exposed name has no \"__\" between an upstream and a tool")]
    NoSeparator,
    #[error("the exposed name does not start with a valid upstream name")]
    BadUpstream,
    #[error("the exposed name does not end with a valid tool name")]
    BadTool,
}

/// One upstream tool, as an app names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExposedName {
    text: String,
    upstream: PluginName,
    tool: ToolName,
}

impl ExposedName {
    /// The longest exposed name, in characters.
    pub const MAX: usize = 50;

    /// Join an upstream and one of its tools.
    ///
    /// # Errors
    ///
    /// Returns an [`ExposedError`] when the result is too long, or when the
    /// tool name holds a character that a model API refuses, such as '.'.
    pub fn join(upstream: &PluginName, tool: &ToolName) -> Result<Self, ExposedError> {
        let text = format!("{upstream}{SEPARATOR}{tool}");
        check_text(&text)?;
        Ok(Self {
            text,
            upstream: upstream.clone(),
            tool: tool.clone(),
        })
    }

    /// Split a name that an app sent. The first `__` ends the upstream.
    ///
    /// # Errors
    ///
    /// Returns an [`ExposedError`] when the text is not a valid exposed name.
    pub fn parse(text: &str) -> Result<Self, ExposedError> {
        check_text(text)?;
        let (upstream, tool) = text
            .split_once(SEPARATOR)
            .ok_or(ExposedError::NoSeparator)?;
        let upstream = PluginName::try_new(upstream).map_err(|_| ExposedError::BadUpstream)?;
        let tool = ToolName::try_new(tool).map_err(|_| ExposedError::BadTool)?;
        Ok(Self {
            text: text.to_owned(),
            upstream,
            tool,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn upstream(&self) -> &PluginName {
        &self.upstream
    }

    #[must_use]
    pub fn tool(&self) -> &ToolName {
        &self.tool
    }
}

impl fmt::Display for ExposedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

fn check_text(text: &str) -> Result<(), ExposedError> {
    if text.len() > ExposedName::MAX {
        return Err(ExposedError::TooLong);
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    if !text.chars().all(allowed) {
        return Err(ExposedError::Character);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(text: &str) -> PluginName {
        PluginName::try_new(text).unwrap()
    }

    fn tool(text: &str) -> ToolName {
        ToolName::try_new(text).unwrap()
    }

    #[test]
    fn join_and_parse_agree() {
        let joined = ExposedName::join(&upstream("vikunja"), &tool("list__tasks")).unwrap();
        assert_eq!(joined.as_str(), "vikunja__list__tasks");
        let parsed = ExposedName::parse("vikunja__list__tasks").unwrap();
        assert_eq!(parsed, joined);
        assert_eq!(parsed.tool().as_str(), "list__tasks");
    }

    #[test]
    fn join_refuses_a_dot_and_a_long_name() {
        let dotted = ExposedName::join(&upstream("vikunja"), &tool("tasks.list"));
        assert_eq!(dotted.unwrap_err(), ExposedError::Character);
        let long = ExposedName::join(&upstream("vikunja"), &tool(&"t".repeat(42)));
        assert_eq!(long.unwrap_err(), ExposedError::TooLong);
        let fits = ExposedName::join(&upstream("vikunja"), &tool(&"t".repeat(41)));
        assert!(fits.is_ok());
    }

    #[test]
    fn parse_refuses_bad_names() {
        assert_eq!(
            ExposedName::parse("vikunja_list").unwrap_err(),
            ExposedError::NoSeparator
        );
        assert_eq!(
            ExposedName::parse("Vikunja__list").unwrap_err(),
            ExposedError::BadUpstream
        );
        assert_eq!(
            ExposedName::parse("vikunja__").unwrap_err(),
            ExposedError::BadTool
        );
        assert_eq!(
            ExposedName::parse("a.b__c").unwrap_err(),
            ExposedError::Character
        );
    }
}
