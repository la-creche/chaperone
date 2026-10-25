//! The plugin manifest (`plugin.toml`) and the facts it states: kind, slot,
//! hooks, secret parameters and the paired half. `docs/design.md` 7.4.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;

use crate::ids::{PluginName, SecretParam};
use crate::strict::{self, ByteCap, StrictError};

/// The largest `plugin.toml` chaperone reads.
pub const PLUGIN_FILE_CAP: ByteCap = ByteCap::new(64 * 1024);

/// How a plugin runs. The directory of a plugin names its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginKind {
    /// Compiled in. Pure.
    Decision,
    /// Compiled in. Does I/O. Never changes a decision.
    Adapter,
    /// A separate process. chaperone speaks MCP to it over stdio.
    Effect,
}

/// A job that exactly one plugin must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Slot {
    FrontDoor,
    Identity,
    SecretSource,
    AuditSink,
    ApprovalChannel,
    Clock,
}

impl Slot {
    /// Every slot, in a fixed order.
    pub const ALL: [Self; 6] = [
        Self::FrontDoor,
        Self::Identity,
        Self::SecretSource,
        Self::AuditSink,
        Self::ApprovalChannel,
        Self::Clock,
    ];

    /// The hook a plugin must serve to fill this slot.
    #[must_use]
    pub const fn hook(self) -> Hook {
        match self {
            Self::FrontDoor => Hook::FrontDoor,
            Self::Identity => Hook::Identity,
            Self::SecretSource => Hook::SecretSource,
            Self::AuditSink => Hook::AuditSink,
            Self::ApprovalChannel => Hook::Approval,
            Self::Clock => Hook::Clock,
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FrontDoor => "front_door",
            Self::Identity => "identity",
            Self::SecretSource => "secret_source",
            Self::AuditSink => "audit_sink",
            Self::ApprovalChannel => "approval_channel",
            Self::Clock => "clock",
        })
    }
}

/// A named point where chaperone calls a plugin. `plugins/AGENTS.md` has
/// the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
    Identity,
    Fence,
    FrontDoor,
    SecretSource,
    AuditSink,
    Approval,
    Upstream,
    Clock,
}

impl Hook {
    /// The plugin kind that serves this hook.
    #[must_use]
    pub const fn kind(self) -> PluginKind {
        match self {
            Self::Identity | Self::Fence => PluginKind::Decision,
            Self::FrontDoor | Self::SecretSource | Self::AuditSink | Self::Clock => {
                PluginKind::Adapter
            }
            Self::Approval | Self::Upstream => PluginKind::Effect,
        }
    }
}

/// `plugin.toml` as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    name: PluginName,
    version: String,
    kind: PluginKind,
    #[serde(default)]
    slot: Option<Slot>,
    hooks: BTreeSet<Hook>,
    #[serde(default)]
    secrets: BTreeSet<SecretParam>,
    #[serde(default)]
    pairs_with: Option<PluginKind>,
    #[serde(default)]
    command: Option<Vec<String>>,
}

/// How chaperone runs a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runtime {
    /// A decision or adapter plugin, compiled into chaperone.
    Compiled,
    /// An effect plugin: the program and its arguments.
    Process { command: Vec<String> },
}

/// A checked plugin manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    name: PluginName,
    version: String,
    kind: PluginKind,
    slot: Option<Slot>,
    hooks: BTreeSet<Hook>,
    secrets: BTreeSet<SecretParam>,
    pairs_with: Option<PluginKind>,
    runtime: Runtime,
}

/// Why a `plugin.toml` is not valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("plugin.toml is not valid for a manifest: {0}")]
    Read(#[from] StrictError),
    #[error("the version is empty or longer than 64 characters")]
    BadVersion,
    #[error("the plugin serves no hook")]
    NoHook,
    #[error("the hook {hook:?} belongs to a {expected:?} plugin, not a {found:?} plugin")]
    HookKind {
        hook: Hook,
        expected: PluginKind,
        found: PluginKind,
    },
    #[error("the plugin claims the slot {slot} but does not serve its hook")]
    SlotHook { slot: Slot },
    #[error("an effect plugin serves one role: upstream or approval, not both")]
    TwoRoles,
    #[error("an effect plugin needs a non-empty command")]
    NoCommand,
    #[error("a compiled plugin has no command")]
    CommandOnCompiled,
    #[error("a plugin cannot pair with its own kind")]
    PairsWithSelf,
    #[error("a {kind:?} plugin cannot take secrets")]
    SecretsOnPure { kind: PluginKind },
}

const VERSION_MAX: usize = 64;

impl Manifest {
    /// Read and check one `plugin.toml`.
    ///
    /// # Errors
    ///
    /// Returns a [`ManifestError`] that names the first rule the file breaks.
    pub fn read(bytes: &[u8]) -> Result<Self, ManifestError> {
        let raw: RawManifest = strict::read_toml(bytes, PLUGIN_FILE_CAP)?;
        Self::check(raw)
    }

    fn check(raw: RawManifest) -> Result<Self, ManifestError> {
        if raw.version.is_empty() || raw.version.len() > VERSION_MAX {
            return Err(ManifestError::BadVersion);
        }
        if raw.hooks.is_empty() {
            return Err(ManifestError::NoHook);
        }
        for hook in &raw.hooks {
            if hook.kind() != raw.kind {
                return Err(ManifestError::HookKind {
                    hook: *hook,
                    expected: hook.kind(),
                    found: raw.kind,
                });
            }
        }
        if let Some(slot) = raw.slot
            && !raw.hooks.contains(&slot.hook())
        {
            return Err(ManifestError::SlotHook { slot });
        }
        if raw.pairs_with == Some(raw.kind) {
            return Err(ManifestError::PairsWithSelf);
        }
        if raw.kind == PluginKind::Decision && !raw.secrets.is_empty() {
            return Err(ManifestError::SecretsOnPure { kind: raw.kind });
        }

        let runtime = match (raw.kind, raw.command) {
            (PluginKind::Effect, Some(command)) if !command.is_empty() => {
                Runtime::Process { command }
            }
            (PluginKind::Effect, Some(_) | None) => return Err(ManifestError::NoCommand),
            (PluginKind::Decision | PluginKind::Adapter, None) => Runtime::Compiled,
            (PluginKind::Decision | PluginKind::Adapter, Some(_)) => {
                return Err(ManifestError::CommandOnCompiled);
            }
        };
        if raw.kind == PluginKind::Effect && raw.hooks.len() > 1 {
            return Err(ManifestError::TwoRoles);
        }

        Ok(Self {
            name: raw.name,
            version: raw.version,
            kind: raw.kind,
            slot: raw.slot,
            hooks: raw.hooks,
            secrets: raw.secrets,
            pairs_with: raw.pairs_with,
            runtime,
        })
    }

    #[must_use]
    pub fn name(&self) -> &PluginName {
        &self.name
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn kind(&self) -> PluginKind {
        self.kind
    }

    #[must_use]
    pub fn slot(&self) -> Option<Slot> {
        self.slot
    }

    #[must_use]
    pub fn serves(&self, hook: Hook) -> bool {
        self.hooks.contains(&hook)
    }

    #[must_use]
    pub fn secrets(&self) -> &BTreeSet<SecretParam> {
        &self.secrets
    }

    #[must_use]
    pub fn pairs_with(&self) -> Option<PluginKind> {
        self.pairs_with
    }

    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Result<Manifest, ManifestError> {
        Manifest::read(text.as_bytes())
    }

    #[test]
    fn reads_an_effect_upstream() {
        let manifest = read(
            r#"
                name = "vikunja"
                version = "1.0.0"
                kind = "effect"
                hooks = ["upstream"]
                secrets = ["VIKUNJA_TOKEN"]
                command = ["vikunja-mcp"]
            "#,
        )
        .unwrap();
        assert_eq!(manifest.kind(), PluginKind::Effect);
        assert!(manifest.serves(Hook::Upstream));
        assert_eq!(
            manifest.runtime(),
            &Runtime::Process {
                command: vec!["vikunja-mcp".into()]
            }
        );
    }

    #[test]
    fn reads_a_slot_plugin() {
        let manifest = read(
            r#"
                name = "bearer"
                version = "1"
                kind = "decision"
                slot = "identity"
                hooks = ["identity"]
            "#,
        )
        .unwrap();
        assert_eq!(manifest.slot(), Some(Slot::Identity));
        assert_eq!(manifest.runtime(), &Runtime::Compiled);
    }

    #[test]
    fn refuses_a_hook_of_another_kind() {
        let error = read(
            r#"
            name = "x"
            version = "1"
            kind = "decision"
            hooks = ["upstream"]
        "#,
        )
        .unwrap_err();
        assert!(matches!(error, ManifestError::HookKind { .. }));
    }

    #[test]
    fn refuses_a_slot_without_its_hook() {
        let error = read(
            r#"
                name = "x"
                version = "1"
                kind = "decision"
                slot = "identity"
                hooks = ["fence"]
            "#,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ManifestError::SlotHook {
                slot: Slot::Identity
            }
        );
    }

    #[test]
    fn refuses_an_effect_plugin_with_two_roles() {
        let error = read(
            r#"
                name = "x"
                version = "1"
                kind = "effect"
                hooks = ["upstream", "approval"]
                command = ["x"]
            "#,
        )
        .unwrap_err();
        assert_eq!(error, ManifestError::TwoRoles);
    }

    #[test]
    fn refuses_an_effect_plugin_without_a_command() {
        let none = read(
            r#"
            name = "x"
            version = "1"
            kind = "effect"
            hooks = ["upstream"]
        "#,
        );
        assert_eq!(none.unwrap_err(), ManifestError::NoCommand);
        let empty = read(
            r#"
                name = "x"
                version = "1"
                kind = "effect"
                hooks = ["upstream"]
                command = []
            "#,
        );
        assert_eq!(empty.unwrap_err(), ManifestError::NoCommand);
    }

    #[test]
    fn refuses_a_command_on_a_compiled_plugin() {
        let error = read(
            r#"
                name = "x"
                version = "1"
                kind = "adapter"
                hooks = ["audit_sink"]
                command = ["x"]
            "#,
        )
        .unwrap_err();
        assert_eq!(error, ManifestError::CommandOnCompiled);
    }

    #[test]
    fn refuses_secrets_on_a_decision_plugin() {
        let error = read(
            r#"
                name = "x"
                version = "1"
                kind = "decision"
                hooks = ["fence"]
                secrets = ["T"]
            "#,
        )
        .unwrap_err();
        assert!(matches!(error, ManifestError::SecretsOnPure { .. }));
    }

    #[test]
    fn refuses_an_unknown_field() {
        let error = read(
            r#"
                name = "x"
                version = "1"
                kind = "decision"
                hooks = ["fence"]
                extra = 1
            "#,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ManifestError::Read(StrictError::Shape { .. })
        ));
    }

    #[test]
    fn refuses_a_json_manifest() {
        let error =
            read(r#"{"name":"x","version":"1","kind":"decision","hooks":["fence"]}"#).unwrap_err();
        assert!(matches!(
            error,
            ManifestError::Read(StrictError::Syntax { line: 1, .. })
        ));
    }

    #[test]
    fn refuses_a_schema_field() {
        let error = read(
            r#"
                "$schema" = "urn:chaperone:plugin:1"
                name = "x"
                version = "1"
                kind = "decision"
                hooks = ["fence"]
            "#,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ManifestError::Read(StrictError::Shape { .. })
        ));
    }

    #[test]
    fn reads_comments_in_a_manifest() {
        let manifest = read(
            r#"
                # A fence with no slot.
                name = "x"
                version = "1" # The plugin version.
                kind = "decision"
                hooks = ["fence"]
            "#,
        )
        .unwrap();
        assert!(manifest.serves(Hook::Fence));
    }
}
