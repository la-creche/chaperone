//! The policy file (`policy.json`): app instances, token digests, limits,
//! grants, argument fences, approval rules and plugin sections. A policy
//! that does not load denies every call (G2). `docs/design.md` 6.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;
use serde_json::value::RawValue;

use crate::hook::{Fence, PreparedFence, RawSection, SectionError};
use crate::ids::{AppId, ArgName, PluginName, ToolName};
use crate::install::Setup;
use crate::strict::{self, ByteCap, StrictError};

/// The largest `policy.json` chaperone reads.
pub const POLICY_FILE_CAP: ByteCap = ByteCap::new(1024 * 1024);

const POLICY_VERSION: u32 = 1;
const DIGESTS_MAX: usize = 2;

/// The SHA-256 digest of one bearer token.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    /// Wrap a digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TokenDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenDigest({})", hex::encode(self.0))
    }
}

/// Why a text is not a token digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a token digest is 64 lower-case hex characters")]
pub struct DigestError;

impl TryFrom<String> for TokenDigest {
    type Error = DigestError;

    fn try_from(text: String) -> Result<Self, DigestError> {
        let lower_hex = text.len() == 64
            && text
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
        let mut bytes = [0_u8; 32];
        if !lower_hex || hex::decode_to_slice(&text, &mut bytes).is_err() {
            return Err(DigestError);
        }
        Ok(Self(bytes))
    }
}

/// One allowed or denied value of an argument fence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    Bool(bool),
    Int(i64),
    String(String),
}

/// A fence on one top-level argument.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum ArgumentFence {
    /// The argument must be present and equal one of these values.
    Allow(Vec<Scalar>),
    /// The argument must not equal one of these values. An argument that is
    /// not a scalar is refused, because it cannot be compared.
    Deny(Vec<Scalar>),
}

/// Whether a call to a tool needs a human approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Approval {
    #[default]
    None,
    Required,
}

/// The grant of one tool.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolGrant {
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    approval: Approval,
    #[serde(default)]
    arguments: BTreeMap<ArgName, ArgumentFence>,
}

impl ToolGrant {
    /// The operator's reason for this grant.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    #[must_use]
    pub fn approval(&self) -> Approval {
        self.approval
    }

    #[must_use]
    pub fn arguments(&self) -> &BTreeMap<ArgName, ArgumentFence> {
        &self.arguments
    }
}

/// The grant of one upstream.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamGrant {
    #[serde(default)]
    note: Option<String>,
    tools: BTreeMap<ToolName, ToolGrant>,
}

/// The limits of one app instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// The most calls the app instance may make in one minute.
    pub calls_per_minute: u32,
    /// The most gates the app instance may have pending at one time.
    pub max_pending_gates: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApp {
    #[serde(default)]
    note: Option<String>,
    token_sha256: Vec<TokenDigest>,
    limits: Limits,
    #[serde(default)]
    grants: BTreeMap<PluginName, UpstreamGrant>,
    #[serde(default)]
    plugins: BTreeMap<PluginName, Box<RawValue>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(rename = "$schema", default)]
    _schema: Option<String>,
    version: u32,
    #[serde(default)]
    apps: BTreeMap<AppId, RawApp>,
}

/// One active fence with its section for one app instance already read.
#[derive(Debug)]
pub(crate) struct ActiveFence {
    pub(crate) plugin: PluginName,
    pub(crate) fence: Box<dyn PreparedFence>,
}

/// One loaded app instance.
#[derive(Debug)]
pub struct App {
    note: Option<String>,
    digests: Vec<TokenDigest>,
    limits: Limits,
    grants: BTreeMap<PluginName, UpstreamGrant>,
    fences: Vec<ActiveFence>,
}

impl App {
    /// The operator's reason for this app instance.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// The operator's reason for the grant of one upstream.
    #[must_use]
    pub fn upstream_note(&self, upstream: &PluginName) -> Option<&str> {
        self.grants.get(upstream)?.note.as_deref()
    }

    /// The token digests of this app instance: one or two.
    #[must_use]
    pub fn digests(&self) -> &[TokenDigest] {
        &self.digests
    }

    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// The grant of one tool, if the policy grants it.
    #[must_use]
    pub fn grant(&self, upstream: &PluginName, tool: &ToolName) -> Option<&ToolGrant> {
        self.grants.get(upstream)?.tools.get(tool)
    }

    /// Every granted tool, in name order.
    pub fn granted(&self) -> impl Iterator<Item = (&PluginName, &ToolName)> {
        self.grants
            .iter()
            .flat_map(|(upstream, grant)| grant.tools.keys().map(move |tool| (upstream, tool)))
    }

    /// The prepared fences, in plugin name order.
    pub(crate) fn fences(&self) -> &[ActiveFence] {
        &self.fences
    }
}

/// A loaded, checked policy.
#[derive(Debug)]
pub struct Policy {
    apps: BTreeMap<AppId, App>,
}

/// Why `policy.json` does not load. Each one denies every call (G2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("policy.json is not valid: {0}")]
    Read(#[from] StrictError),
    #[error("policy.json has version {found}, this chaperone reads version {POLICY_VERSION}")]
    Version { found: u32 },
    #[error("the app {app} needs one or two token digests")]
    DigestCount { app: AppId },
    #[error("the apps {first} and {second} share a token digest")]
    SharedDigest { first: AppId, second: AppId },
    #[error("the app {app} grants tools of {upstream}, which is not an active upstream")]
    UnknownUpstream { app: AppId, upstream: PluginName },
    #[error("the app {app} grants no tool of {upstream}")]
    EmptyGrant { app: AppId, upstream: PluginName },
    #[error("the app {app} fences {argument} of {tool} with an empty list")]
    EmptyFence {
        app: AppId,
        tool: ToolName,
        argument: ArgName,
    },
    #[error("the app {app} has a section for {plugin}, which is not an active fence")]
    UnknownSection { app: AppId, plugin: PluginName },
    #[error("the active fence {0} has no compiled code in this chaperone")]
    MissingFence(PluginName),
    #[error("two compiled fences are named {0}")]
    DuplicateFence(PluginName),
    #[error("the fence {plugin} refuses its section in the app {app}: {error}")]
    Section {
        app: AppId,
        plugin: PluginName,
        error: SectionError,
    },
}

impl Policy {
    /// Read `policy.json` and check it against the setup. Each active fence
    /// in `setup` needs its code in `fences`.
    ///
    /// # Errors
    ///
    /// Returns the first [`PolicyError`] found. Checks run in a fixed order.
    pub fn load(bytes: &[u8], setup: &Setup, fences: &[&dyn Fence]) -> Result<Self, PolicyError> {
        let raw: RawPolicy = strict::read(bytes, POLICY_FILE_CAP)?;
        if raw.version != POLICY_VERSION {
            return Err(PolicyError::Version { found: raw.version });
        }

        // Two fences of one name would let the registration order pick
        // the code that runs (G10). Refuse the pair instead.
        let mut code: BTreeMap<&PluginName, &dyn Fence> = BTreeMap::new();
        for fence in fences {
            if code.insert(fence.name(), *fence).is_some() {
                return Err(PolicyError::DuplicateFence(fence.name().clone()));
            }
        }
        for name in setup.fences() {
            if !code.contains_key(name) {
                return Err(PolicyError::MissingFence(name.clone()));
            }
        }

        let mut owners: BTreeMap<TokenDigest, AppId> = BTreeMap::new();
        let mut apps = BTreeMap::new();
        for (id, raw_app) in raw.apps {
            let app = load_app(&id, raw_app, setup, &code)?;
            for digest in &app.digests {
                if let Some(first) = owners.get(digest) {
                    return Err(PolicyError::SharedDigest {
                        first: first.clone(),
                        second: id,
                    });
                }
                owners.insert(digest.clone(), id.clone());
            }
            apps.insert(id, app);
        }
        Ok(Self { apps })
    }

    /// One app instance.
    #[must_use]
    pub fn app(&self, id: &AppId) -> Option<&App> {
        self.apps.get(id)
    }

    /// Whether some app instance is granted this tool of this upstream.
    #[must_use]
    pub fn configures(&self, upstream: &PluginName, tool: &ToolName) -> bool {
        self.apps
            .values()
            .any(|app| app.grant(upstream, tool).is_some())
    }

    /// Every app instance, in ID order.
    pub fn apps(&self) -> impl Iterator<Item = (&AppId, &App)> {
        self.apps.iter()
    }
}

fn load_app(
    id: &AppId,
    raw: RawApp,
    setup: &Setup,
    code: &BTreeMap<&PluginName, &dyn Fence>,
) -> Result<App, PolicyError> {
    if raw.token_sha256.is_empty() || raw.token_sha256.len() > DIGESTS_MAX {
        return Err(PolicyError::DigestCount { app: id.clone() });
    }
    let mut seen = BTreeSet::new();
    for digest in &raw.token_sha256 {
        if !seen.insert(digest) {
            return Err(PolicyError::SharedDigest {
                first: id.clone(),
                second: id.clone(),
            });
        }
    }

    for (upstream, grant) in &raw.grants {
        if !setup.upstreams().contains(upstream) {
            return Err(PolicyError::UnknownUpstream {
                app: id.clone(),
                upstream: upstream.clone(),
            });
        }
        if grant.tools.is_empty() {
            return Err(PolicyError::EmptyGrant {
                app: id.clone(),
                upstream: upstream.clone(),
            });
        }
        for (tool, tool_grant) in &grant.tools {
            for (argument, fence) in &tool_grant.arguments {
                let empty = match fence {
                    ArgumentFence::Allow(values) | ArgumentFence::Deny(values) => values.is_empty(),
                };
                if empty {
                    return Err(PolicyError::EmptyFence {
                        app: id.clone(),
                        tool: tool.clone(),
                        argument: argument.clone(),
                    });
                }
            }
        }
    }

    for plugin in raw.plugins.keys() {
        if !setup.fences().contains(plugin) {
            return Err(PolicyError::UnknownSection {
                app: id.clone(),
                plugin: plugin.clone(),
            });
        }
    }

    let mut fences = Vec::new();
    for name in setup.fences() {
        let Some(fence) = code.get(name) else {
            return Err(PolicyError::MissingFence(name.clone()));
        };
        let section = raw.plugins.get(name).map(|raw| RawSection::new(raw));
        let prepared = fence
            .prepare(section)
            .map_err(|error| PolicyError::Section {
                app: id.clone(),
                plugin: name.clone(),
                error,
            })?;
        fences.push(ActiveFence {
            plugin: name.clone(),
            fence: prepared,
        });
    }

    Ok(App {
        note: raw.note,
        digests: raw.token_sha256,
        limits: raw.limits,
        grants: raw.grants,
        fences,
    })
}
