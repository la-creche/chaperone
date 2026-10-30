//! The policy file (`policy.toml`): app instances, token digests, limits,
//! grants, argument fences, approval rules and plugin sections. A policy
//! that does not load denies every call (G2). A fault inside one app table
//! refuses that app alone, and the other apps load. `docs/design.md` 6.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hook::{CrossAppError, Fence, PreparedFence, RawSection, SectionError};
use crate::ids::{AppId, ArgName, PluginName, ToolName};
use crate::install::Setup;
use crate::strict::{self, ByteCap, StrictError};

/// The largest `policy.toml` chaperone reads.
pub const POLICY_FILE_CAP: ByteCap = ByteCap::new(1024 * 1024);

const POLICY_VERSION: u32 = 1;
const DIGESTS_MAX: usize = 2;
const BOUND_MIN_SECONDS: u64 = 1;
const BOUND_MAX_SECONDS: u64 = 120;
const INFLIGHT_MIN: u32 = 1;
const INFLIGHT_MAX: u32 = 8;

/// The longest chaperone waits for one call to one upstream, in whole
/// seconds from 1 to 120 (`docs/design.md` 5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamBound(u64);

impl UpstreamBound {
    /// The bound of a grant that sets no `timeout_s`.
    pub const DEFAULT: Self = Self(30);

    /// The bound of `seconds`, or `None` outside 1 to 120.
    #[must_use]
    pub fn from_seconds(seconds: i64) -> Option<Self> {
        let seconds = u64::try_from(seconds).ok()?;
        (BOUND_MIN_SECONDS..=BOUND_MAX_SECONDS)
            .contains(&seconds)
            .then_some(Self(seconds))
    }

    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

/// The most calls of one app instance to one upstream that may run at one
/// time, from 1 to 8 (`docs/design.md` 5.2 and 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InflightLimit(u32);

impl InflightLimit {
    /// The limit of `count`, or `None` outside 1 to 8.
    #[must_use]
    pub fn from_count(count: i64) -> Option<Self> {
        let count = u32::try_from(count).ok()?;
        (INFLIGHT_MIN..=INFLIGHT_MAX)
            .contains(&count)
            .then_some(Self(count))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The SHA-256 digest of one bearer token.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TokenDigest([u8; 32]);

impl From<TokenDigest> for String {
    fn from(digest: TokenDigest) -> Self {
        hex::encode(digest.0)
    }
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    Bool(bool),
    Int(i64),
    String(String),
}

/// A fence on one top-level argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum ArgumentFence {
    /// The argument must be present and equal one of these values.
    Allow(Vec<Scalar>),
    /// The argument must not equal one of these values. An argument that is
    /// not a scalar is refused, because it cannot be compared.
    Deny(Vec<Scalar>),
}

/// Whether a call to a tool needs a human approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Approval {
    #[default]
    None,
    Required,
}

/// The grant of one tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolGrant {
    /// The operator's reason for the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamGrant {
    /// The operator's reason for the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    /// The bound of one call, in seconds. See [`UpstreamBound`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout_s: Option<i64>,
    /// The most calls to the upstream in flight at one time. See
    /// [`InflightLimit`]. Without it, the policy sets no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_inflight: Option<i64>,
    /// The granted tools of the upstream, by tool name.
    tools: BTreeMap<ToolName, ToolGrant>,
}

/// The limits of one app instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// The most calls the app instance may make in one minute.
    pub calls_per_minute: u32,
    /// The most gates the app instance may have pending at one time.
    pub max_pending_gates: u32,
}

/// One app instance, as `policy.toml` holds it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApp {
    /// The operator's reason for the app instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    /// One or two token digests, so a token can rotate.
    token_sha256: Vec<TokenDigest>,
    limits: Limits,
    /// The granted upstreams, by plugin name.
    #[serde(default)]
    grants: BTreeMap<PluginName, UpstreamGrant>,
    /// The section of each active fence plugin, by plugin name. Each
    /// plugin states the shape of its own section.
    #[serde(default)]
    plugins: BTreeMap<PluginName, toml::Value>,
}

/// `policy.toml` as written. Each app table is read as a value first, so a
/// table of the wrong shape refuses its own app and no other.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    /// The version of the file shape. This chaperone reads 1.
    version: u32,
    /// The app instances, by app ID.
    #[serde(default)]
    apps: BTreeMap<AppId, toml::Value>,
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
    bounds: BTreeMap<PluginName, UpstreamBound>,
    inflight: BTreeMap<PluginName, InflightLimit>,
    /// The plugin sections as the policy file holds them. Each fence
    /// prepares its own at load.
    sections: BTreeMap<PluginName, toml::Value>,
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

    /// The bound of a call to `upstream`, or `None` when the policy grants
    /// no tool of it.
    #[must_use]
    pub fn upstream_bound(&self, upstream: &PluginName) -> Option<UpstreamBound> {
        self.bounds.get(upstream).copied()
    }

    /// The in-flight limit of calls to `upstream`, or `None` when the grant
    /// sets none or the policy grants no tool of it.
    #[must_use]
    pub fn inflight_limit(&self, upstream: &PluginName) -> Option<InflightLimit> {
        self.inflight.get(upstream).copied()
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

/// A loaded, checked policy. An app that the load refused is not in it, so
/// each call of that app is denied.
#[derive(Debug)]
pub struct Policy {
    apps: BTreeMap<AppId, App>,
    refused: BTreeMap<AppId, PolicyError>,
}

/// Why `policy.toml` does not load, or why it refuses one app. A refusal of
/// the file denies every call (G2). A refusal of one app denies each call
/// of that app.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("policy.toml is not valid: {0}")]
    Read(#[from] StrictError),
    #[error("policy.toml has version {found}, this chaperone reads version {POLICY_VERSION}")]
    Version { found: u32 },
    #[error("the app {0} is not in policy.toml")]
    UnknownApp(AppId),
    #[error("the app {app} is not valid: {error}")]
    AppShape { app: AppId, error: String },
    #[error("the app {app} already holds {DIGESTS_MAX} token digests")]
    DigestsFull { app: AppId },
    #[error("the token digests of the app {app} are not one array in policy.toml")]
    DigestArray { app: AppId },
    #[error("the app {app} needs one or two token digests")]
    DigestCount { app: AppId },
    #[error("the apps {first} and {second} share a token digest")]
    SharedDigest { first: AppId, second: AppId },
    #[error("the app {app} grants tools of {upstream}, which is not an active upstream")]
    UnknownUpstream { app: AppId, upstream: PluginName },
    #[error("the app {app} grants tools of {upstream}, which did not start")]
    UpstreamDown { app: AppId, upstream: PluginName },
    #[error("the app {app} grants no tool of {upstream}")]
    EmptyGrant { app: AppId, upstream: PluginName },
    #[error("the app {app} sets timeout_s of {upstream} outside 1 to 120 seconds")]
    UpstreamBound { app: AppId, upstream: PluginName },
    #[error("the app {app} sets max_inflight of {upstream} outside 1 to 8")]
    InflightLimit { app: AppId, upstream: PluginName },
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
    #[error("the fence {plugin} refuses the app {}: {error}", error.caller)]
    CrossApp {
        plugin: PluginName,
        error: CrossAppError,
    },
}

/// A [`Fence`] of any section type, as [`Policy::load`] takes it. Every
/// fence is one, and nothing else can be one.
pub trait FenceCode: Send + Sync + fmt::Debug + sealed::Sealed {
    /// The plugin name of the fence.
    fn plugin(&self) -> &PluginName;

    /// Prepare the section of each app instance in `apps` that `refused`
    /// does not hold, then check the sections together. A section that
    /// does not prepare refuses its app. A rule that two apps break
    /// together refuses the caller of the rule, and the check runs again
    /// without it. Each app that passes gets its prepared fence.
    fn prepare_apps(
        &self,
        apps: &mut BTreeMap<AppId, App>,
        refused: &mut BTreeMap<AppId, PolicyError>,
    );
}

mod sealed {
    pub trait Sealed {}

    impl<F: super::Fence> Sealed for F {}
}

impl<F: Fence> FenceCode for F {
    fn plugin(&self) -> &PluginName {
        self.name()
    }

    fn prepare_apps(
        &self,
        apps: &mut BTreeMap<AppId, App>,
        refused: &mut BTreeMap<AppId, PolicyError>,
    ) {
        let plugin = self.name();
        let mut prepared = BTreeMap::new();
        for (id, app) in apps.iter() {
            if refused.contains_key(id) {
                continue;
            }
            let section = app.sections.get(plugin).map(RawSection::new);
            match self.prepare(section) {
                Ok(fence) => {
                    prepared.insert(id.clone(), fence);
                }
                Err(error) => {
                    let app = id.clone();
                    let plugin = plugin.clone();
                    refused.insert(id.clone(), PolicyError::Section { app, plugin, error });
                }
            }
        }
        while let Err(error) = self.check_sections(&prepared.iter().collect()) {
            let caller = error.caller.clone();
            let refusal = PolicyError::CrossApp {
                plugin: plugin.clone(),
                error,
            };
            if prepared.remove(&caller).is_none() {
                // The fence names an app it was not given. The check cannot
                // say which app breaks the rule, so it refuses each one.
                for (id, _) in std::mem::take(&mut prepared) {
                    refused.insert(id, refusal.clone());
                }
                break;
            }
            refused.insert(caller, refusal);
        }
        for (id, fence) in prepared {
            if let Some(app) = apps.get_mut(&id) {
                app.fences.push(ActiveFence {
                    plugin: plugin.clone(),
                    fence: Box::new(fence),
                });
            }
        }
    }
}

/// Read `policy.toml` through the strict reader.
fn read_raw(bytes: &[u8]) -> Result<RawPolicy, PolicyError> {
    Ok(strict::read_toml(bytes, POLICY_FILE_CAP)?)
}

/// `policy.toml` with `digest` added to the app instance `app`
/// (`docs/design.md` 9). The digest goes in after the last digest of the
/// app. The rest of the text, comments too, stays as the operator wrote it.
///
/// # Errors
///
/// Returns a [`PolicyError`] when the file does not read, the app is not in
/// it, or the app already holds two digests.
pub fn with_digest(bytes: &[u8], app: &AppId, digest: TokenDigest) -> Result<Vec<u8>, PolicyError> {
    let mut raw = read_raw(bytes)?;
    let instance = raw
        .apps
        .remove(app)
        .ok_or_else(|| PolicyError::UnknownApp(app.clone()))?;
    if raw_app(app, instance)?.token_sha256.len() >= DIGESTS_MAX {
        return Err(PolicyError::DigestsFull { app: app.clone() });
    }
    let not_found = || PolicyError::DigestArray { app: app.clone() };
    let text = std::str::from_utf8(bytes).map_err(|_| not_found())?;
    let (at, comma) = digest_slot(text, app).ok_or_else(not_found)?;
    let (head, tail) = (
        text.get(..at).ok_or_else(not_found)?,
        text.get(at..).ok_or_else(not_found)?,
    );
    let separator = if comma { ", " } else { "" };
    let digest = String::from(digest);
    let after = format!("{head}{separator}\"{digest}\"{tail}").into_bytes();
    let instance = read_raw(&after)?.apps.remove(app).ok_or_else(not_found)?;
    raw_app(app, instance)?;
    Ok(after)
}

/// The byte offset in `text` where a new digest of `app` goes, and whether
/// a comma must come before it. A new digest follows the last digest of the
/// array, so a trailing comma or a comment in the array stays valid.
fn digest_slot(text: &str, app: &AppId) -> Option<(usize, bool)> {
    let document = toml::de::DeTable::parse(text).ok()?;
    let digests = document
        .get_ref()
        .get("apps")?
        .get_ref()
        .get(app.as_str())?
        .get_ref()
        .get("token_sha256")?;
    let toml::de::DeValue::Array(list) = digests.get_ref() else {
        return None;
    };
    match list.last() {
        Some(last) => Some((last.span().end, true)),
        None => Some((digests.span().start + 1, false)),
    }
}

impl Policy {
    /// Read `policy.toml` and check it against the setup. Each active fence
    /// in `setup` needs its code in `fences`. A fault inside one app table
    /// refuses that app: [`Policy::refused`] names it, with its fault, and
    /// the other apps load.
    ///
    /// # Errors
    ///
    /// Returns the first [`PolicyError`] of the file itself: the strict
    /// reader, the version, or the fence code of this build.
    pub fn load(
        bytes: &[u8],
        setup: &Setup,
        fences: &[&dyn FenceCode],
    ) -> Result<Self, PolicyError> {
        let raw: RawPolicy = read_raw(bytes)?;
        if raw.version != POLICY_VERSION {
            return Err(PolicyError::Version { found: raw.version });
        }

        // Two fences of one name would let the registration order pick
        // the code that runs (G10). Refuse the pair instead.
        let mut code: BTreeMap<&PluginName, &dyn FenceCode> = BTreeMap::new();
        for fence in fences {
            if code.insert(fence.plugin(), *fence).is_some() {
                return Err(PolicyError::DuplicateFence(fence.plugin().clone()));
            }
        }
        for name in setup.fences() {
            if !code.contains_key(name) {
                return Err(PolicyError::MissingFence(name.clone()));
            }
        }

        let mut apps = BTreeMap::new();
        let mut refused = BTreeMap::new();
        for (id, value) in raw.apps {
            match raw_app(&id, value).and_then(|raw| load_app(&id, raw, setup)) {
                Ok(app) => {
                    apps.insert(id, app);
                }
                Err(error) => {
                    refused.insert(id, error);
                }
            }
        }
        let shared = shared_digests(&apps);
        refuse(&mut apps, &mut refused, shared);

        // A refused app can change what a rule across apps sees, so the
        // fences run again until a round refuses no app.
        loop {
            let mut round = BTreeMap::new();
            for app in apps.values_mut() {
                app.fences.clear();
            }
            for name in setup.fences() {
                let Some(fence) = code.get(name) else {
                    return Err(PolicyError::MissingFence(name.clone()));
                };
                fence.prepare_apps(&mut apps, &mut round);
            }
            if round.is_empty() {
                break;
            }
            refuse(&mut apps, &mut refused, round);
        }
        Ok(Self { apps, refused })
    }

    /// Each app that the load refused, with its fault, in ID order.
    pub fn refused(&self) -> impl Iterator<Item = (&AppId, &PolicyError)> {
        self.refused.iter()
    }

    /// The app instance `id`, or `None` when the policy does not hold it.
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

/// The typed table of one app, from its value in the file.
fn raw_app(id: &AppId, value: toml::Value) -> Result<RawApp, PolicyError> {
    value
        .try_into()
        .map_err(|error: toml::de::Error| PolicyError::AppShape {
            app: id.clone(),
            error: error.message().to_owned(),
        })
}

/// Each app that holds a token digest another app also holds. A token that
/// matches two apps names neither, so each holder is refused.
fn shared_digests(apps: &BTreeMap<AppId, App>) -> BTreeMap<AppId, PolicyError> {
    let mut holders: BTreeMap<&TokenDigest, Vec<&AppId>> = BTreeMap::new();
    for (id, app) in apps {
        for digest in &app.digests {
            holders.entry(digest).or_default().push(id);
        }
    }
    let mut shared = BTreeMap::new();
    for ids in holders.values() {
        let [first, second, ..] = ids.as_slice() else {
            continue;
        };
        for id in ids {
            shared
                .entry((*id).clone())
                .or_insert_with(|| PolicyError::SharedDigest {
                    first: (*first).clone(),
                    second: (*second).clone(),
                });
        }
    }
    shared
}

/// Move each app of `faults` from `apps` to `refused`.
fn refuse(
    apps: &mut BTreeMap<AppId, App>,
    refused: &mut BTreeMap<AppId, PolicyError>,
    faults: BTreeMap<AppId, PolicyError>,
) {
    for (id, error) in faults {
        apps.remove(&id);
        refused.insert(id, error);
    }
}

fn load_app(id: &AppId, raw: RawApp, setup: &Setup) -> Result<App, PolicyError> {
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

    let mut bounds = BTreeMap::new();
    let mut inflight = BTreeMap::new();
    for (upstream, grant) in &raw.grants {
        if !setup.upstreams().contains(upstream) {
            return Err(PolicyError::UnknownUpstream {
                app: id.clone(),
                upstream: upstream.clone(),
            });
        }
        // An app runs with all of its grants or not at all (G2).
        if setup.down().contains(upstream) {
            return Err(PolicyError::UpstreamDown {
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
        let bound = match grant.timeout_s {
            None => Some(UpstreamBound::DEFAULT),
            Some(seconds) => UpstreamBound::from_seconds(seconds),
        };
        let bound = bound.ok_or_else(|| PolicyError::UpstreamBound {
            app: id.clone(),
            upstream: upstream.clone(),
        })?;
        bounds.insert(upstream.clone(), bound);
        if let Some(count) = grant.max_inflight {
            let limit =
                InflightLimit::from_count(count).ok_or_else(|| PolicyError::InflightLimit {
                    app: id.clone(),
                    upstream: upstream.clone(),
                })?;
            inflight.insert(upstream.clone(), limit);
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

    Ok(App {
        note: raw.note,
        digests: raw.token_sha256,
        limits: raw.limits,
        grants: raw.grants,
        bounds,
        inflight,
        sections: raw.plugins,
        fences: Vec::new(),
    })
}
