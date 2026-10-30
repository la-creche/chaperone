//! The install file (`install.toml`) and slot resolution. The install file
//! alone enables a plugin and fills a slot (G10). `docs/design.md` 7.2 to
//! 7.5.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::ids::{PluginName, PluginUser, SecretName, SecretParam};
use crate::plugin::{Hook, Manifest, PluginKind, Slot};
use crate::strict::{self, ByteCap, StrictError};

/// The largest `install.toml` chaperone reads.
pub const INSTALL_FILE_CAP: ByteCap = ByteCap::new(256 * 1024);

const INSTALL_VERSION: u32 = 1;

/// The one variable of `chaperone-as`: the whole environment of the
/// effect plugin, as one JSON object of strings (`docs/design.md` 8).
pub const CHILD_ENV_VAR: &str = "CHAPERONE_CHILD_ENV";

/// Where a plugin sits in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Location {
    /// `plugins/default/`
    Default,
    /// `plugins/<kind>/included/`
    Included,
    /// `plugins/<kind>/added/`
    Added,
}

/// How chaperone hands a secret to an effect plugin (`docs/design.md` 7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretDelivery {
    /// In the first message on stdin.
    #[default]
    Stdin,
    /// In the environment. Only for a plugin in `added/`.
    Env,
}

/// What limits who reaches the front door on its address
/// (`docs/design.md` 7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Guard {
    /// Only a loopback address. The default when the install file sets no
    /// guard.
    #[default]
    Loopback,
    /// A LAN address too. The operator states that a host firewall limits
    /// who reaches the port.
    HostFirewall,
}

/// One enabled plugin in `install.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallEntry {
    /// The operator's reason for enabling the plugin.
    #[serde(default)]
    note: Option<String>,
    /// The secret file bound to each secret parameter of the manifest.
    #[serde(default)]
    secrets: BTreeMap<SecretParam, SecretName>,
    #[serde(default)]
    secret_delivery: SecretDelivery,
    /// Arguments appended to the command of an effect plugin's manifest
    /// (`docs/design.md` 7.4). Never a secret value (G9).
    #[serde(default)]
    args: Vec<String>,
    /// The guard of a front door plugin. No other plugin takes one.
    #[serde(default)]
    guard: Option<Guard>,
    /// The OS user an effect plugin runs as (`docs/design.md` 8).
    #[serde(default)]
    user: Option<PluginUser>,
}

impl InstallEntry {
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }
}

/// `install.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallFile {
    /// The version of the file shape. This chaperone reads 1.
    version: u32,
    #[serde(default)]
    note: Option<String>,
    /// The enabled plugins, by plugin name.
    #[serde(default)]
    plugins: BTreeMap<PluginName, InstallEntry>,
    /// The plugin for each slot that the default does not fill.
    #[serde(default)]
    slots: BTreeMap<Slot, PluginName>,
}

/// Why `install.toml` is not valid on its own.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    #[error("install.toml is not valid: {0}")]
    Read(#[from] StrictError),
    #[error("install.toml has version {found}, this chaperone reads version {INSTALL_VERSION}")]
    Version { found: u32 },
}

impl InstallFile {
    /// Read and check `install.toml`.
    ///
    /// # Errors
    ///
    /// Returns an [`InstallError`] that names the first rule the file breaks.
    pub fn read(bytes: &[u8]) -> Result<Self, InstallError> {
        let file: Self = strict::read_toml(bytes, INSTALL_FILE_CAP)?;
        if file.version != INSTALL_VERSION {
            return Err(InstallError::Version {
                found: file.version,
            });
        }
        Ok(file)
    }

    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }
}

/// One plugin found on disk, with where it sits.
#[derive(Debug, Clone)]
pub struct Found {
    pub location: Location,
    pub manifest: Manifest,
}

/// The key of one plugin on disk. Two halves of one plugin share a name and
/// differ in kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginKey {
    pub kind: PluginKind,
    pub name: PluginName,
}

impl PluginKey {
    /// The key of the plugin that `manifest` describes.
    #[must_use]
    pub fn from_manifest(manifest: &Manifest) -> Self {
        Self {
            kind: manifest.kind(),
            name: manifest.name().clone(),
        }
    }
}

/// Every plugin found on disk.
pub type Catalog = BTreeMap<PluginKey, Found>;

/// The secrets of one active plugin, how it receives them, and the
/// arguments the install file adds to its command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub secrets: BTreeMap<SecretParam, SecretName>,
    pub delivery: SecretDelivery,
    pub args: Vec<String>,
    pub user: Option<PluginUser>,
}

/// The resolved setup: which plugin fills each slot, which fences and
/// upstreams are active, and the secret binding of each active plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    slots: BTreeMap<Slot, PluginName>,
    fences: BTreeSet<PluginName>,
    upstreams: BTreeSet<PluginName>,
    /// The active upstreams that did not start. Empty until the host
    /// launches the upstreams.
    down: BTreeSet<PluginName>,
    bindings: BTreeMap<PluginName, Binding>,
    guard: Guard,
}

impl Setup {
    /// The plugin that fills `slot`. Every slot has one.
    #[must_use]
    pub fn slot(&self, slot: Slot) -> Option<&PluginName> {
        self.slots.get(&slot)
    }

    /// The active fence plugins, in name order.
    #[must_use]
    pub fn fences(&self) -> &BTreeSet<PluginName> {
        &self.fences
    }

    /// The active upstreams, in name order.
    #[must_use]
    pub fn upstreams(&self) -> &BTreeSet<PluginName> {
        &self.upstreams
    }

    /// The active upstreams that did not start, in name order. A grant of
    /// one refuses its app (`docs/design.md` 7.7).
    #[must_use]
    pub fn down(&self) -> &BTreeSet<PluginName> {
        &self.down
    }

    /// This setup with `down` as the upstreams that did not start. A name
    /// that is not an active upstream is left out.
    #[must_use]
    pub fn with_down(mut self, down: &BTreeSet<PluginName>) -> Self {
        self.down = self.upstreams.intersection(down).cloned().collect();
        self
    }

    /// The secret binding of an active plugin.
    #[must_use]
    pub fn binding(&self, plugin: &PluginName) -> Option<&Binding> {
        self.bindings.get(plugin)
    }

    /// The guard that the install file sets for the front door plugin.
    #[must_use]
    pub fn guard(&self) -> Guard {
        self.guard
    }

    /// Every active plugin with its secret binding, in name order.
    pub fn bindings(&self) -> impl Iterator<Item = (&PluginName, &Binding)> {
        self.bindings.iter()
    }
}

/// Why the install file and the plugins on disk do not form a valid setup.
/// Each one refuses start (G2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    #[error("install.toml enables {0}, but no plugin of that name exists")]
    UnknownPlugin(PluginName),
    #[error("no default plugin exists for the slot {0}")]
    MissingDefault(Slot),
    #[error("{plugins:?} are each a default for the slot {slot}. Keep one in plugins/default.")]
    TwoDefaults {
        slot: Slot,
        plugins: Vec<PluginName>,
    },
    #[error("install.toml picks {plugin} for the slot {slot}, but it does not serve that slot")]
    WrongSlot { slot: Slot, plugin: PluginName },
    #[error("install.toml picks {plugin} for the slot {slot}, but does not enable it")]
    SlotNotEnabled { slot: Slot, plugin: PluginName },
    #[error("{plugins:?} each claim the slot {slot}. Pick one in install.toml \"slots\".")]
    Ambiguous {
        slot: Slot,
        plugins: Vec<PluginName>,
    },
    #[error("{plugin} pairs with a {kind:?} half that does not exist or does not pair back")]
    MissingPair {
        plugin: PluginName,
        kind: PluginKind,
    },
    #[error("{plugin} needs the secret parameter {param}, and install.toml does not bind it")]
    UnboundSecret {
        plugin: PluginName,
        param: SecretParam,
    },
    #[error("install.toml binds {param} for {plugin}, which does not declare it")]
    UnknownSecret {
        plugin: PluginName,
        param: SecretParam,
    },
    #[error("{plugin} sits in default or included and cannot use secret_delivery env")]
    EnvNotAllowed { plugin: PluginName },
    #[error("{plugin} has no effect half, so secret_delivery env means nothing")]
    EnvWithoutProcess { plugin: PluginName },
    #[error("{plugin} has no effect half, so a user means nothing")]
    UserWithoutProcess { plugin: PluginName },
    #[error("{plugin} has no effect half, so args mean nothing")]
    ArgsWithoutProcess { plugin: PluginName },
    #[error("install.toml sets a guard for {plugin}, but only a front door takes a guard")]
    GuardWithoutFrontDoor { plugin: PluginName },
}

/// Resolve the setup from `install.toml` and the plugins found on disk.
///
/// A plugin on disk takes part only when `install.toml` enables it, or when
/// it is the default that fills an open slot (G10).
///
/// # Errors
///
/// Returns the first [`SetupError`] found. Checks run in a fixed order.
pub fn resolve(install: &InstallFile, catalog: &Catalog) -> Result<Setup, SetupError> {
    let halves = |name: &PluginName| -> Vec<&Found> {
        catalog
            .iter()
            .filter(|(key, _)| key.name == *name)
            .map(|(_, found)| found)
            .collect()
    };

    for name in install.plugins.keys() {
        if halves(name).is_empty() {
            return Err(SetupError::UnknownPlugin(name.clone()));
        }
    }

    let mut active: BTreeSet<PluginName> = install.plugins.keys().cloned().collect();
    let mut slots = BTreeMap::new();
    for slot in Slot::ALL {
        let default = default_for(slot, catalog)?;
        let plugin = pick_slot(slot, install, catalog, default)?;
        active.insert(plugin.clone());
        slots.insert(slot, plugin);
    }

    let mut fences = BTreeSet::new();
    let mut upstreams = BTreeSet::new();
    let mut bindings = BTreeMap::new();
    for name in &active {
        let found = halves(name);
        check_pairs(name, &found)?;
        if found.iter().any(|f| f.manifest.serves(Hook::Fence)) {
            fences.insert(name.clone());
        }
        if found.iter().any(|f| f.manifest.serves(Hook::Upstream)) {
            upstreams.insert(name.clone());
        }
        bindings.insert(name.clone(), bind(name, &found, install.plugins.get(name))?);
    }

    let guard = slots
        .get(&Slot::FrontDoor)
        .and_then(|plugin| install.plugins.get(plugin))
        .and_then(|entry| entry.guard)
        .unwrap_or_default();
    Ok(Setup {
        slots,
        fences,
        upstreams,
        down: BTreeSet::new(),
        bindings,
        guard,
    })
}

/// The one default plugin of `slot`. Two defaults refuse start, so the
/// catalog order never picks one (G10).
fn default_for(slot: Slot, catalog: &Catalog) -> Result<&PluginName, SetupError> {
    let mut defaults = catalog
        .values()
        .filter(|found| found.location == Location::Default && found.manifest.slot() == Some(slot))
        .map(|found| found.manifest.name());
    let Some(first) = defaults.next() else {
        return Err(SetupError::MissingDefault(slot));
    };
    let others: Vec<PluginName> = defaults.cloned().collect();
    if others.is_empty() {
        return Ok(first);
    }
    let mut plugins = vec![first.clone()];
    plugins.extend(others);
    Err(SetupError::TwoDefaults { slot, plugins })
}

fn pick_slot(
    slot: Slot,
    install: &InstallFile,
    catalog: &Catalog,
    default: &PluginName,
) -> Result<PluginName, SetupError> {
    let claims = |name: &PluginName| {
        catalog
            .values()
            .find(|found| {
                found.manifest.kind() == slot.hook().kind() && found.manifest.name() == name
            })
            .is_some_and(|found| found.manifest.slot() == Some(slot))
    };

    if let Some(chosen) = install.slots.get(&slot) {
        if !claims(chosen) {
            return Err(SetupError::WrongSlot {
                slot,
                plugin: chosen.clone(),
            });
        }
        if chosen != default && !install.plugins.contains_key(chosen) {
            return Err(SetupError::SlotNotEnabled {
                slot,
                plugin: chosen.clone(),
            });
        }
        return Ok(chosen.clone());
    }

    let claimants: Vec<PluginName> = install
        .plugins
        .keys()
        .filter(|name| *name != default && claims(name))
        .cloned()
        .collect();
    if claimants.is_empty() {
        return Ok(default.clone());
    }
    let mut plugins = vec![default.clone()];
    plugins.extend(claimants);
    Err(SetupError::Ambiguous { slot, plugins })
}

fn check_pairs(name: &PluginName, found: &[&Found]) -> Result<(), SetupError> {
    for half in found {
        let Some(kind) = half.manifest.pairs_with() else {
            continue;
        };
        let pairs_back = found.iter().any(|other| {
            other.manifest.kind() == kind
                && other.manifest.pairs_with() == Some(half.manifest.kind())
        });
        if !pairs_back {
            return Err(SetupError::MissingPair {
                plugin: name.clone(),
                kind,
            });
        }
    }
    Ok(())
}

fn bind(
    name: &PluginName,
    found: &[&Found],
    entry: Option<&InstallEntry>,
) -> Result<Binding, SetupError> {
    let declared: BTreeSet<&SecretParam> =
        found.iter().flat_map(|f| f.manifest.secrets()).collect();
    let secrets = entry.map(|e| e.secrets.clone()).unwrap_or_default();
    let delivery = entry.map(|e| e.secret_delivery).unwrap_or_default();
    let args = entry.map(|e| e.args.clone()).unwrap_or_default();
    let user = entry.and_then(|e| e.user.clone());
    let has_process = found
        .iter()
        .any(|f| f.manifest.kind() == PluginKind::Effect);
    if user.is_some() && !has_process {
        return Err(SetupError::UserWithoutProcess {
            plugin: name.clone(),
        });
    }
    if !args.is_empty() && !has_process {
        return Err(SetupError::ArgsWithoutProcess {
            plugin: name.clone(),
        });
    }
    let front_door = found.iter().any(|f| f.manifest.serves(Hook::FrontDoor));
    if entry.is_some_and(|e| e.guard.is_some()) && !front_door {
        return Err(SetupError::GuardWithoutFrontDoor {
            plugin: name.clone(),
        });
    }

    for param in &declared {
        if !secrets.contains_key(*param) {
            return Err(SetupError::UnboundSecret {
                plugin: name.clone(),
                param: (*param).clone(),
            });
        }
    }
    for param in secrets.keys() {
        if !declared.contains(param) {
            return Err(SetupError::UnknownSecret {
                plugin: name.clone(),
                param: param.clone(),
            });
        }
    }

    if delivery == SecretDelivery::Env {
        let effect = found
            .iter()
            .find(|f| f.manifest.kind() == PluginKind::Effect)
            .ok_or_else(|| SetupError::EnvWithoutProcess {
                plugin: name.clone(),
            })?;
        if effect.location != Location::Added {
            return Err(SetupError::EnvNotAllowed {
                plugin: name.clone(),
            });
        }
    }

    Ok(Binding {
        secrets,
        delivery,
        args,
        user,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn manifest(text: &str) -> Manifest {
        Manifest::read(text.as_bytes()).unwrap()
    }

    fn put(catalog: &mut Catalog, location: Location, text: &str) {
        let manifest = manifest(text);
        catalog.insert(
            PluginKey::from_manifest(&manifest),
            Found { location, manifest },
        );
    }

    /// The six defaults, as `plugins/default/` holds them.
    pub(crate) fn defaults() -> Catalog {
        let mut catalog = Catalog::new();
        for (name, kind, slot, hook) in [
            ("mcp-http", "adapter", "front_door", "front_door"),
            ("bearer", "decision", "identity", "identity"),
            ("secret-files", "adapter", "secret_source", "secret_source"),
            ("audit-jsonl", "adapter", "audit_sink", "audit_sink"),
            ("system-clock", "adapter", "clock", "clock"),
        ] {
            put(
                &mut catalog,
                Location::Default,
                &format!(
                    r#"
                        name = "{name}"
                        version = "1"
                        kind = "{kind}"
                        slot = "{slot}"
                        hooks = ["{hook}"]
                    "#
                ),
            );
        }
        put(
            &mut catalog,
            Location::Default,
            r#"
                name = "deny-all"
                version = "1"
                kind = "effect"
                slot = "approval_channel"
                hooks = ["approval"]
                command = ["chaperone-deny-all"]
            "#,
        );
        catalog
    }

    /// The version 1 set: defaults plus ha-call, ha-approval and vikunja.
    pub(crate) fn v1_catalog() -> Catalog {
        let mut catalog = defaults();
        put(
            &mut catalog,
            Location::Included,
            r#"
                name = "ha-call"
                version = "1"
                kind = "decision"
                hooks = ["fence"]
                pairs_with = "effect"
            "#,
        );
        put(
            &mut catalog,
            Location::Included,
            r#"
                name = "ha-call"
                version = "1"
                kind = "effect"
                hooks = ["upstream"]
                secrets = ["token"]
                pairs_with = "decision"
                command = ["ha-call"]
            "#,
        );
        put(
            &mut catalog,
            Location::Included,
            r#"
                name = "ha-approval"
                version = "1"
                kind = "effect"
                slot = "approval_channel"
                hooks = ["approval"]
                secrets = ["token"]
                command = ["ha-approval"]
            "#,
        );
        put(
            &mut catalog,
            Location::Added,
            r#"
                name = "vikunja"
                version = "1"
                kind = "effect"
                hooks = ["upstream"]
                secrets = ["VIKUNJA_TOKEN"]
                command = ["vikunja-mcp"]
            "#,
        );
        catalog
    }

    pub(crate) const V1_INSTALL: &str = r#"
        version = 1

        [plugins.ha-call]
        secrets = { token = "ha_token" }

        [plugins.ha-approval]
        secrets = { token = "ha_token" }

        [plugins.vikunja]
        secrets = { VIKUNJA_TOKEN = "vikunja_token" }
        secret_delivery = "env"

        [slots]
        approval_channel = "ha-approval"
    "#;

    /// An install file that enables nothing.
    const EMPTY_INSTALL: &str = "version = 1\n";

    fn install(text: &str) -> InstallFile {
        InstallFile::read(text.as_bytes()).unwrap()
    }

    fn name(text: &str) -> PluginName {
        PluginName::try_new(text).unwrap()
    }

    #[test]
    fn defaults_fill_every_slot_of_an_empty_install() {
        let setup = resolve(&install(EMPTY_INSTALL), &defaults()).unwrap();
        assert_eq!(setup.slot(Slot::Identity), Some(&name("bearer")));
        assert_eq!(setup.slot(Slot::ApprovalChannel), Some(&name("deny-all")));
        assert!(setup.fences().is_empty());
        assert!(setup.upstreams().is_empty());
    }

    #[test]
    fn resolves_the_version_1_setup() {
        let setup = resolve(&install(V1_INSTALL), &v1_catalog()).unwrap();
        assert_eq!(
            setup.slot(Slot::ApprovalChannel),
            Some(&name("ha-approval"))
        );
        assert_eq!(setup.fences(), &BTreeSet::from([name("ha-call")]));
        assert_eq!(
            setup.upstreams(),
            &BTreeSet::from([name("ha-call"), name("vikunja")])
        );
        let vikunja = setup.binding(&name("vikunja")).unwrap();
        assert_eq!(vikunja.delivery, SecretDelivery::Env);
    }

    #[test]
    fn bindings_cover_every_active_plugin_in_name_order() {
        let setup = resolve(&install(V1_INSTALL), &v1_catalog()).unwrap();
        let names: Vec<&str> = setup.bindings().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "audit-jsonl",
                "bearer",
                "ha-approval",
                "ha-call",
                "mcp-http",
                "secret-files",
                "system-clock",
                "vikunja"
            ]
        );
        for (name, binding) in setup.bindings() {
            assert_eq!(setup.binding(name), Some(binding));
        }
    }

    #[test]
    fn a_plugin_on_disk_does_nothing_until_enabled() {
        let setup = resolve(&install(EMPTY_INSTALL), &v1_catalog()).unwrap();
        assert!(setup.fences().is_empty());
        assert!(setup.upstreams().is_empty());
        assert_eq!(setup.slot(Slot::ApprovalChannel), Some(&name("deny-all")));
    }

    #[test]
    fn args_reach_the_binding_of_an_effect_plugin_only() {
        let setup = resolve(
            &install(
                r#"
                version = 1
                [plugins.vikunja]
                secrets = { VIKUNJA_TOKEN = "vikunja_token" }
                args = ["--port", "1"]
                "#,
            ),
            &v1_catalog(),
        )
        .unwrap();
        assert_eq!(
            setup.binding(&name("vikunja")).unwrap().args,
            ["--port", "1"]
        );
        assert!(setup.binding(&name("bearer")).unwrap().args.is_empty());

        let error = resolve(
            &install("version = 1\nplugins.bearer.args = [\"x\"]\n"),
            &v1_catalog(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            SetupError::ArgsWithoutProcess {
                plugin: name("bearer")
            }
        );
    }

    #[test]
    fn a_user_reaches_the_binding_of_an_effect_plugin_only() {
        let text = "version = 1\nplugins.vikunja.user = \"mcp-vikunja\"\n\
                    plugins.vikunja.secrets = { VIKUNJA_TOKEN = \"vikunja_token\" }\n";
        let setup = resolve(&install(text), &v1_catalog()).unwrap();
        let user = setup.binding(&name("vikunja")).unwrap().user.clone();
        assert_eq!(user.unwrap().as_str(), "mcp-vikunja");
        assert_eq!(setup.binding(&name("bearer")).unwrap().user, None);

        let text = "version = 1\nplugins.bearer.user = \"mcp-bearer\"\n";
        let error = resolve(&install(text), &v1_catalog()).unwrap_err();
        let plugin = name("bearer");
        assert_eq!(error, SetupError::UserWithoutProcess { plugin });

        let text = "version = 1\nplugins.vikunja.user = \"root\"\n";
        assert!(InstallFile::read(text.as_bytes()).is_err());
    }

    #[test]
    fn the_guard_of_the_front_door_reaches_the_setup() {
        let setup = resolve(&install(EMPTY_INSTALL), &defaults()).unwrap();
        assert_eq!(setup.guard(), Guard::Loopback);

        let text = "version = 1\nplugins.mcp-http.guard = \"host-firewall\"\n";
        let setup = resolve(&install(text), &defaults()).unwrap();
        assert_eq!(setup.guard(), Guard::HostFirewall);
        assert_eq!(setup.slot(Slot::FrontDoor), Some(&name("mcp-http")));
    }

    #[test]
    fn refuses_a_guard_on_a_plugin_that_is_not_a_front_door() {
        let text = "version = 1\nplugins.bearer.guard = \"loopback\"\n";
        let error = resolve(&install(text), &defaults()).unwrap_err();
        assert_eq!(
            error,
            SetupError::GuardWithoutFrontDoor {
                plugin: name("bearer")
            }
        );
    }

    #[test]
    fn refuses_an_unknown_guard() {
        let text = "version = 1\nplugins.mcp-http.guard = \"tls\"\n";
        let error = InstallFile::read(text.as_bytes()).unwrap_err();
        assert!(matches!(
            error,
            InstallError::Read(StrictError::Shape { .. })
        ));
    }

    #[test]
    fn refuses_an_unknown_plugin() {
        let error = resolve(&install("version = 1\nplugins.nope = {}\n"), &defaults());
        assert_eq!(error.unwrap_err(), SetupError::UnknownPlugin(name("nope")));
    }

    #[test]
    fn refuses_a_missing_default() {
        let mut catalog = defaults();
        catalog.remove(&PluginKey {
            kind: PluginKind::Decision,
            name: name("bearer"),
        });
        let error = resolve(&install(EMPTY_INSTALL), &catalog).unwrap_err();
        assert_eq!(error, SetupError::MissingDefault(Slot::Identity));
    }

    #[test]
    fn refuses_two_defaults_for_one_slot() {
        let mut catalog = defaults();
        put(
            &mut catalog,
            Location::Default,
            r#"
                name = "other-identity"
                version = "1"
                kind = "decision"
                slot = "identity"
                hooks = ["identity"]
            "#,
        );
        let error = resolve(&install(EMPTY_INSTALL), &catalog).unwrap_err();
        assert_eq!(
            error,
            SetupError::TwoDefaults {
                slot: Slot::Identity,
                plugins: vec![name("bearer"), name("other-identity")],
            }
        );
    }

    #[test]
    fn refuses_two_claimants_without_a_choice() {
        let text = "version = 1\nplugins.ha-approval.secrets.token = \"ha_token\"\n";
        let error = resolve(&install(text), &v1_catalog()).unwrap_err();
        assert!(matches!(
            error,
            SetupError::Ambiguous {
                slot: Slot::ApprovalChannel,
                ..
            }
        ));
    }

    #[test]
    fn refuses_a_chosen_plugin_that_is_not_enabled() {
        let text = "version = 1\nslots.approval_channel = \"ha-approval\"\n";
        let error = resolve(&install(text), &v1_catalog()).unwrap_err();
        assert!(matches!(error, SetupError::SlotNotEnabled { .. }));
    }

    #[test]
    fn refuses_a_chosen_plugin_that_does_not_serve_the_slot() {
        let text = r#"
            version = 1
            slots.approval_channel = "vikunja"
            [plugins.vikunja]
            secrets.VIKUNJA_TOKEN = "v"
            secret_delivery = "env"
        "#;
        let error = resolve(&install(text), &v1_catalog()).unwrap_err();
        assert!(matches!(error, SetupError::WrongSlot { .. }));
    }

    #[test]
    fn refuses_a_missing_pair_half() {
        let mut catalog = v1_catalog();
        catalog.remove(&PluginKey {
            kind: PluginKind::Effect,
            name: name("ha-call"),
        });
        let text = "version = 1\nplugins.ha-call = {}\n";
        let error = resolve(&install(text), &catalog).unwrap_err();
        assert!(matches!(error, SetupError::MissingPair { .. }));
    }

    #[test]
    fn refuses_an_unbound_and_an_unknown_secret() {
        let unbound = "version = 1\nplugins.ha-call = {}\n";
        assert!(matches!(
            resolve(&install(unbound), &v1_catalog()).unwrap_err(),
            SetupError::UnboundSecret { .. }
        ));
        let unknown = "version = 1\nplugins.ha-call.secrets = { token = \"t\", other = \"o\" }\n";
        assert!(matches!(
            resolve(&install(unknown), &v1_catalog()).unwrap_err(),
            SetupError::UnknownSecret { .. }
        ));
    }

    #[test]
    fn refuses_env_delivery_for_an_included_plugin() {
        let text = r#"
            version = 1
            [plugins.ha-call]
            secrets.token = "t"
            secret_delivery = "env"
        "#;
        let error = resolve(&install(text), &v1_catalog()).unwrap_err();
        assert_eq!(
            error,
            SetupError::EnvNotAllowed {
                plugin: name("ha-call")
            }
        );
    }

    #[test]
    fn refuses_another_install_version() {
        let error = InstallFile::read(b"version = 2\n").unwrap_err();
        assert_eq!(error, InstallError::Version { found: 2 });
    }

    #[test]
    fn refuses_a_json_install_file() {
        let error = InstallFile::read(br#"{"version":1}"#).unwrap_err();
        assert!(matches!(
            error,
            InstallError::Read(StrictError::Syntax { line: 1, .. })
        ));
    }

    #[test]
    fn refuses_a_schema_field() {
        let text = "\"$schema\" = \"urn:chaperone:install:1\"\nversion = 1\n";
        let error = InstallFile::read(text.as_bytes()).unwrap_err();
        assert!(matches!(
            error,
            InstallError::Read(StrictError::Shape { .. })
        ));
    }

    #[test]
    fn reads_comments_in_an_install_file() {
        let text = "# The plugins the operator enables.\nversion = 1 # The file shape.\n";
        assert!(InstallFile::read(text.as_bytes()).is_ok());
    }
}
