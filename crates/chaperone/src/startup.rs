//! Load the configuration, find the plugins, resolve the slots, open the
//! audit file and read every bound secret before chaperone serves anything.
//! Every check that fails refuses start (G2).

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use chaperone_core::{
    AuditSink, Catalog, Clock, Fence, INSTALL_FILE_CAP, Identity, InstallError, InstallFile,
    NameError, POLICY_FILE_CAP, PluginKind, PluginName, Policy, PolicyError, RunId, Secret,
    SecretDelivery, SecretError, SecretName, SecretParam, SecretSource, Setup, SetupError, Slot,
    resolve,
};
use chaperone_plugin_audit_jsonl::OpenError;

use crate::catalog::{self, CatalogError};
use crate::files::{self, ReadError};
use crate::registry::{self, Build, Entry};

const INSTALL_FILE: &str = "install.toml";
const POLICY_FILE: &str = "policy.json";

/// Why chaperone refuses to start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error(transparent)]
    Install(#[from] InstallError),
    #[error(transparent)]
    Setup(#[from] SetupError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Audit(#[from] OpenError),
    #[error("the slot {0} has no plugin")]
    EmptySlot(Slot),
    #[error("this build has no code for {plugin} in the slot {slot}")]
    NoCode { slot: Slot, plugin: PluginName },
    #[error("this build has no code for the fence {plugin}")]
    NoFenceCode { plugin: PluginName },
    #[error("the fence {plugin} could not be built: {error}")]
    FenceBuild {
        plugin: PluginName,
        error: NameError,
    },
    #[error("the secret {name} for {plugin} ({param}) cannot be read: {error}")]
    Secret {
        plugin: PluginName,
        param: SecretParam,
        name: SecretName,
        error: SecretError,
    },
    #[error("the OS random source failed: {0}")]
    Random(getrandom::Error),
    #[error(
        "the front door address {0} is not loopback, and TLS is not set up (docs/design.md 7.6)"
    )]
    NotLoopback(SocketAddr),
}

/// A fact the operator must see at each start. It does not refuse start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// The plugin uses the env exception of `docs/design.md` 7.5.
    EnvDelivery { plugin: PluginName },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvDelivery { plugin } => write!(
                f,
                "{plugin} receives its secrets in its environment, and every child process of it inherits them"
            ),
        }
    }
}

/// The secrets of every active plugin, by plugin and by the parameter the
/// plugin receives each one under.
pub type Secrets = BTreeMap<PluginName, BTreeMap<SecretParam, Secret>>;

/// The checked configuration, the plugins that serve the slots, every
/// bound secret and the ID of this run.
#[derive(Debug)]
pub struct Loaded {
    pub run: RunId,
    pub catalog: Catalog,
    pub setup: Setup,
    pub policy: Policy,
    pub identity: Box<dyn Identity>,
    pub audit: Arc<dyn AuditSink>,
    pub clock: Box<dyn Clock>,
    pub secrets: Secrets,
    pub warnings: Vec<Warning>,
}

/// Load `install.toml` and `policy.json` from `config_dir` and every plugin
/// under `plugins_dir`. Open `audit_file`. Read every bound secret through
/// the secret source over `secrets_dir`. Check that this build can run the
/// setup.
///
/// # Errors
///
/// Returns the first [`StartError`] found.
pub fn load(
    config_dir: &Path,
    plugins_dir: &Path,
    audit_file: &Path,
    secrets_dir: &Path,
) -> Result<Loaded, StartError> {
    let install_bytes = files::read_capped(&config_dir.join(INSTALL_FILE), INSTALL_FILE_CAP)?;
    let (catalog, setup) = setup_from(&install_bytes, plugins_dir)?;

    for slot in Slot::ALL {
        if slot.hook().kind() == PluginKind::Effect {
            continue;
        }
        entry_for(&setup, slot)?;
    }
    let identity = identity_for(&setup)?;
    let audit = audit_for(&setup, audit_file)?;
    let clock = clock_for(&setup)?;
    let source = secret_source_for(&setup, secrets_dir)?;

    let mut secrets = Secrets::new();
    let mut warnings = Vec::new();
    for (plugin, binding) in setup.bindings() {
        let mut read = BTreeMap::new();
        for (param, name) in &binding.secrets {
            let secret = source.read(name).map_err(|error| StartError::Secret {
                plugin: plugin.clone(),
                param: param.clone(),
                name: name.clone(),
                error,
            })?;
            read.insert(param.clone(), secret);
        }
        if !read.is_empty() {
            secrets.insert(plugin.clone(), read);
        }
        if binding.delivery == SecretDelivery::Env {
            warnings.push(Warning::EnvDelivery {
                plugin: plugin.clone(),
            });
        }
    }

    let policy_bytes = files::read_capped(&config_dir.join(POLICY_FILE), POLICY_FILE_CAP)?;
    let policy = policy_from(&policy_bytes, &setup)?;
    let run = run_id()?;
    Ok(Loaded {
        run,
        catalog,
        setup,
        policy,
        identity,
        audit,
        clock,
        secrets,
        warnings,
    })
}

/// The plugin tree under `plugins_dir` and the setup that `install_bytes`
/// names in it. This is the strict reader and every cross-file rule of the
/// install file (`docs/design.md` 10).
///
/// # Errors
///
/// Returns the first [`StartError`] found.
pub fn setup_from(
    install_bytes: &[u8],
    plugins_dir: &Path,
) -> Result<(Catalog, Setup), StartError> {
    let catalog = catalog::discover(plugins_dir)?;
    let install = InstallFile::read(install_bytes)?;
    let setup = resolve(&install, &catalog)?;
    Ok((catalog, setup))
}

/// The policy that `policy_bytes` holds, checked against `setup` with the
/// fences this build has code for (`docs/design.md` 10).
///
/// # Errors
///
/// Returns the first [`StartError`] found.
pub fn policy_from(policy_bytes: &[u8], setup: &Setup) -> Result<Policy, StartError> {
    let fences = fences_for(setup)?;
    let fence_refs: Vec<&dyn Fence> = fences.iter().map(AsRef::as_ref).collect();
    Ok(Policy::load(policy_bytes, setup, &fence_refs)?)
}

/// Refuse a front door address that is not loopback (`docs/design.md` 7.6).
///
/// # Errors
///
/// Returns [`StartError::NotLoopback`] for every other address.
pub fn check_listen(address: SocketAddr) -> Result<(), StartError> {
    if address.ip().is_loopback() {
        return Ok(());
    }
    Err(StartError::NotLoopback(address))
}

/// Every active fence of the setup, built from its registry row. A fence
/// without a row refuses start (G2).
fn fences_for(setup: &Setup) -> Result<Vec<Box<dyn Fence>>, StartError> {
    let mut fences = Vec::new();
    for plugin in setup.fences() {
        let entry = registry::find_fence(plugin).ok_or_else(|| StartError::NoFenceCode {
            plugin: plugin.clone(),
        })?;
        let fence = (entry.build)().map_err(|error| StartError::FenceBuild {
            plugin: plugin.clone(),
            error,
        })?;
        fences.push(fence);
    }
    Ok(fences)
}

/// The registry row of the plugin that fills `slot`. A slot without a
/// plugin, or with a plugin this build has no row for, refuses start (G2).
fn entry_for(setup: &Setup, slot: Slot) -> Result<(&PluginName, &'static Entry), StartError> {
    let plugin = setup.slot(slot).ok_or(StartError::EmptySlot(slot))?;
    let entry = registry::find(slot, plugin).ok_or_else(|| no_code(slot, plugin))?;
    Ok((plugin, entry))
}

fn no_code(slot: Slot, plugin: &PluginName) -> StartError {
    StartError::NoCode {
        slot,
        plugin: plugin.clone(),
    }
}

/// The identity plugin of the setup, built from its registry row.
fn identity_for(setup: &Setup) -> Result<Box<dyn Identity>, StartError> {
    let (plugin, entry) = entry_for(setup, Slot::Identity)?;
    match entry.build {
        Build::Identity(build) => Ok(build()),
        Build::AuditSink(_) | Build::Clock(_) | Build::SecretSource(_) | Build::FrontDoor => {
            Err(no_code(Slot::Identity, plugin))
        }
    }
}

/// The audit sink of the setup, opened on `audit_file` from its registry
/// row.
fn audit_for(setup: &Setup, audit_file: &Path) -> Result<Arc<dyn AuditSink>, StartError> {
    let (plugin, entry) = entry_for(setup, Slot::AuditSink)?;
    match entry.build {
        Build::AuditSink(open) => Ok(open(audit_file)?),
        Build::Identity(_) | Build::Clock(_) | Build::SecretSource(_) | Build::FrontDoor => {
            Err(no_code(Slot::AuditSink, plugin))
        }
    }
}

/// The clock of the setup, built from its registry row.
fn clock_for(setup: &Setup) -> Result<Box<dyn Clock>, StartError> {
    let (plugin, entry) = entry_for(setup, Slot::Clock)?;
    match entry.build {
        Build::Clock(build) => Ok(build()),
        Build::Identity(_) | Build::AuditSink(_) | Build::SecretSource(_) | Build::FrontDoor => {
            Err(no_code(Slot::Clock, plugin))
        }
    }
}

/// The secret source of the setup over `secrets_dir`, built from its
/// registry row.
fn secret_source_for(
    setup: &Setup,
    secrets_dir: &Path,
) -> Result<Box<dyn SecretSource>, StartError> {
    let (plugin, entry) = entry_for(setup, Slot::SecretSource)?;
    match entry.build {
        Build::SecretSource(build) => Ok(build(secrets_dir)),
        Build::Identity(_) | Build::AuditSink(_) | Build::Clock(_) | Build::FrontDoor => {
            Err(no_code(Slot::SecretSource, plugin))
        }
    }
}

/// A run ID from the OS random source (`docs/design.md` 5.4).
fn run_id() -> Result<RunId, StartError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(StartError::Random)?;
    Ok(RunId::from_bytes(bytes))
}
