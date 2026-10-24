//! Load the configuration, find the plugins, resolve the slots and open the
//! audit file before chaperone serves anything. Every check that fails
//! refuses start (G2).

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use chaperone_core::{
    AuditSink, INSTALL_FILE_CAP, Identity, InstallError, InstallFile, POLICY_FILE_CAP, PluginName,
    Policy, PolicyError, RunId, SecretDelivery, Setup, SetupError, Slot, resolve,
};
use chaperone_plugin_audit_jsonl::OpenError;

use crate::catalog::{self, CatalogError};
use crate::files::{self, ReadError};
use crate::registry::{self, Build, Entry};

const INSTALL_FILE: &str = "install.json";
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
    #[error("{plugin} needs secrets, and the secret source comes in build step 5")]
    SecretsNotReady { plugin: PluginName },
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

/// The checked configuration, the plugins that serve the slots and the ID
/// of this run.
#[derive(Debug)]
pub struct Loaded {
    pub run: RunId,
    pub setup: Setup,
    pub policy: Policy,
    pub identity: Box<dyn Identity>,
    pub audit: Arc<dyn AuditSink>,
    pub warnings: Vec<Warning>,
}

/// Load `install.json` and `policy.json` from `config_dir` and every plugin
/// under `plugins_dir`. Open `audit_file`. Check that this build can run
/// the setup.
///
/// # Errors
///
/// Returns the first [`StartError`] found.
pub fn load(
    config_dir: &Path,
    plugins_dir: &Path,
    audit_file: &Path,
) -> Result<Loaded, StartError> {
    let catalog = catalog::discover(plugins_dir)?;
    let install_bytes = files::read_capped(&config_dir.join(INSTALL_FILE), INSTALL_FILE_CAP)?;
    let install = InstallFile::read(&install_bytes)?;
    let setup = resolve(&install, &catalog)?;

    for slot in Slot::ALL {
        entry_for(&setup, slot)?;
    }
    let identity = identity_for(&setup)?;
    let audit = audit_for(&setup, audit_file)?;

    let mut warnings = Vec::new();
    for (plugin, binding) in setup.bindings() {
        if !binding.secrets.is_empty() {
            return Err(StartError::SecretsNotReady {
                plugin: plugin.clone(),
            });
        }
        if binding.delivery == SecretDelivery::Env {
            warnings.push(Warning::EnvDelivery {
                plugin: plugin.clone(),
            });
        }
    }

    // No fence plugin has code in build step 3, so an active fence refuses
    // start through `PolicyError::MissingFence`.
    let policy_bytes = files::read_capped(&config_dir.join(POLICY_FILE), POLICY_FILE_CAP)?;
    let policy = Policy::load(&policy_bytes, &setup, &[])?;
    let run = run_id()?;
    Ok(Loaded {
        run,
        setup,
        policy,
        identity,
        audit,
        warnings,
    })
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
        Build::AuditSink(_) | Build::FrontDoor | Build::Later => {
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
        Build::Identity(_) | Build::FrontDoor | Build::Later => {
            Err(no_code(Slot::AuditSink, plugin))
        }
    }
}

/// A run ID from the OS random source (`docs/design.md` 5.4).
fn run_id() -> Result<RunId, StartError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(StartError::Random)?;
    Ok(RunId::from_bytes(bytes))
}
