//! Load the configuration, find the plugins, resolve the slots and open the
//! audit file before chaperone serves anything. Every check that fails
//! refuses start (G2).

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use chaperone_core::{
    AuditSink, INSTALL_FILE_CAP, Identity, InstallError, InstallFile, POLICY_FILE_CAP, PluginName,
    Policy, PolicyError, RunId, SecretDelivery, Setup, SetupError, Slot, resolve,
};
use chaperone_plugin_audit_jsonl::{JsonlAudit, OpenError};
use chaperone_plugin_bearer::BearerIdentity;

use crate::catalog::{self, CatalogError};
use crate::files::{self, ReadError};

const INSTALL_FILE: &str = "install.json";
const POLICY_FILE: &str = "policy.json";

/// The identity plugin this build has code for.
const BEARER: &str = "bearer";
/// The audit sink this build has code for.
const AUDIT_JSONL: &str = "audit-jsonl";

/// The plugin this build accepts in each slot that no code serves yet. The
/// front door comes in build step 3.2, the approval channel in steps 4 and
/// 6, and the secret source in step 5. Another plugin in one of these slots
/// refuses start now, so a later step never finds a slot it cannot serve.
const ACCEPTED: [(Slot, &str); 3] = [
    (Slot::FrontDoor, "mcp-http"),
    (Slot::SecretSource, "secret-files"),
    (Slot::ApprovalChannel, "deny-all"),
];

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

    let identity = identity_for(&setup)?;
    let audit = audit_for(&setup, audit_file)?;
    for (slot, accepted) in ACCEPTED {
        let plugin = slot_plugin(&setup, slot)?;
        if plugin.as_str() != accepted {
            return Err(StartError::NoCode {
                slot,
                plugin: plugin.clone(),
            });
        }
    }

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

fn slot_plugin(setup: &Setup, slot: Slot) -> Result<&PluginName, StartError> {
    setup.slot(slot).ok_or(StartError::EmptySlot(slot))
}

/// The compiled identity plugin that the setup names.
fn identity_for(setup: &Setup) -> Result<Box<dyn Identity>, StartError> {
    let plugin = slot_plugin(setup, Slot::Identity)?;
    if plugin.as_str() == BEARER {
        return Ok(Box::new(BearerIdentity));
    }
    Err(StartError::NoCode {
        slot: Slot::Identity,
        plugin: plugin.clone(),
    })
}

/// The compiled audit sink that the setup names, opened on `audit_file`.
fn audit_for(setup: &Setup, audit_file: &Path) -> Result<Arc<dyn AuditSink>, StartError> {
    let plugin = slot_plugin(setup, Slot::AuditSink)?;
    if plugin.as_str() == AUDIT_JSONL {
        return Ok(Arc::new(JsonlAudit::open(audit_file)?));
    }
    Err(StartError::NoCode {
        slot: Slot::AuditSink,
        plugin: plugin.clone(),
    })
}

/// A run ID from the OS random source (`docs/design.md` 5.4).
fn run_id() -> Result<RunId, StartError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(StartError::Random)?;
    Ok(RunId::from_bytes(bytes))
}
