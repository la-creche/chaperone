//! The plugins this build can serve in each compiled slot. A decision or
//! adapter plugin is compiled into chaperone (`docs/design.md` 7.3), so the
//! build must know how to construct each one. This table is the one place
//! that names a compiled plugin. `startup` looks the plugin of each
//! compiled slot up here and refuses start when the table has no row for it
//! (G2). An effect slot needs no row: the effect host launches its plugin
//! as a process.
//!
//! A compiled fence has a row in [`FENCES`] the same way.
//!
//! A compiled plugin in `plugins/<kind>/added/` needs a row here and a
//! build from source.

use std::path::Path;
use std::sync::Arc;

use chaperone_core::{
    AuditSink, Clock, Fence, Identity, NameError, PluginName, SecretSource, Slot,
};
use chaperone_plugin_audit_jsonl::{JsonlAudit, OpenError};
use chaperone_plugin_bearer::BearerIdentity;
use chaperone_plugin_ha_call_fence::EntityFence;
use chaperone_plugin_secret_files::FileSecrets;
use chaperone_plugin_system_clock::SystemClock;

/// How this build constructs the plugin of one row.
#[derive(Debug, Clone, Copy)]
pub enum Build {
    Identity(fn() -> Box<dyn Identity>),
    AuditSink(fn(&Path) -> Result<Arc<dyn AuditSink>, OpenError>),
    Clock(fn() -> Box<dyn Clock>),
    SecretSource(fn(&Path) -> Box<dyn SecretSource>),
    /// A front door. `chaperone serve` starts it over the gateway after the
    /// configuration is loaded, so load time constructs nothing.
    FrontDoor,
}

/// One row: a plugin name, the slot it fills and how to build it.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    pub name: &'static str,
    pub slot: Slot,
    pub build: Build,
}

/// Every plugin this build can serve, by slot.
pub const ENTRIES: &[Entry] = &[
    Entry {
        name: "mcp-http",
        slot: Slot::FrontDoor,
        build: Build::FrontDoor,
    },
    Entry {
        name: "bearer",
        slot: Slot::Identity,
        build: Build::Identity(bearer),
    },
    Entry {
        name: "secret-files",
        slot: Slot::SecretSource,
        build: Build::SecretSource(secret_files),
    },
    Entry {
        name: "audit-jsonl",
        slot: Slot::AuditSink,
        build: Build::AuditSink(audit_jsonl),
    },
    Entry {
        name: "system-clock",
        slot: Slot::Clock,
        build: Build::Clock(system_clock),
    },
];

/// The row for `plugin` in `slot`, if this build has one.
#[must_use]
pub fn find(slot: Slot, plugin: &PluginName) -> Option<&'static Entry> {
    ENTRIES
        .iter()
        .find(|entry| entry.slot == slot && entry.name == plugin.as_str())
}

/// One compiled fence: its plugin name and how to build it.
#[derive(Debug, Clone, Copy)]
pub struct FenceEntry {
    pub name: &'static str,
    pub build: fn() -> Result<Box<dyn Fence>, NameError>,
}

/// Every fence this build can run.
pub const FENCES: &[FenceEntry] = &[FenceEntry {
    name: "ha-call",
    build: ha_call,
}];

/// The row of the fence `plugin`, if this build has one.
#[must_use]
pub fn find_fence(plugin: &PluginName) -> Option<&'static FenceEntry> {
    FENCES.iter().find(|entry| entry.name == plugin.as_str())
}

fn ha_call() -> Result<Box<dyn Fence>, NameError> {
    Ok(Box::new(EntityFence::new()?))
}

fn bearer() -> Box<dyn Identity> {
    Box::new(BearerIdentity)
}

fn system_clock() -> Box<dyn Clock> {
    Box::new(SystemClock)
}

fn secret_files(dir: &Path) -> Box<dyn SecretSource> {
    Box::new(FileSecrets::new(dir.to_owned()))
}

fn audit_jsonl(file: &Path) -> Result<Arc<dyn AuditSink>, OpenError> {
    let sink = JsonlAudit::open(file)?;
    Ok(Arc::new(sink))
}
