//! The plugins this build can serve in each slot. A decision or adapter
//! plugin is compiled into chaperone (`docs/design.md` 7.3), so the build
//! must know how to construct each one. This table is the one place that
//! names a compiled plugin. `startup` looks the plugin of each slot up here
//! and refuses start when the table has no row for it (G2).
//!
//! A compiled plugin in `plugins/<kind>/added/` needs a row here and a
//! build from source.

use std::path::Path;
use std::sync::Arc;

use chaperone_core::{AuditSink, Clock, Identity, PluginName, Slot};
use chaperone_plugin_audit_jsonl::{JsonlAudit, OpenError};
use chaperone_plugin_bearer::BearerIdentity;
use chaperone_plugin_system_clock::SystemClock;

/// How this build constructs the plugin of one row.
#[derive(Debug, Clone, Copy)]
pub enum Build {
    Identity(fn() -> Box<dyn Identity>),
    AuditSink(fn(&Path) -> Result<Arc<dyn AuditSink>, OpenError>),
    Clock(fn() -> Box<dyn Clock>),
    /// A front door. `chaperone serve` starts it over the gateway after the
    /// configuration is loaded, so load time constructs nothing.
    FrontDoor,
    /// A plugin whose code comes in build step 4 (the secret source) or
    /// build step 6 (the approval channel). The slot accepts only this
    /// plugin until then, so that step never meets a slot it cannot serve.
    Later,
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
        build: Build::Later,
    },
    Entry {
        name: "audit-jsonl",
        slot: Slot::AuditSink,
        build: Build::AuditSink(audit_jsonl),
    },
    Entry {
        name: "deny-all",
        slot: Slot::ApprovalChannel,
        build: Build::Later,
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

fn bearer() -> Box<dyn Identity> {
    Box::new(BearerIdentity)
}

fn system_clock() -> Box<dyn Clock> {
    Box::new(SystemClock)
}

fn audit_jsonl(file: &Path) -> Result<Arc<dyn AuditSink>, OpenError> {
    let sink = JsonlAudit::open(file)?;
    Ok(Arc::new(sink))
}
