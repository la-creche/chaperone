//! The core of chaperone: policy types, the strict JSON reader and the pure
//! decision. This crate does no I/O (G3). `crates/core/AGENTS.md` has the
//! rules.

mod ids;
mod secret;
pub mod strict;
mod time;
mod value;

pub use ids::{AppId, ArgName, Name, NameError, NameKind, PluginName, SecretName, ToolName};
pub use secret::Secret;
pub use time::Timestamp;
pub use value::ArgValue;
