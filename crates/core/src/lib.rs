//! The core of chaperone: policy types, the strict JSON reader and the pure
//! decision. This crate does no I/O (G3). `crates/core/AGENTS.md` has the
//! rules.

mod decide;
mod hook;
mod ids;
mod install;
mod plugin;
mod policy;
mod secret;
pub mod strict;
mod time;
mod value;

pub use decide::{Decision, DenyReason, GateId, Gates, Request, decide};
pub use hook::{
    Caller, Credentials, Fence, FenceReason, FenceVerdict, Identity, PreparedFence, RawSection,
    Reach, SectionError, ToolCall,
};
pub use ids::{AppId, ArgName, NameError, PluginName, SecretName, ToolName};
pub use install::{
    Binding, Catalog, Found, INSTALL_FILE_CAP, InstallEntry, InstallError, InstallFile, Location,
    SecretDelivery, Setup, SetupError, resolve,
};
pub use plugin::{
    Hook, Manifest, ManifestError, PLUGIN_FILE_CAP, PluginKind, Runtime, SecretParam, Slot,
};
pub use policy::{
    App, Approval, ArgumentFence, Limits, POLICY_FILE_CAP, Policy, PolicyError, Scalar,
    TokenDigest, ToolGrant,
};
pub use secret::{Bearer, Secret};
pub use time::Timestamp;
pub use value::ArgValue;
