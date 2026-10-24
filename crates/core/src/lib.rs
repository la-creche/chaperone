//! The core of chaperone: policy types, the strict JSON reader and the pure
//! decision. This crate does no I/O (G3). `crates/core/AGENTS.md` has the
//! rules.

// G2: a panic is an unhandled error. These lints refuse the panics that
// arithmetic and slicing can hide.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::string_slice
)]

mod decide;
mod hook;
mod ids;
mod install;
mod plugin;
mod policy;
#[cfg(kani)]
mod proofs;
mod secret;
pub mod strict;
mod time;
mod value;

pub use decide::{Decision, DenyReason, GateId, Gates, Request, decide};
pub use hook::{
    Caller, Credentials, Fence, FenceReason, FenceVerdict, Identity, PreparedFence, RawSection,
    Reach, SectionError, ToolCall,
};
pub use ids::{
    AppId, ArgName, Name, NameError, NameKind, PluginName, SecretName, SecretParam, ToolName,
};
pub use install::{
    Binding, Catalog, Found, INSTALL_FILE_CAP, InstallEntry, InstallError, InstallFile, Location,
    PluginKey, SecretDelivery, Setup, SetupError, resolve,
};
pub use plugin::{Hook, Manifest, ManifestError, PLUGIN_FILE_CAP, PluginKind, Runtime, Slot};
pub use policy::{
    App, Approval, ArgumentFence, DigestError, Limits, POLICY_FILE_CAP, Policy, PolicyError,
    Scalar, TokenDigest, ToolGrant,
};
pub use secret::{Bearer, Secret};
pub use time::Timestamp;
pub use value::ArgValue;
