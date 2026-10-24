//! The core of chaperone: policy types, the strict JSON reader and the pure
//! decision. This crate does no I/O (G3). `crates/core/AGENTS.md` has the
//! rules.

mod audit;
mod decide;
mod exposed;
mod gateway;
mod hook;
mod ids;
mod install;
mod plugin;
mod policy;
mod secret;
pub mod strict;
mod time;
mod value;

pub use audit::{
    AfterDecision, AllowedCall, ArgumentsDigest, AuditError, AuditEvent, AuditRecord, AuditSink,
    AuditTool, CallAudit, CallNumber, GatedCall, RunId,
};
pub use decide::{Decision, DenyReason, GateId, Gates, Request, decide};
pub use exposed::{ExposedError, ExposedName, SEPARATOR};
pub use gateway::{CallFault, CallOutcome, Gateway, ListError, ListedTool};
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
