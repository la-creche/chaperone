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
    AfterDecision, AllowedCall, ArgumentsDigest, AuditApp, AuditDecision, AuditError, AuditEvent,
    AuditRecord, AuditTool, CallAudit, CallNumber, GateMismatch, GatedCall, RunId, WaitingCall,
};
pub use decide::{Decision, DenyReason, GateId, Gates, Request, decide};
pub use exposed::{ExposedError, ExposedName, SEPARATOR};
pub use gateway::{CallFault, CallOutcome, Health, ListError, ListedTool, UpstreamResult};
pub use hook::{
    ANSWER_CAP, APPROVE_TOOL, AnswerError, ApprovalRequest, AuditSink, Caller, Clock, Credentials,
    DenialReason, Fence, FenceReason, FenceVerdict, GateAnswer, Gateway, Identity, PreparedFence,
    RawSection, Reach, SecretSource, SectionError, ToolCall,
};
pub use ids::{
    AppId, ArgName, Name, NameError, NameKind, PluginName, PluginUser, SecretName, SecretParam,
    ToolName,
};
pub use install::{
    Binding, CHILD_ENV_VAR, Catalog, Found, Guard, INSTALL_FILE_CAP, InstallEntry, InstallError,
    InstallFile, Location, PluginKey, SecretDelivery, Setup, SetupError, resolve,
};
pub use plugin::{Hook, Manifest, ManifestError, PLUGIN_FILE_CAP, PluginKind, Runtime, Slot};
pub use policy::{
    App, Approval, ArgumentFence, DigestError, InflightLimit, Limits, POLICY_FILE_CAP, Policy,
    PolicyError, Scalar, TokenDigest, ToolGrant, UpstreamBound, with_digest,
};
pub use secret::{Bearer, REDACTED, Secret, SecretError};
pub use time::Timestamp;
pub use value::{ArgValue, Finite};
