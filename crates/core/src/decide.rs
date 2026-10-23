//! The decision function (`docs/design.md` 5). It is pure (G3): the caller
//! passes the policy, the call, the counters, the gate state and the time.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::hook::{Caller, FenceReason, FenceVerdict, Reach, ToolCall};
use crate::ids::{ArgName, PluginName, ToolName};
use crate::policy::{App, Approval, ArgumentFence, Policy, Scalar};
use crate::time::Timestamp;
use crate::value::ArgValue;

/// The ID of one gate. Equal calls of one app instance give equal IDs, so an
/// identical retry finds the same gate (`docs/design.md` 5.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GateId([u8; 16]);

impl GateId {
    /// Hash the app instance, the upstream, the tool and the canonical
    /// arguments, each separated by a NUL byte. Keep the first 16 bytes.
    #[must_use]
    pub fn from_call(call: &ToolCall<'_>) -> Self {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(call.app.as_str());
        hasher.update([0]);
        hasher.update(call.upstream.as_str());
        hasher.update([0]);
        hasher.update(call.tool.as_str());
        hasher.update([0]);
        hasher.update(ArgValue::canonical_object(call.arguments));
        let digest = hasher.finalize();
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest[..16]);
        Self(id)
    }

    /// The ID as 32 lower-case hex characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GateId({})", self.to_hex())
    }
}

impl fmt::Display for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The gates of one app instance, as the caller keeps them. Each map value
/// is the time the entry expires.
#[derive(Debug, Clone, Copy)]
pub struct Gates<'a> {
    pub pending: &'a BTreeSet<GateId>,
    pub approved: &'a BTreeMap<GateId, Timestamp>,
    pub denied: &'a BTreeMap<GateId, Timestamp>,
}

/// One request to decide.
#[derive(Debug)]
pub struct Request<'a> {
    /// The result of the identity hook.
    pub caller: Option<&'a Caller>,
    pub upstream: &'a PluginName,
    pub tool: &'a ToolName,
    pub arguments: &'a BTreeMap<String, ArgValue>,
    /// The calls this app instance made in the current minute, before this one.
    pub calls_this_minute: u32,
    pub gates: Gates<'a>,
    pub now: Timestamp,
}

/// Why a call is denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    PolicyNotLoaded,
    UnknownCredential,
    RateLimited,
    ToolNotGranted,
    ArgumentFenced {
        argument: ArgName,
    },
    Fence {
        plugin: PluginName,
        reason: FenceReason,
    },
    ApprovalDenied,
    GateCap,
}

/// The result of the decision function.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
    /// The call waits for an approval of this gate.
    Gate(GateId),
}

/// Decide one call. `policy` is `None` when no valid policy is loaded.
pub fn decide(policy: Option<&Policy>, request: &Request<'_>) -> Decision {
    let Some(policy) = policy else {
        return Decision::Deny(DenyReason::PolicyNotLoaded);
    };
    let Some((caller, app)) = request
        .caller
        .and_then(|caller| policy.app(&caller.app).map(|app| (caller, app)))
    else {
        return Decision::Deny(DenyReason::UnknownCredential);
    };

    if request.calls_this_minute >= app.limits().calls_per_minute {
        return Decision::Deny(DenyReason::RateLimited);
    }

    let Some(grant) = app.grant(request.upstream, request.tool) else {
        return Decision::Deny(DenyReason::ToolNotGranted);
    };
    if !in_reach(&caller.reach, request.upstream, request.tool) {
        return Decision::Deny(DenyReason::ToolNotGranted);
    }

    for (argument, fence) in grant.arguments() {
        if !passes(fence, request.arguments.get(argument.as_str())) {
            return Decision::Deny(DenyReason::ArgumentFenced {
                argument: argument.clone(),
            });
        }
    }

    let call = ToolCall {
        app: &caller.app,
        upstream: request.upstream,
        tool: request.tool,
        arguments: request.arguments,
        now: request.now,
    };
    let fenced = match run_fences(app, &call) {
        Ok(fenced) => fenced,
        Err(reason) => return Decision::Deny(reason),
    };

    if grant.approval() == Approval::Required || fenced == FenceOutcome::Gate {
        return decide_gate(app, &call, request.gates, request.now);
    }
    Decision::Allow
}

fn in_reach(reach: &Reach, upstream: &PluginName, tool: &ToolName) -> bool {
    match reach {
        Reach::Full => true,
        Reach::Only(tools) => tools
            .get(upstream)
            .is_some_and(|names| names.contains(tool)),
    }
}

fn passes(fence: &ArgumentFence, value: Option<&ArgValue>) -> bool {
    match fence {
        ArgumentFence::Allow(allowed) => {
            value.is_some_and(|value| allowed.iter().any(|scalar| matches(scalar, value)))
        }
        ArgumentFence::Deny(denied) => match value {
            None => true,
            Some(value) => is_scalar(value) && !denied.iter().any(|scalar| matches(scalar, value)),
        },
    }
}

fn is_scalar(value: &ArgValue) -> bool {
    match value {
        ArgValue::Bool(_)
        | ArgValue::Int(_)
        | ArgValue::UInt(_)
        | ArgValue::Float(_)
        | ArgValue::String(_)
        | ArgValue::Null => true,
        ArgValue::Array(_) | ArgValue::Object(_) => false,
    }
}

fn matches(scalar: &Scalar, value: &ArgValue) -> bool {
    match (scalar, value) {
        (Scalar::Bool(expected), ArgValue::Bool(found)) => expected == found,
        (Scalar::Int(expected), ArgValue::Int(found)) => expected == found,
        (Scalar::String(expected), ArgValue::String(found)) => expected == found,
        (Scalar::Bool(_) | Scalar::Int(_) | Scalar::String(_), _) => false,
    }
}

/// What the fences of one call ask for, when none denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FenceOutcome {
    Clear,
    Gate,
}

/// Run every fence in plugin name order. The first deny wins.
fn run_fences(app: &App, call: &ToolCall<'_>) -> Result<FenceOutcome, DenyReason> {
    let mut outcome = FenceOutcome::Clear;
    for active in app.fences() {
        match active.fence.check(call) {
            FenceVerdict::Pass => {}
            FenceVerdict::Gate => outcome = FenceOutcome::Gate,
            FenceVerdict::Deny(reason) => {
                return Err(DenyReason::Fence {
                    plugin: active.plugin.clone(),
                    reason,
                });
            }
        }
    }
    Ok(outcome)
}

fn decide_gate(app: &App, call: &ToolCall<'_>, gates: Gates<'_>, now: Timestamp) -> Decision {
    let id = GateId::from_call(call);
    let live =
        |entries: &BTreeMap<GateId, Timestamp>| entries.get(&id).is_some_and(|end| *end > now);

    if live(gates.denied) {
        return Decision::Deny(DenyReason::ApprovalDenied);
    }
    if live(gates.approved) {
        return Decision::Allow;
    }
    if gates.pending.contains(&id) {
        return Decision::Gate(id);
    }
    let pending = u32::try_from(gates.pending.len()).unwrap_or(u32::MAX);
    if pending >= app.limits().max_pending_gates {
        return Decision::Deny(DenyReason::GateCap);
    }
    Decision::Gate(id)
}
