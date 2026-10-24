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
        use sha2::digest::typenum::U16;
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
        let (head, _) = digest.split_ref::<U16>();
        Self((*head).into())
    }

    /// A fixed ID. Only the Kani proofs use it, to stub the hash.
    #[cfg(kani)]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
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

/// Kani proof of the argument-fence table (`docs/design.md` 5.2, row 4).
#[cfg(kani)]
mod proofs {
    use super::passes;
    use crate::policy::{ArgumentFence, Scalar};
    use crate::value::ArgValue;

    fn any_scalar() -> Scalar {
        let pick: u8 = kani::any();
        kani::assume(pick < 3);
        match pick {
            0 => Scalar::Bool(kani::any()),
            1 => Scalar::Int(kani::any()),
            _ => Scalar::String(if kani::any() { "x" } else { "y" }.to_owned()),
        }
    }

    fn any_value() -> ArgValue {
        let pick: u8 = kani::any();
        kani::assume(pick < 6);
        match pick {
            0 => ArgValue::Bool(kani::any()),
            1 => ArgValue::Int(kani::any()),
            2 => ArgValue::UInt(kani::any()),
            3 => ArgValue::String(if kani::any() { "x" } else { "y" }.to_owned()),
            4 => ArgValue::Null,
            _ => ArgValue::Array(Vec::new()),
        }
    }

    fn same(scalar: &Scalar, value: &ArgValue) -> bool {
        match (scalar, value) {
            (Scalar::Bool(a), ArgValue::Bool(b)) => a == b,
            (Scalar::Int(a), ArgValue::Int(b)) => a == b,
            (Scalar::String(a), ArgValue::String(b)) => a == b,
            (Scalar::Bool(_) | Scalar::Int(_) | Scalar::String(_), _) => false,
        }
    }

    /// An allow fence passes exactly the listed value. A deny fence refuses
    /// the listed value and every array, and passes a missing argument.
    #[kani::proof]
    #[kani::unwind(3)]
    fn argument_fence_table() {
        let scalar = any_scalar();
        let value = any_value();
        let present = kani::any::<bool>();
        let found = if present { Some(&value) } else { None };
        let is_array = matches!(value, ArgValue::Array(_));

        let allow = passes(&ArgumentFence::Allow(vec![scalar.clone()]), found);
        assert_eq!(allow, present && same(&scalar, &value));

        let deny = passes(&ArgumentFence::Deny(vec![scalar.clone()]), found);
        assert_eq!(deny, !present || (!is_array && !same(&scalar, &value)));
    }

    /// The same table, with booleans and integers only.
    /// An allow fence passes exactly the listed value. A deny fence refuses
    /// the listed value and every array, and passes a missing argument.
    #[kani::proof]
    #[kani::unwind(3)]
    fn argument_fence_table_no_strings() {
        let scalar = if kani::any() {
            Scalar::Bool(kani::any())
        } else {
            Scalar::Int(kani::any())
        };
        let value = match kani::any::<u8>() {
            0 => ArgValue::Bool(kani::any()),
            1 => ArgValue::Null,
            2 => ArgValue::Array(Vec::new()),
            _ => ArgValue::Int(kani::any()),
        };
        let present = kani::any::<bool>();
        let found = if present { Some(&value) } else { None };
        let is_array = matches!(value, ArgValue::Array(_));

        let allow = passes(&ArgumentFence::Allow(vec![scalar.clone()]), found);
        assert_eq!(allow, present && same(&scalar, &value));

        let deny = passes(&ArgumentFence::Deny(vec![scalar.clone()]), found);
        assert_eq!(deny, !present || (!is_array && !same(&scalar, &value)));
    }
}
