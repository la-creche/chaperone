//! The call path of the program. It resolves the caller, counts the call,
//! decides and writes the decision record. It then runs the call through
//! its upstream, checks the result, writes the final record and answers. A
//! gated call returns `waiting` at once. The approval task runs it when the
//! answer comes and keeps the result for an identical call to collect
//! (`docs/design.md` 5.3).

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chaperone_core::{
    AfterDecision, AllowedCall, AppId, ApprovalRequest, ArgValue, ArgumentsDigest, AuditApp,
    AuditError, AuditSink, AuditTool, CallAudit, CallFault, CallNumber, CallOutcome, Caller, Clock,
    Credentials, Decision, ExposedName, GateAnswer, GateId, GatedCall, Gates, Gateway, Health,
    Identity, ListError, ListedTool, PluginName, Policy, Request, RunId, Timestamp, ToolCall,
    ToolName, UpstreamBound, UpstreamResult, WaitingCall,
};
use tokio::sync::watch;

use crate::approval::ApprovalChannel;
use crate::effect::{self, EffectFault, Redactor, Upstreams};
use crate::gates::{GATE_LIFE, GateBook, GateMaps, GateStatus, Opened};
use crate::inflight::{Inflight, Slot};
use crate::reload::PolicySource;

/// The longest the program waits for one decision (`docs/design.md` 5.5).
/// A decision that takes longer fails the call with `no_decision` (G2).
pub const DECISION_BUDGET: Duration = Duration::from_secs(5);

/// The time bounds of one call (`docs/design.md` 5.5). The bound of an
/// upstream call comes from the upstream grant in the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub decision: Duration,
    /// How long a gate lives, with its approval ask and its kept result.
    pub gate: Duration,
}

impl Bounds {
    /// The bounds of `docs/design.md` 5.5.
    pub const DEFAULT: Self = Self {
        decision: DECISION_BUDGET,
        gate: GATE_LIFE,
    };
}

const MINUTE_MILLIS: i64 = 60_000;

/// The calls of one app instance in its current minute.
#[derive(Debug, Clone, Copy)]
struct Window {
    minute: i64,
    calls: u32,
}

/// The calls of each app instance in its current minute.
#[derive(Debug, Default)]
struct RateBook {
    windows: BTreeMap<AppId, Window>,
}

impl RateBook {
    /// Count one call of `app` at `now`. Return the calls before it in the
    /// same minute.
    fn count(&mut self, app: &AppId, now: Timestamp) -> u32 {
        let minute = now.unix_millis().div_euclid(MINUTE_MILLIS);
        let window = self
            .windows
            .entry(app.clone())
            .or_insert(Window { minute, calls: 0 });
        if window.minute != minute {
            *window = Window { minute, calls: 0 };
        }
        let before = window.calls;
        window.calls = window.calls.saturating_add(1);
        before
    }
}

/// The state that changes with each call.
#[derive(Debug)]
struct Counters {
    rates: RateBook,
    /// The number of the next call, or `None` once the counter is exhausted.
    next_call: Option<CallNumber>,
    gates: GateBook,
}

/// Why a call could not take a call number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BeginFault {
    /// The call counter is exhausted.
    Exhausted,
    /// A panic left the counters lock poisoned. The program does not reach
    /// inside a poisoned lock, so every later call fails (G2).
    Poisoned,
}

/// Take the next call number and count the call for `app`.
fn begin(
    counters: &Mutex<Counters>,
    app: Option<&AppId>,
    now: Timestamp,
) -> Result<(CallNumber, u32), BeginFault> {
    let mut counters = counters.lock().map_err(|_| BeginFault::Poisoned)?;
    let call = counters.next_call.ok_or(BeginFault::Exhausted)?;
    counters.next_call = call.checked_next();
    let calls_this_minute = app.map_or(0, |app| counters.rates.count(app, now));
    Ok((call, calls_this_minute))
}

/// The program's side of the gateway. It decides each call through core,
/// runs an allowed call through its upstream and writes the audit records
/// of the call.
#[derive(Debug)]
pub struct ChaperoneGateway {
    run: RunId,
    policy: PolicySource,
    identity: Box<dyn Identity>,
    audit: Arc<dyn AuditSink>,
    clock: Box<dyn Clock>,
    upstreams: Upstreams,
    approval: ApprovalChannel,
    redactor: Redactor,
    bounds: Bounds,
    counters: Mutex<Counters>,
    inflight: Inflight,
}

/// The plugins one gateway runs with: the slot plugins the call path uses,
/// the running upstreams and every secret for blanking.
#[derive(Debug)]
pub struct Plugins {
    pub identity: Box<dyn Identity>,
    pub audit: Arc<dyn AuditSink>,
    pub clock: Box<dyn Clock>,
    pub upstreams: Upstreams,
    pub approval: ApprovalChannel,
    pub redactor: Redactor,
}

/// An allowed call between its decision record and its upstream call.
struct Staged {
    call: AllowedCall,
    app: AppId,
    upstream: PluginName,
    tool: ToolName,
    arguments: BTreeMap<String, ArgValue>,
    bound: Duration,
    /// The in-flight slot of the call, held until its final record.
    slot: Slot,
}

/// A gated call between its decision record and the approval answer.
struct StagedGate {
    call: GatedCall,
    app: AppId,
    exposed: ExposedName,
    arguments: BTreeMap<String, ArgValue>,
    bound: Duration,
}

/// The state one decision reads besides the call itself.
struct Facts {
    policy: Option<Arc<Policy>>,
    caller: Option<Caller>,
    calls_this_minute: u32,
    calls_in_flight: u32,
    gates: GateMaps,
    now: Timestamp,
}

/// Where a call stands after the decision record.
enum AfterRecord {
    /// The call is answered. No upstream runs.
    Done(CallOutcome),
    /// The call is allowed, and its upstream runs next.
    Allowed(Staged),
    /// The call waits on its gate.
    Gated(StagedGate),
}

impl ChaperoneGateway {
    /// The policy for one call. An upstream that ended since start is down,
    /// so each app granted it is refused (`docs/design.md` 7.7).
    fn policy(&self) -> Option<Arc<Policy>> {
        let ended: BTreeSet<PluginName> = self
            .upstreams
            .iter()
            .filter(|(_, upstream)| upstream.has_ended())
            .map(|(name, _)| name.clone())
            .collect();
        self.policy.current(&ended)
    }

    /// A gateway over a policy and the running upstreams.
    #[must_use]
    pub fn new(
        run: RunId,
        policy: impl Into<PolicySource>,
        plugins: Plugins,
        bounds: Bounds,
    ) -> Self {
        let Plugins {
            identity,
            audit,
            clock,
            upstreams,
            approval,
            redactor,
        } = plugins;
        Self {
            run,
            policy: policy.into(),
            identity,
            audit,
            clock,
            upstreams,
            approval,
            redactor,
            bounds,
            counters: Mutex::new(Counters {
                rates: RateBook::default(),
                next_call: Some(CallNumber::FIRST),
                gates: GateBook::default(),
            }),
            inflight: Inflight::default(),
        }
    }

    /// The tools that these credentials may see (`docs/design.md` 7.7): the
    /// policy grants each one, the reach holds it, its upstream lists it and
    /// its exposed name is valid.
    ///
    /// # Errors
    ///
    /// Returns [`ListError::PolicyNotLoaded`] when no valid policy is
    /// loaded, and [`ListError::UnknownCredential`] when the credentials
    /// resolve to no app instance.
    pub fn list_tools(&self, credentials: &Credentials<'_>) -> Result<Vec<ListedTool>, ListError> {
        let policy = self.policy().ok_or(ListError::PolicyNotLoaded)?;
        let caller = self
            .resolve(credentials, Some(&policy))
            .ok_or(ListError::UnknownCredential)?;
        let app = policy
            .app(&caller.app)
            .ok_or(ListError::UnknownCredential)?;
        let mut listed = Vec::new();
        for (upstream, tool) in app.granted() {
            if !caller.reach.holds(upstream, tool) {
                continue;
            }
            let Some(running) = self.upstreams.get(upstream) else {
                continue;
            };
            let Some(info) = running.tools().iter().find(|t| t.name == *tool) else {
                continue;
            };
            let Ok(name) = ExposedName::join(upstream, tool) else {
                tracing::warn!(%upstream, %tool, "the manifest leaves out a tool with an invalid exposed name");
                continue;
            };
            listed.push(ListedTool {
                name,
                description: info.description.clone(),
                input_schema: info.input_schema.clone(),
            });
        }
        Ok(listed)
    }

    /// The call path from the identity result to the decision record. It
    /// blocks on the audit sink and on the decision, so an async caller runs
    /// it on a blocking thread.
    fn stage(
        &self,
        policy: Option<Arc<Policy>>,
        caller: Option<Caller>,
        name: &str,
        arguments: BTreeMap<String, ArgValue>,
    ) -> AfterRecord {
        let started_at = self.clock.now();
        let app = caller.as_ref().map(|caller| &caller.app);
        let (call, calls_this_minute) = match begin(&self.counters, app, started_at) {
            Ok(begun) => begun,
            // Without a call number no record can be written (G6).
            Err(BeginFault::Exhausted) => {
                return AfterRecord::Done(CallOutcome::Failed(CallFault::AuditFailed));
            }
            Err(BeginFault::Poisoned) => {
                tracing::error!("the call counters are poisoned, so every call fails");
                return AfterRecord::Done(CallOutcome::Failed(CallFault::Halted));
            }
        };
        let audit = CallAudit::new(
            self.run,
            call,
            started_at,
            AuditApp::lookup(app, policy.as_deref()),
            AuditTool::lookup(name, policy.as_deref()),
            ArgumentsDigest::of(&arguments),
        );

        let Ok(exposed) = ExposedName::parse(name) else {
            return AfterRecord::Done(self.fail_before_decision(audit, CallFault::UnknownTool));
        };
        let app_id = caller.as_ref().map(|caller| caller.app.clone());
        // A call takes its in-flight slot before its decision. A call that
        // does not run gives the slot back when this function returns.
        let taken = app_id
            .as_ref()
            .map(|app| self.inflight.take(app, exposed.upstream()));
        let (slot, calls_in_flight) = match taken {
            Some(Ok((slot, before))) => (Some(slot), before),
            None => (None, 0),
            Some(Err(_)) => {
                tracing::error!("the in-flight count is poisoned, so every call fails");
                return AfterRecord::Done(self.fail_before_decision(audit, CallFault::Halted));
            }
        };
        let gates = match app_id.as_ref().map(|app| self.gate_maps(app, started_at)) {
            Some(Ok(maps)) => maps,
            None => GateMaps::default(),
            Some(Err(fault)) => return AfterRecord::Done(self.fail_before_decision(audit, fault)),
        };
        // A call whose gate is done when the decision reads it collects the
        // kept result and never runs (`docs/design.md` 5.3).
        let done_gate = app_id
            .as_ref()
            .map(|app| {
                GateId::from_call(&ToolCall {
                    app,
                    upstream: exposed.upstream(),
                    tool: exposed.tool(),
                    arguments: &arguments,
                    now: started_at,
                })
            })
            .filter(|gate| gates.approved.contains_key(gate));
        // The policy that decides the call also bounds its upstream call.
        let bound = upstream_bound(policy.as_deref(), app_id.as_ref(), exposed.upstream());
        let facts = Facts {
            policy,
            caller,
            calls_this_minute,
            calls_in_flight,
            gates,
            now: started_at,
        };
        let Some(decision) = self.decide(facts, &exposed, &arguments) else {
            return AfterRecord::Done(self.fail_before_decision(audit, CallFault::NoDecision));
        };

        let sink = self.audit.as_ref();
        let next = match audit.decided(decision, self.clock.now(), sink) {
            Ok(next) => next,
            Err(error) => {
                tracing::error!(%error, "the decision record is not durable");
                return AfterRecord::Done(CallOutcome::Failed(CallFault::AuditFailed));
            }
        };
        match next {
            AfterDecision::Denied(reason) => AfterRecord::Done(CallOutcome::Denied(reason)),
            AfterDecision::Allowed(call) => {
                // The decision allows only a call of a known app instance.
                let (Some(app), Some(slot)) = (app_id, slot) else {
                    let fault = CallFault::NoDecision;
                    return AfterRecord::Done(outcome(
                        call.failed(fault, self.clock.now(), sink),
                        fault,
                    ));
                };
                if let Some(gate) = done_gate {
                    return AfterRecord::Done(match self.take_result(&app, gate) {
                        Ok(result) => match call.delivered(gate, self.clock.now(), sink) {
                            Ok(()) => CallOutcome::Ran(result),
                            Err(error) => {
                                tracing::error!(%error, "the delivered record is not durable");
                                CallOutcome::Failed(CallFault::AuditFailed)
                            }
                        },
                        Err(fault) => outcome(call.failed(fault, self.clock.now(), sink), fault),
                    });
                }
                AfterRecord::Allowed(Staged {
                    call,
                    app,
                    upstream: exposed.upstream().clone(),
                    tool: exposed.tool().clone(),
                    arguments,
                    bound,
                    slot,
                })
            }
            AfterDecision::Gated(call) => match app_id {
                Some(app) => AfterRecord::Gated(StagedGate {
                    call,
                    app,
                    exposed,
                    arguments,
                    bound,
                }),
                // The decision gates only a call of a known app instance.
                None => {
                    let fault = CallFault::ApprovalFault;
                    AfterRecord::Done(outcome(call.failed(fault, self.clock.now(), sink), fault))
                }
            },
        }
    }

    /// The live gates of `app`, for the decision.
    fn gate_maps(&self, app: &AppId, now: Timestamp) -> Result<GateMaps, CallFault> {
        let mut counters = self.counters.lock().map_err(|_| CallFault::Halted)?;
        Ok(counters.gates.snapshot(app, now))
    }

    /// The kept result of `gate`. The gate is removed with it. The fault is
    /// `ApprovalSpent` when an identical call collected the result first,
    /// so the approval runs one call (G2).
    fn take_result(&self, app: &AppId, gate: GateId) -> Result<UpstreamResult, CallFault> {
        let mut counters = self.counters.lock().map_err(|_| CallFault::Halted)?;
        counters
            .gates
            .take_result(app, gate)
            .ok_or(CallFault::ApprovalSpent)
    }

    /// Write the `waiting` record of a gated call. It blocks on the audit
    /// sink. The returned state ends the call when the answer comes.
    fn wait_gate(&self, call: GatedCall) -> Result<WaitingCall, CallOutcome> {
        call.waiting(self.clock.now(), self.audit.as_ref())
            .map_err(|error| {
                tracing::error!(%error, "the waiting record is not durable");
                CallOutcome::Failed(CallFault::AuditFailed)
            })
    }

    /// Write the final record of a gated call that the answer ended without
    /// a run. It blocks on the audit sink.
    fn fail_waiting(&self, call: WaitingCall, fault: CallFault) {
        if let Err(error) = call.failed(fault, self.clock.now(), self.audit.as_ref()) {
            tracing::error!(%error, "the final record of a gated call is not durable");
        }
    }

    /// Write the final record of a gated call that ran, and move its gate
    /// to done or faulted in the same step. The gate status stays locked
    /// while the sink writes, so a reader that sees the record finds the
    /// gate moved. The result is kept only after the record is durable (G6).
    /// It blocks on the audit sink.
    fn finish_waiting(
        &self,
        sender: &watch::Sender<GateStatus>,
        call: WaitingCall,
        gate: GateId,
        result: Result<UpstreamResult, CallFault>,
    ) {
        sender.send_modify(|status| {
            *status = match self.final_record(call, gate, result) {
                Some(result) => GateStatus::Done(result),
                None => GateStatus::Faulted,
            };
        });
    }

    /// Write the final record of a gated call that ran. Return the result
    /// to keep, or `None` when the call failed or the record is not
    /// durable.
    fn final_record(
        &self,
        call: WaitingCall,
        gate: GateId,
        result: Result<UpstreamResult, CallFault>,
    ) -> Option<UpstreamResult> {
        let sink = self.audit.as_ref();
        let Ok(allowed) = call.approved(gate) else {
            tracing::error!(%gate, "the approval names another gate");
            return None;
        };
        match result {
            Ok(result) => match allowed.ran(result.is_error, self.clock.now(), sink) {
                Ok(()) => Some(result),
                Err(error) => {
                    tracing::error!(%error, "the ran record is not durable, so the result is dropped");
                    None
                }
            },
            Err(fault) => {
                if let Err(error) = allowed.failed(fault, self.clock.now(), sink) {
                    tracing::error!(%error, "the final record of a gated call is not durable");
                }
                None
            }
        }
    }

    /// Ask the approval channel about one gate on its own task. On an
    /// approval, run the call and keep the result on the gate. The ask ends
    /// with the life of the gate (`docs/design.md` 5.3).
    fn approve_and_run(
        self: &Arc<Self>,
        sender: watch::Sender<GateStatus>,
        call: WaitingCall,
        app: AppId,
        exposed: ExposedName,
        arguments: BTreeMap<String, ArgValue>,
        bound: Duration,
    ) {
        let gateway = Arc::clone(self);
        let gate = call.gate();
        tokio::spawn(async move {
            let request = ApprovalRequest {
                gate,
                app: &app,
                tool: &exposed,
                arguments: &arguments,
            };
            let asked = tokio::time::timeout(
                gateway.bounds.gate,
                gateway.approval.ask(&request, &gateway.redactor),
            )
            .await;
            let fault = match asked {
                Ok(Ok(GateAnswer::Approved)) => {
                    sender.send_replace(GateStatus::Running);
                    // The run holds an in-flight slot until its final
                    // record. Its decision came before, so the count does
                    // not stop it.
                    let slot = gateway.inflight.take(&app, exposed.upstream());
                    let result = match slot {
                        Ok(_) => {
                            gateway
                                .run_upstream(
                                    &app,
                                    exposed.upstream(),
                                    exposed.tool(),
                                    arguments.clone(),
                                    bound,
                                )
                                .await
                        }
                        Err(_) => {
                            tracing::error!("the in-flight count is poisoned, so every call fails");
                            Err(CallFault::Halted)
                        }
                    };
                    let finishing = Arc::clone(&gateway);
                    let moving = sender.clone();
                    let finished = tokio::task::spawn_blocking(move || {
                        finishing.finish_waiting(&moving, call, gate, result);
                    })
                    .await;
                    if let Err(error) = finished {
                        tracing::error!(%error, "the final record did not return");
                        sender.send_replace(GateStatus::Faulted);
                    }
                    drop(slot);
                    return;
                }
                Ok(Ok(GateAnswer::Denied(reason))) => {
                    tracing::info!(%app, %gate, reason = reason.as_str(), "the approval channel denied the gate");
                    sender.send_replace(GateStatus::Denied(reason));
                    CallFault::ApprovalDenied
                }
                Ok(Err(fault)) => {
                    tracing::warn!(%app, %gate, ?fault, "the approval channel gave no answer");
                    sender.send_replace(GateStatus::Faulted);
                    CallFault::ApprovalFault
                }
                Err(_) => {
                    tracing::warn!(%app, %gate, "the approval channel did not answer in the life of the gate");
                    sender.send_replace(GateStatus::Faulted);
                    CallFault::ApprovalFault
                }
            };
            let finishing = Arc::clone(&gateway);
            if let Err(error) =
                tokio::task::spawn_blocking(move || finishing.fail_waiting(call, fault)).await
            {
                tracing::error!(%error, "the final record did not return");
            }
        });
    }

    /// Send an allowed call to its upstream and check the result
    /// (`docs/design.md` 7.7). The wait is bounded by `bound`
    /// (`docs/design.md` 5.5).
    async fn run_upstream(
        &self,
        app: &AppId,
        upstream: &PluginName,
        tool: &ToolName,
        arguments: BTreeMap<String, ArgValue>,
        bound: Duration,
    ) -> Result<UpstreamResult, CallFault> {
        let Some(running) = self.upstreams.get(upstream) else {
            return Err(CallFault::NotConnected);
        };
        let raw = tokio::time::timeout(bound, running.call(app, tool, arguments))
            .await
            .map_err(|_| CallFault::UpstreamTimeout)?;
        let raw = raw.map_err(|fault| match fault {
            EffectFault::NotConnected => CallFault::NotConnected,
            EffectFault::BadResult => CallFault::BadResult,
        })?;
        effect::check_result(raw, &self.redactor).map_err(|fault| match fault {
            EffectFault::NotConnected => CallFault::NotConnected,
            EffectFault::BadResult => CallFault::BadResult,
        })
    }

    /// Write the final record of an allowed call and answer. It blocks on
    /// the audit sink.
    fn finish(&self, call: AllowedCall, result: Result<UpstreamResult, CallFault>) -> CallOutcome {
        let sink = self.audit.as_ref();
        match result {
            Ok(result) => match call.ran(result.is_error, self.clock.now(), sink) {
                Ok(()) => CallOutcome::Ran(result),
                Err(error) => {
                    tracing::error!(%error, "the final record is not durable");
                    CallOutcome::Failed(CallFault::AuditFailed)
                }
            },
            Err(fault) => outcome(call.failed(fault, self.clock.now(), sink), fault),
        }
    }

    /// Run the identity hook. A hook that panics resolves to nothing, as a
    /// fence that panics denies (G2). The payload is dropped unread, because
    /// it can hold a token (G9). With no policy, nothing resolves.
    pub(crate) fn resolve(
        &self,
        credentials: &Credentials<'_>,
        policy: Option<&Policy>,
    ) -> Option<Caller> {
        let policy = policy?;
        // The identity hook has no time bound (`docs/design.md` 5.5).
        panic::catch_unwind(AssertUnwindSafe(|| {
            self.identity.resolve(credentials, policy)
        }))
        .unwrap_or(None)
    }

    /// Decide on another thread and wait up to the budget. `None` means the
    /// decision did not return in time, or did not return at all.
    fn decide(
        &self,
        facts: Facts,
        name: &ExposedName,
        arguments: &BTreeMap<String, ArgValue>,
    ) -> Option<Decision> {
        let Facts {
            policy,
            caller,
            calls_this_minute,
            calls_in_flight,
            gates,
            now,
        } = facts;
        let name = name.clone();
        let arguments = arguments.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let spawned = thread::Builder::new()
            .name("decide".to_owned())
            .spawn(move || {
                let decision = chaperone_core::decide(
                    policy.as_deref(),
                    &Request {
                        caller: caller.as_ref(),
                        upstream: name.upstream(),
                        tool: name.tool(),
                        arguments: &arguments,
                        calls_this_minute,
                        calls_in_flight,
                        gates: Gates {
                            pending: &gates.pending,
                            approved: &gates.approved,
                            denied: &gates.denied,
                        },
                        now,
                    },
                );
                // A caller that gave up has dropped the receiver. The
                // decision is then dropped too.
                let _ = sender.send(decision);
            });
        if spawned.is_err() {
            return None;
        }
        receiver.recv_timeout(self.bounds.decision).ok()
    }

    /// Write the only record of a call that fails before a decision, and
    /// answer.
    fn fail_before_decision(&self, audit: CallAudit, fault: CallFault) -> CallOutcome {
        let written = audit.failed_before_decision(fault, self.clock.now(), self.audit.as_ref());
        outcome(written, fault)
    }
}

/// The bound of a call to `upstream` by `app` under `policy`
/// (`docs/design.md` 5.5). A call that the policy does not grant is denied
/// before it runs, so it takes the default bound.
fn upstream_bound(policy: Option<&Policy>, app: Option<&AppId>, upstream: &PluginName) -> Duration {
    let bound = policy
        .zip(app)
        .and_then(|(policy, app)| policy.app(app))
        .and_then(|app| app.upstream_bound(upstream))
        .unwrap_or(UpstreamBound::DEFAULT);
    Duration::from_secs(bound.seconds())
}

/// The answer after the final record of a failed call: the fault, or the
/// audit fault when the record is not durable (G6).
fn outcome(written: Result<(), AuditError>, fault: CallFault) -> CallOutcome {
    match written {
        Ok(()) => CallOutcome::Failed(fault),
        Err(error) => {
            tracing::error!(%error, "the final record is not durable");
            CallOutcome::Failed(CallFault::AuditFailed)
        }
    }
}

/// The gateway as a front door holds it. The identity hook runs on the
/// calling thread, because `Credentials` borrows the request. The audit
/// writes and the decision wait run on a blocking thread. The upstream
/// call is awaited.
#[derive(Debug, Clone)]
pub struct SharedGateway(Arc<ChaperoneGateway>);

impl SharedGateway {
    #[must_use]
    pub fn new(gateway: ChaperoneGateway) -> Self {
        Self(Arc::new(gateway))
    }

    /// The call path after the identity hook.
    async fn call_resolved(
        &self,
        policy: Option<Arc<Policy>>,
        caller: Option<Caller>,
        name: String,
        arguments: BTreeMap<String, ArgValue>,
    ) -> CallOutcome {
        let gateway = Arc::clone(&self.0);
        let staged =
            tokio::task::spawn_blocking(move || gateway.stage(policy, caller, &name, arguments));
        let staged = match staged.await {
            Ok(AfterRecord::Done(outcome)) => return outcome,
            Ok(AfterRecord::Allowed(staged)) => staged,
            Ok(AfterRecord::Gated(staged)) => return self.gate_call(staged).await,
            // The blocking task did not return its outcome (G2).
            Err(error) => {
                tracing::error!(%error, "the call did not return");
                return CallOutcome::Failed(CallFault::NoDecision);
            }
        };
        self.run_and_finish(staged).await
    }

    /// Run an allowed call through its upstream and write its final record.
    async fn run_and_finish(&self, staged: Staged) -> CallOutcome {
        let slot = staged.slot;
        let result = self
            .0
            .run_upstream(
                &staged.app,
                &staged.upstream,
                &staged.tool,
                staged.arguments,
                staged.bound,
            )
            .await;
        let gateway = Arc::clone(&self.0);
        let finished =
            tokio::task::spawn_blocking(move || gateway.finish(staged.call, result)).await;
        drop(slot);
        match finished {
            Ok(outcome) => outcome,
            // The final record may not be written, so no result returns (G6).
            Err(error) => {
                tracing::error!(%error, "the final record did not return");
                CallOutcome::Failed(CallFault::AuditFailed)
            }
        }
    }

    /// Open the gate of a gated call, write its `waiting` record and answer
    /// `waiting` at once (`docs/design.md` 5.3). The call that created the
    /// gate also starts the approval task.
    async fn gate_call(&self, staged: StagedGate) -> CallOutcome {
        let gateway = &self.0;
        let gate = staged.call.gate();
        let now = gateway.clock.now();
        // The guard ends inside the closure, so no lock is held across an
        // await.
        let opened = gateway.counters.lock().ok().map(|mut counters| {
            let (_, opened, sender) =
                counters
                    .gates
                    .open(&staged.app, gate, now, gateway.bounds.gate);
            (opened, sender)
        });
        let Some((opened, sender)) = opened else {
            tracing::error!("the call counters are poisoned, so every call fails");
            return self.end_gate(staged.call, CallFault::Halted).await;
        };

        let recording = Arc::clone(gateway);
        let waiting = tokio::task::spawn_blocking(move || recording.wait_gate(staged.call)).await;
        let waiting = match waiting {
            Ok(Ok(waiting)) => waiting,
            Ok(Err(outcome)) => return outcome,
            Err(error) => {
                tracing::error!(%error, "the waiting record did not return");
                return CallOutcome::Failed(CallFault::AuditFailed);
            }
        };
        match (opened, sender) {
            (Opened::Created, Some(sender)) => {
                gateway.approve_and_run(
                    sender,
                    waiting,
                    staged.app,
                    staged.exposed,
                    staged.arguments,
                    staged.bound,
                );
            }
            // An identical call while the gate is pending or running ends
            // with its waiting record.
            (Opened::Created, None) | (Opened::Found, _) => {}
        }
        CallOutcome::Waiting(gate)
    }

    /// Write the final record of a gated call that fails before it waits.
    async fn end_gate(&self, call: GatedCall, fault: CallFault) -> CallOutcome {
        let gateway = Arc::clone(&self.0);
        let written = tokio::task::spawn_blocking(move || {
            let sink = gateway.audit.as_ref();
            outcome(call.failed(fault, gateway.clock.now(), sink), fault)
        })
        .await;
        match written {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!(%error, "the final record did not return");
                CallOutcome::Failed(CallFault::AuditFailed)
            }
        }
    }
}

impl Gateway for SharedGateway {
    async fn list_tools(
        &self,
        credentials: &Credentials<'_>,
    ) -> Result<Vec<ListedTool>, ListError> {
        self.0.list_tools(credentials)
    }

    async fn call_tool(
        &self,
        credentials: &Credentials<'_>,
        name: &str,
        arguments: BTreeMap<String, ArgValue>,
    ) -> CallOutcome {
        // One policy decides the whole call, even when the file changes
        // during it (`docs/design.md` 6).
        let policy = self.0.policy();
        let caller = self.0.resolve(credentials, policy.as_deref());
        self.call_resolved(policy, caller, name.to_owned(), arguments)
            .await
    }

    async fn health(&self) -> Health {
        match self.0.policy() {
            Some(_) => Health::Serving,
            None => Health::PolicyNotLoaded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Mutex<Counters> {
        Mutex::new(Counters {
            rates: RateBook::default(),
            next_call: Some(CallNumber::FIRST),
            gates: GateBook::default(),
        })
    }

    #[test]
    fn begin_numbers_each_call() {
        let counters = fresh();
        let now = Timestamp::from_unix_millis(0);
        let (first, _) = begin(&counters, None, now).unwrap();
        let (second, _) = begin(&counters, None, now).unwrap();
        assert_eq!(first, CallNumber::FIRST);
        assert_eq!(Some(second), first.checked_next());
    }

    #[test]
    fn a_poisoned_lock_fails_every_later_call() {
        let counters = std::sync::Arc::new(fresh());
        let held = std::sync::Arc::clone(&counters);
        let panicked = std::thread::spawn(move || {
            let _guard = held.lock().unwrap();
            panic!("a panic while the lock is held");
        })
        .join();
        assert!(panicked.is_err());

        let now = Timestamp::from_unix_millis(0);
        for _ in 0..2 {
            assert_eq!(begin(&counters, None, now), Err(BeginFault::Poisoned));
        }
    }

    #[test]
    fn the_rate_book_counts_within_a_minute_and_starts_over_after_it() {
        let app = AppId::try_new("librechat").unwrap();
        let other = AppId::try_new("other").unwrap();
        let mut book = RateBook::default();
        let start = Timestamp::from_unix_millis(120_000);
        assert_eq!(book.count(&app, start), 0);
        assert_eq!(book.count(&app, Timestamp::from_unix_millis(179_999)), 1);
        assert_eq!(book.count(&other, start), 0);
        assert_eq!(book.count(&app, Timestamp::from_unix_millis(180_000)), 0);
    }
}
