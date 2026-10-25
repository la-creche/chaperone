//! The call path of the program. It resolves the caller, counts the call,
//! decides and writes the decision record. It then runs the call through
//! its upstream, checks the result, writes the final record and answers.
//! No approval channel answers in build step 5, so a gated call fails with
//! `no_approval_channel` (G2).

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chaperone_core::{
    AfterDecision, AllowedCall, AppId, ArgValue, ArgumentsDigest, AuditApp, AuditError, AuditSink,
    AuditTool, CallAudit, CallFault, CallNumber, CallOutcome, Caller, Clock, Credentials, Decision,
    ExposedName, Gates, Gateway, Identity, ListError, ListedTool, PluginName, Policy, Request,
    RunId, Timestamp, ToolName, UpstreamResult,
};

use crate::effect::{self, Redactor, UPSTREAM_BUDGET, UpstreamFault, Upstreams};

/// The longest the program waits for one decision (`docs/design.md` 5.5).
/// A decision that takes longer fails the call with `no_decision` (G2).
pub const DECISION_BUDGET: Duration = Duration::from_secs(5);

/// The time bounds of one call (`docs/design.md` 5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub decision: Duration,
    pub upstream: Duration,
}

impl Bounds {
    /// The bounds of `docs/design.md` 5.5.
    pub const DEFAULT: Self = Self {
        decision: DECISION_BUDGET,
        upstream: UPSTREAM_BUDGET,
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
    policy: Arc<Policy>,
    identity: Box<dyn Identity>,
    audit: Arc<dyn AuditSink>,
    clock: Box<dyn Clock>,
    upstreams: Upstreams,
    redactor: Redactor,
    bounds: Bounds,
    counters: Mutex<Counters>,
}

/// The plugins one gateway runs with: the slot plugins the call path uses,
/// the running upstreams and every secret for blanking.
#[derive(Debug)]
pub struct Plugins {
    pub identity: Box<dyn Identity>,
    pub audit: Arc<dyn AuditSink>,
    pub clock: Box<dyn Clock>,
    pub upstreams: Upstreams,
    pub redactor: Redactor,
}

/// An allowed call between its decision record and its upstream call.
struct Staged {
    call: AllowedCall,
    upstream: PluginName,
    tool: ToolName,
    arguments: BTreeMap<String, ArgValue>,
}

/// Where a call stands after the decision record.
enum AfterRecord {
    /// The call is answered. No upstream runs.
    Done(CallOutcome),
    /// The call is allowed, and its upstream runs next.
    Allowed(Staged),
}

impl ChaperoneGateway {
    /// A gateway over a loaded policy and the running upstreams.
    #[must_use]
    pub fn new(run: RunId, policy: Policy, plugins: Plugins, bounds: Bounds) -> Self {
        let Plugins {
            identity,
            audit,
            clock,
            upstreams,
            redactor,
        } = plugins;
        Self {
            run,
            policy: Arc::new(policy),
            identity,
            audit,
            clock,
            upstreams,
            redactor,
            bounds,
            counters: Mutex::new(Counters {
                rates: RateBook::default(),
                next_call: Some(CallNumber::FIRST),
            }),
        }
    }

    /// The tools that these credentials may see (`docs/design.md` 7.7): the
    /// policy grants each one, the reach holds it, its upstream lists it and
    /// its exposed name is valid.
    ///
    /// # Errors
    ///
    /// Returns [`ListError::UnknownCredential`] when the credentials resolve
    /// to no app instance.
    pub fn list_tools(&self, credentials: &Credentials<'_>) -> Result<Vec<ListedTool>, ListError> {
        let caller = self
            .resolve(credentials)
            .ok_or(ListError::UnknownCredential)?;
        let app = self
            .policy
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
            AuditApp::lookup(app, Some(&self.policy)),
            AuditTool::lookup(name, Some(&self.policy)),
            ArgumentsDigest::of(&arguments),
        );

        let Ok(exposed) = ExposedName::parse(name) else {
            return AfterRecord::Done(self.fail_before_decision(audit, CallFault::UnknownTool));
        };
        let Some(decision) =
            self.decide(caller, &exposed, &arguments, calls_this_minute, started_at)
        else {
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
            AfterDecision::Allowed(call) => AfterRecord::Allowed(Staged {
                call,
                upstream: exposed.upstream().clone(),
                tool: exposed.tool().clone(),
                arguments,
            }),
            AfterDecision::Gated(call) => {
                // Build step 6 asks the approval channel. None answers yet.
                let fault = CallFault::NoApprovalChannel;
                AfterRecord::Done(outcome(call.failed(fault, self.clock.now(), sink), fault))
            }
        }
    }

    /// Send an allowed call to its upstream and check the result
    /// (`docs/design.md` 7.7). The wait is bounded (`docs/design.md` 5.5).
    async fn run_upstream(
        &self,
        upstream: &PluginName,
        tool: &ToolName,
        arguments: BTreeMap<String, ArgValue>,
    ) -> Result<UpstreamResult, CallFault> {
        let Some(running) = self.upstreams.get(upstream) else {
            return Err(CallFault::NotConnected);
        };
        let raw = tokio::time::timeout(self.bounds.upstream, running.call(tool, arguments))
            .await
            .map_err(|_| CallFault::UpstreamTimeout)?;
        let raw = raw.map_err(|fault| match fault {
            UpstreamFault::NotConnected => CallFault::NotConnected,
            UpstreamFault::BadResult => CallFault::BadResult,
        })?;
        effect::check_result(raw, &self.redactor).map_err(|fault| match fault {
            UpstreamFault::NotConnected => CallFault::NotConnected,
            UpstreamFault::BadResult => CallFault::BadResult,
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
    /// it can hold a token (G9).
    pub(crate) fn resolve(&self, credentials: &Credentials<'_>) -> Option<Caller> {
        // The identity hook has no time bound (`docs/design.md` 5.5).
        let policy = &self.policy;
        panic::catch_unwind(AssertUnwindSafe(|| {
            self.identity.resolve(credentials, policy)
        }))
        .unwrap_or(None)
    }

    /// Decide on another thread and wait up to the budget. `None` means the
    /// decision did not return in time, or did not return at all.
    fn decide(
        &self,
        caller: Option<Caller>,
        name: &ExposedName,
        arguments: &BTreeMap<String, ArgValue>,
        calls_this_minute: u32,
        now: Timestamp,
    ) -> Option<Decision> {
        let policy = Arc::clone(&self.policy);
        let name = name.clone();
        let arguments = arguments.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let spawned = thread::Builder::new()
            .name("decide".to_owned())
            .spawn(move || {
                // Build step 6 keeps the gate state. No gate exists yet.
                let no_gates = BTreeMap::new();
                let decision = chaperone_core::decide(
                    Some(&policy),
                    &Request {
                        caller: caller.as_ref(),
                        upstream: name.upstream(),
                        tool: name.tool(),
                        arguments: &arguments,
                        calls_this_minute,
                        gates: Gates {
                            pending: &no_gates,
                            approved: &no_gates,
                            denied: &no_gates,
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
        caller: Option<Caller>,
        name: String,
        arguments: BTreeMap<String, ArgValue>,
    ) -> CallOutcome {
        let gateway = Arc::clone(&self.0);
        let staged = tokio::task::spawn_blocking(move || gateway.stage(caller, &name, arguments));
        let staged = match staged.await {
            Ok(AfterRecord::Done(outcome)) => return outcome,
            Ok(AfterRecord::Allowed(staged)) => staged,
            // The blocking task did not return its outcome (G2).
            Err(error) => {
                tracing::error!(%error, "the call did not return");
                return CallOutcome::Failed(CallFault::NoDecision);
            }
        };
        let result = self
            .0
            .run_upstream(&staged.upstream, &staged.tool, staged.arguments)
            .await;
        let gateway = Arc::clone(&self.0);
        let finished =
            tokio::task::spawn_blocking(move || gateway.finish(staged.call, result)).await;
        match finished {
            Ok(outcome) => outcome,
            // The final record may not be written, so no result returns (G6).
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
        let caller = self.0.resolve(credentials);
        self.call_resolved(caller, name.to_owned(), arguments).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Mutex<Counters> {
        Mutex::new(Counters {
            rates: RateBook::default(),
            next_call: Some(CallNumber::FIRST),
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
