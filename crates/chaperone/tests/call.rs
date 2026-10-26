//! The call path end to end, without a front door: each outcome of
//! `docs/design.md` 5.4 that build step 5 can reach, and its audit records.
//! An in-memory fake stands in for the upstream process.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chaperone::approval::ApprovalChannel;
use chaperone::effect::{Effect, EffectFault, EffectTool, RESULT_CAP, Redactor, Upstreams};
use chaperone::gateway::{Bounds, ChaperoneGateway, Plugins, SharedGateway};
use chaperone::startup::{self, Secrets};
use chaperone_core::{
    AppId, ArgValue, AuditDecision, AuditError, AuditEvent, AuditRecord, AuditSink, AuditTool,
    Bearer, CallFault, CallNumber, CallOutcome, Caller, Clock, Credentials, DenyReason, Fence,
    FenceVerdict, Gateway, Identity, InstallFile, ListError, PluginName, Policy, PreparedFence,
    RawSection, RunId, Secret, SecretName, SecretParam, SectionError, Timestamp, ToolCall,
    ToolName, UpstreamResult,
};
use rmcp::model::{CallToolResult, ContentBlock};
use support::{
    FakeApproval, INSTALL, TOKEN, config_dir, fake_approval, hanging_approval, plugin_tree,
    policy_text, secrets_dir, write_manifest,
};

const RUN: RunId = RunId::from_bytes([9; 16]);
const START: Timestamp = Timestamp::from_unix_millis(1_761_264_000_000);
const OTHER_TOKEN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// A sink that keeps each record for the test.
#[derive(Debug, Default)]
struct MemorySink {
    records: Mutex<Vec<AuditRecord>>,
    /// How long a write of a `ran` record takes after the record is
    /// visible, as a slow disk sync takes.
    ran_delay: Duration,
    /// How long a write of an allow decision takes after the record is
    /// visible.
    allow_delay: Duration,
}

impl MemorySink {
    fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap().clone()
    }

    fn events(&self) -> Vec<AuditEvent> {
        self.records()
            .iter()
            .map(|record| record.event().clone())
            .collect()
    }
}

impl AuditSink for MemorySink {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.records.lock().unwrap().push(record.clone());
        if matches!(record.event(), AuditEvent::Ran { .. }) {
            std::thread::sleep(self.ran_delay);
        }
        if matches!(record.event(), AuditEvent::Decided(AuditDecision::Allow)) {
            std::thread::sleep(self.allow_delay);
        }
        Ok(())
    }
}

/// A sink that refuses every record.
#[derive(Debug)]
struct RefusingSink;

impl AuditSink for RefusingSink {
    fn write(&self, _: &AuditRecord) -> Result<(), AuditError> {
        Err(AuditError::Encode)
    }
}

/// A clock the test moves.
#[derive(Debug)]
struct FixedClock(Mutex<Timestamp>);

impl FixedClock {
    fn set(&self, time: Timestamp) {
        *self.0.lock().unwrap() = time;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

/// An identity hook that panics on every request.
#[derive(Debug)]
struct PanicIdentity;

impl Identity for PanicIdentity {
    fn resolve(&self, _: &Credentials<'_>, _: &Policy) -> Option<Caller> {
        panic!("identity fault")
    }
}

/// A fence that never answers.
#[derive(Debug)]
struct HangFence(PluginName);

#[derive(Debug)]
struct PreparedHang;

impl Fence for HangFence {
    type Prepared = PreparedHang;

    fn name(&self) -> &PluginName {
        &self.0
    }

    fn prepare(&self, _: Option<RawSection<'_>>) -> Result<Self::Prepared, SectionError> {
        Ok(PreparedHang)
    }
}

impl PreparedFence for PreparedHang {
    fn check(&self, _: &ToolCall<'_>) -> FenceVerdict {
        std::thread::sleep(Duration::from_secs(60));
        FenceVerdict::Pass
    }
}

/// The loaded policy of the fixture with the repository's slot plugins.
fn loaded(root: &std::path::Path, calls_per_minute: u32) -> startup::Loaded {
    let plugins = plugin_tree(root);
    let config = config_dir(root, INSTALL, &policy_text(calls_per_minute));
    let secrets = secrets_dir(root);
    startup::load(&config, &plugins, &root.join("audit.jsonl"), &secrets).unwrap()
}

const SECRET_VALUE: &str = "tok-123";

/// Every secret the harness holds: one for `vikunja`.
fn secrets() -> Secrets {
    let mut vikunja = BTreeMap::new();
    vikunja.insert(
        SecretParam::try_new("VIKUNJA_TOKEN").unwrap(),
        Secret::new(
            SecretName::try_new("vikunja_token").unwrap(),
            SECRET_VALUE.to_owned(),
        ),
    );
    let mut secrets = Secrets::new();
    secrets.insert(PluginName::try_new("vikunja").unwrap(), vikunja);
    secrets
}

/// How long the fake `slow` tool takes to answer.
const SLOW: Duration = Duration::from_millis(1500);

/// An upstream in memory. Each tool answers by its name.
#[derive(Debug)]
struct FakeUpstream(Vec<EffectTool>);

impl FakeUpstream {
    fn new() -> Self {
        let tools = [
            "list_tasks",
            "create_task",
            "picture",
            "big",
            "broken",
            "slow",
            "secret_echo",
            "delete_task",
            "wait_task",
            "odd_task",
        ]
        .into_iter()
        .map(|name| EffectTool {
            name: ToolName::try_new(name).unwrap(),
            description: Some(format!("the fake {name} tool")),
            input_schema: BTreeMap::new(),
        })
        .collect();
        Self(tools)
    }
}

impl Effect for FakeUpstream {
    fn tools(&self) -> &[EffectTool] {
        &self.0
    }

    fn call<'a>(
        &'a self,
        _app: &'a AppId,
        tool: &'a ToolName,
        _arguments: BTreeMap<String, ArgValue>,
    ) -> Pin<Box<dyn Future<Output = Result<CallToolResult, EffectFault>> + Send + 'a>> {
        Box::pin(async move {
            let text = |text: String| CallToolResult::success(vec![ContentBlock::text(text)]);
            Ok(match tool.as_str() {
                "list_tasks" => text(format!("two tasks for token {SECRET_VALUE}")),
                "create_task" => text("created".to_owned()),
                "picture" => CallToolResult::success(vec![ContentBlock::image(
                    "iVBORw0KGgo=".to_owned(),
                    "image/png".to_owned(),
                )]),
                "big" => text("a".repeat(RESULT_CAP + 1)),
                "broken" => CallToolResult::error(vec![ContentBlock::text("boom".to_owned())]),
                "slow" => {
                    tokio::time::sleep(SLOW).await;
                    text("late".to_owned())
                }
                "secret_echo" => text(SECRET_VALUE.to_owned()),
                "delete_task" => text("deleted".to_owned()),
                "wait_task" => text("waited".to_owned()),
                "odd_task" => text("odd".to_owned()),
                _ => return Err(EffectFault::NotConnected),
            })
        })
    }
}

/// The running upstreams of the harness: the fake as `vikunja`.
fn upstreams() -> Upstreams {
    let mut upstreams = Upstreams::new();
    upstreams.insert(
        PluginName::try_new("vikunja").unwrap(),
        Box::new(FakeUpstream::new()),
    );
    upstreams
}

struct Harness {
    gateway: SharedGateway,
    sink: Arc<MemorySink>,
    clock: Arc<FixedClock>,
}

/// A gateway over the fixture policy, a memory sink and a fixed clock.
fn harness(calls_per_minute: u32) -> Harness {
    harness_with(calls_per_minute, MemorySink::default())
}

/// As [`harness`], with `sink`.
fn harness_with(calls_per_minute: u32, sink: MemorySink) -> Harness {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), calls_per_minute);
    let sink = Arc::new(sink);
    let clock = Arc::new(FixedClock(Mutex::new(START)));
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        RUN,
        loaded.policy,
        Plugins {
            identity: loaded.identity,
            audit: Arc::clone(&sink) as Arc<dyn AuditSink>,
            clock: Box::new(SharedClock(Arc::clone(&clock))),
            upstreams: upstreams(),
            approval: fake_approval(),
            redactor: Redactor::new(secrets()),
        },
        Bounds::DEFAULT,
    ));
    Harness {
        gateway,
        sink,
        clock,
    }
}

/// A `Clock` that the test holds a second handle to.
#[derive(Debug)]
struct SharedClock(Arc<FixedClock>);

impl Clock for SharedClock {
    fn now(&self) -> Timestamp {
        self.0.now()
    }
}

/// Call `name` with no arguments as the holder of `token`.
async fn call(gateway: &SharedGateway, token: Option<&str>, name: &str) -> CallOutcome {
    let bearer = token.map(|token| Bearer::new(token.to_owned()));
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: bearer.as_ref(),
        headers: &headers,
    };
    gateway.call_tool(&credentials, name, BTreeMap::new()).await
}

fn app(text: &str) -> AppId {
    AppId::try_new(text).unwrap()
}

#[tokio::test]
async fn an_allowed_call_runs_with_each_secret_blanked_after_two_records() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__list_tasks").await;
    let CallOutcome::Ran(result) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(
        result,
        UpstreamResult {
            content: vec!["two tasks for token [redacted]".to_owned()],
            is_error: false,
        }
    );
    assert_eq!(
        sink.events(),
        [
            AuditEvent::Decided(AuditDecision::Allow),
            AuditEvent::Ran { is_error: false },
        ]
    );
    let record = &sink.records()[0];
    assert_eq!(record.run(), RUN);
    assert_eq!(record.call(), CallNumber::FIRST);
    assert_eq!(record.started_at(), START);
    assert_eq!(record.app(), Some(&app("librechat")));
    assert_eq!(record.tool().as_str(), "vikunja__list_tasks");
}

#[tokio::test]
async fn a_tool_without_a_grant_is_denied_with_one_record() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__delete_everything").await;
    assert!(matches!(
        outcome,
        CallOutcome::Denied(DenyReason::ToolNotGranted)
    ));
    assert_eq!(
        sink.events(),
        [AuditEvent::Decided(AuditDecision::Deny("tool_not_granted"))]
    );
    assert_eq!(sink.records()[0].tool().as_str(), AuditTool::UNKNOWN);
}

/// Wait until the sink holds `count` records, up to three seconds.
async fn until_records(sink: &MemorySink, count: usize) {
    for _ in 0..150 {
        if sink.records().len() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "the sink holds {} records, not {count}",
        sink.records().len()
    );
}

#[tokio::test]
async fn a_visible_ran_record_means_the_result_is_kept() {
    let Harness { gateway, sink, .. } = harness_with(
        30,
        MemorySink {
            ran_delay: Duration::from_millis(500),
            ..MemorySink::default()
        },
    );
    let outcome = call(&gateway, Some(TOKEN), "vikunja__create_task").await;
    assert!(matches!(outcome, CallOutcome::Waiting(_)), "{outcome:?}");

    // The ran record is visible while the sink still writes it. An
    // identical call then waits for the write and collects the result.
    until_records(&sink, 3).await;
    assert_eq!(sink.events()[2], AuditEvent::Ran { is_error: false });
    let collected = call(&gateway, Some(TOKEN), "vikunja__create_task").await;
    let CallOutcome::Ran(result) = collected else {
        panic!("{collected:?}");
    };
    assert_eq!(result.content, ["created"]);
}

#[tokio::test]
async fn a_gated_call_waits_and_an_identical_call_collects_the_result() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__create_task").await;
    let CallOutcome::Waiting(gate) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(
        sink.events()[..2],
        [
            AuditEvent::Decided(AuditDecision::Gate(gate)),
            AuditEvent::Waiting(gate),
        ]
    );

    // The approval task runs the call and writes the ran record.
    until_records(&sink, 3).await;
    assert_eq!(sink.events()[2], AuditEvent::Ran { is_error: false });

    let collected = call(&gateway, Some(TOKEN), "vikunja__create_task").await;
    let CallOutcome::Ran(result) = collected else {
        panic!("{collected:?}");
    };
    assert_eq!(result.content, ["created"]);
    assert_eq!(
        sink.events()[3..],
        [
            AuditEvent::Decided(AuditDecision::Allow),
            AuditEvent::Delivered(gate),
        ]
    );

    // The result is collected once. The next identical call gates again.
    let again = call(&gateway, Some(TOKEN), "vikunja__create_task").await;
    assert!(matches!(again, CallOutcome::Waiting(_)), "{again:?}");
}

#[tokio::test]
async fn two_identical_calls_after_the_run_get_one_result() {
    let Harness { gateway, sink, .. } = harness_with(
        30,
        MemorySink {
            allow_delay: Duration::from_millis(300),
            ..MemorySink::default()
        },
    );
    let outcome = call(&gateway, Some(TOKEN), "vikunja__create_task").await;
    assert!(matches!(outcome, CallOutcome::Waiting(_)), "{outcome:?}");
    until_records(&sink, 3).await;

    // Both calls read the done gate, and both are allowed, before either
    // collects. The approval runs one call and gives one result.
    let identical = |gateway: SharedGateway| {
        tokio::spawn(async move { call(&gateway, Some(TOKEN), "vikunja__create_task").await })
    };
    let first = identical(gateway.clone());
    let second = identical(gateway.clone());
    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    let collected = outcomes
        .iter()
        .filter(
            |outcome| matches!(outcome, CallOutcome::Ran(result) if result.content == ["created"]),
        )
        .count();
    let spent = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, CallOutcome::Failed(CallFault::ApprovalSpent)))
        .count();
    assert_eq!((collected, spent), (1, 1), "{outcomes:?}");
    let events = sink.events();
    let count = |event: fn(&AuditEvent) -> bool| events.iter().filter(|e| event(e)).count();
    assert_eq!(
        count(|e| matches!(e, AuditEvent::Ran { .. })),
        1,
        "{events:?}"
    );
    assert_eq!(
        count(|e| matches!(e, AuditEvent::Delivered(_))),
        1,
        "{events:?}"
    );
}

#[tokio::test]
async fn a_denied_gate_fails_the_call_and_holds() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__delete_task").await;
    assert!(matches!(outcome, CallOutcome::Waiting(_)), "{outcome:?}");
    until_records(&sink, 3).await;
    assert_eq!(
        sink.events()[2],
        AuditEvent::Failed(CallFault::ApprovalDenied)
    );

    let again = call(&gateway, Some(TOKEN), "vikunja__delete_task").await;
    assert!(matches!(
        again,
        CallOutcome::Denied(DenyReason::ApprovalDenied)
    ));
    assert_eq!(
        sink.events()[3],
        AuditEvent::Decided(AuditDecision::Deny("approval_denied"))
    );
}

#[tokio::test]
async fn an_answer_that_is_no_answer_faults_the_gate_and_holds() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__odd_task").await;
    assert!(matches!(outcome, CallOutcome::Waiting(_)), "{outcome:?}");
    until_records(&sink, 3).await;
    assert_eq!(
        sink.events()[2],
        AuditEvent::Failed(CallFault::ApprovalFault)
    );
    let again = call(&gateway, Some(TOKEN), "vikunja__odd_task").await;
    assert!(matches!(
        again,
        CallOutcome::Denied(DenyReason::ApprovalDenied)
    ));
}

#[tokio::test]
async fn an_identical_call_while_pending_waits_and_asks_once() {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), 30);
    let sink = Arc::new(MemorySink::default());
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        RUN,
        loaded.policy,
        Plugins {
            identity: loaded.identity,
            audit: Arc::clone(&sink) as Arc<dyn AuditSink>,
            clock: Box::new(FixedClock(Mutex::new(START))),
            upstreams: upstreams(),
            approval: ApprovalChannel::new(Box::new(FakeApproval {
                wait: Duration::from_millis(300),
            })),
            redactor: Redactor::new(secrets()),
        },
        Bounds::DEFAULT,
    ));
    let first = call(&gateway, Some(TOKEN), "vikunja__wait_task").await;
    let CallOutcome::Waiting(gate) = first else {
        panic!("{first:?}");
    };
    let second = call(&gateway, Some(TOKEN), "vikunja__wait_task").await;
    assert!(matches!(second, CallOutcome::Waiting(g) if g == gate));
    assert_eq!(sink.events().len(), 4, "{:?}", sink.events());

    // The approval comes, the call runs once, and a later call collects it.
    until_records(&sink, 5).await;
    assert_eq!(sink.events()[4], AuditEvent::Ran { is_error: false });
    let collected = call(&gateway, Some(TOKEN), "vikunja__wait_task").await;
    let CallOutcome::Ran(result) = collected else {
        panic!("{collected:?}");
    };
    assert_eq!(result.content, ["waited"]);
    assert_eq!(sink.events()[6], AuditEvent::Delivered(gate));
}

#[tokio::test]
async fn a_name_that_is_not_exposed_fails_before_a_decision() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "not.a.tool").await;
    assert!(matches!(
        outcome,
        CallOutcome::Failed(CallFault::UnknownTool)
    ));
    assert_eq!(sink.events(), [AuditEvent::Failed(CallFault::UnknownTool)]);
    assert_eq!(sink.records()[0].tool().as_str(), AuditTool::UNKNOWN);
}

#[tokio::test]
async fn unknown_credentials_are_denied_and_see_no_tools() {
    let Harness { gateway, sink, .. } = harness(30);
    for token in [Some(OTHER_TOKEN), Some("not-a-token"), None] {
        let outcome = call(&gateway, token, "vikunja__list_tasks").await;
        assert!(
            matches!(outcome, CallOutcome::Denied(DenyReason::UnknownCredential)),
            "{token:?}: {outcome:?}"
        );
    }
    let records = sink.records();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| record.app().is_none()));

    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: None,
        headers: &headers,
    };
    assert_eq!(
        gateway.list_tools(&credentials).await,
        Err(ListError::UnknownCredential)
    );
}

#[tokio::test]
async fn a_known_caller_sees_the_granted_tools_the_upstream_lists() {
    let Harness { gateway, .. } = harness(30);
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    let names: Vec<String> = gateway
        .list_tools(&credentials)
        .await
        .unwrap()
        .into_iter()
        .map(|tool| tool.name.as_str().to_owned())
        .collect();
    // `secret_echo` is listed by the upstream and granted to nobody.
    assert_eq!(
        names,
        [
            "vikunja__big",
            "vikunja__broken",
            "vikunja__create_task",
            "vikunja__delete_task",
            "vikunja__list_tasks",
            "vikunja__odd_task",
            "vikunja__picture",
            "vikunja__slow",
            "vikunja__wait_task",
        ]
    );
}

#[tokio::test]
async fn the_rate_limit_counts_every_call_of_the_minute() {
    let Harness {
        gateway,
        sink,
        clock,
    } = harness(2);
    assert!(matches!(
        call(&gateway, Some(TOKEN), "vikunja__list_tasks").await,
        CallOutcome::Ran(_)
    ));
    assert!(matches!(
        call(&gateway, Some(TOKEN), "vikunja__delete_everything").await,
        CallOutcome::Denied(DenyReason::ToolNotGranted)
    ));
    assert!(matches!(
        call(&gateway, Some(TOKEN), "vikunja__list_tasks").await,
        CallOutcome::Denied(DenyReason::RateLimited)
    ));

    clock.set(START.checked_add(Duration::from_secs(60)).unwrap());
    assert!(matches!(
        call(&gateway, Some(TOKEN), "vikunja__list_tasks").await,
        CallOutcome::Ran(_)
    ));

    let calls: Vec<u64> = sink
        .records()
        .iter()
        .map(|record| record.call().get())
        .collect();
    assert_eq!(calls, [1, 1, 2, 3, 4, 4]);
}

#[tokio::test]
async fn an_identity_hook_that_panics_resolves_to_nothing() {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), 30);
    let sink = Arc::new(MemorySink::default());
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        RUN,
        loaded.policy,
        Plugins {
            identity: Box::new(PanicIdentity),
            audit: Arc::clone(&sink) as Arc<dyn AuditSink>,
            clock: Box::new(FixedClock(Mutex::new(START))),
            upstreams: upstreams(),
            approval: fake_approval(),
            redactor: Redactor::new(secrets()),
        },
        Bounds::DEFAULT,
    ));
    let outcome = call(&gateway, Some(TOKEN), "vikunja__list_tasks").await;
    assert!(matches!(
        outcome,
        CallOutcome::Denied(DenyReason::UnknownCredential)
    ));
    assert_eq!(
        sink.events(),
        [AuditEvent::Decided(AuditDecision::Deny(
            "unknown_credential"
        ))]
    );
}

#[tokio::test]
async fn a_decision_that_does_not_return_fails_no_decision() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    write_manifest(
        &plugins,
        "decision/included/hang",
        r#"
            name = "hang"
            version = "1"
            kind = "decision"
            hooks = ["fence"]
        "#,
    );
    let catalog = chaperone::catalog::discover(&plugins).unwrap();
    let install =
        InstallFile::read(b"version = 1\nplugins = { hang = {}, vikunja = {} }\n").unwrap();
    let setup = chaperone_core::resolve(&install, &catalog).unwrap();
    let hang = HangFence(PluginName::try_new("hang").unwrap());
    let policy = Policy::load(policy_text(30).as_bytes(), &setup, &[&hang]).unwrap();

    let sink = Arc::new(MemorySink::default());
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        RUN,
        policy,
        Plugins {
            identity: Box::new(chaperone_plugin_bearer::BearerIdentity),
            audit: Arc::clone(&sink) as Arc<dyn AuditSink>,
            clock: Box::new(FixedClock(Mutex::new(START))),
            upstreams: upstreams(),
            approval: fake_approval(),
            redactor: Redactor::new(secrets()),
        },
        Bounds {
            decision: Duration::from_millis(100),
            ..Bounds::DEFAULT
        },
    ));
    let began = Instant::now();
    let outcome = call(&gateway, Some(TOKEN), "vikunja__list_tasks").await;
    assert!(began.elapsed() < Duration::from_secs(10));
    assert!(matches!(
        outcome,
        CallOutcome::Failed(CallFault::NoDecision)
    ));
    assert_eq!(sink.events(), [AuditEvent::Failed(CallFault::NoDecision)]);
}

#[tokio::test]
async fn a_sink_that_refuses_the_record_fails_the_call() {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), 30);
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        RUN,
        loaded.policy,
        Plugins {
            identity: loaded.identity,
            audit: Arc::new(RefusingSink),
            clock: Box::new(FixedClock(Mutex::new(START))),
            upstreams: upstreams(),
            approval: fake_approval(),
            redactor: Redactor::new(secrets()),
        },
        Bounds::DEFAULT,
    ));
    for name in ["vikunja__list_tasks", "vikunja__nope", "not.a.tool"] {
        let outcome = call(&gateway, Some(TOKEN), name).await;
        assert!(
            matches!(outcome, CallOutcome::Failed(CallFault::AuditFailed)),
            "{name}: {outcome:?}"
        );
    }
}

#[tokio::test]
async fn the_audit_file_records_each_call_and_never_the_token() {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), 30);
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        loaded.run,
        loaded.policy,
        Plugins {
            identity: loaded.identity,
            audit: loaded.audit,
            clock: Box::new(FixedClock(Mutex::new(START))),
            upstreams: upstreams(),
            approval: hanging_approval(),
            redactor: Redactor::new(secrets()),
        },
        Bounds::DEFAULT,
    ));
    call(&gateway, Some(TOKEN), "vikunja__list_tasks").await;
    call(&gateway, Some(TOKEN), "vikunja__delete_everything").await;
    call(&gateway, Some(TOKEN), "vikunja__create_task").await;
    call(&gateway, Some(TOKEN), "not.a.tool").await;
    call(&gateway, Some(OTHER_TOKEN), "vikunja__list_tasks").await;

    let audit = std::fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
    let lines: Vec<&str> = audit.lines().collect();
    assert_eq!(lines.len(), 7, "{audit}");
    assert!(
        lines[0].contains(r#""event":"decided","detail":"allow""#),
        "{}",
        lines[0]
    );
    assert!(lines[1].contains(r#""event":"ran","detail":"is_error:false""#));
    assert!(lines[2].contains(r#""detail":"deny:tool_not_granted""#));
    assert!(lines[3].contains(r#""detail":"gate:"#));
    assert!(lines[4].contains(r#""event":"waiting""#), "{}", lines[4]);
    assert!(lines[5].contains(r#""detail":"unknown_tool""#));
    assert!(lines[6].contains(r#""app":null"#) && lines[6].contains("deny:unknown_credential"));
    assert!(lines.iter().all(|line| line.contains(&loaded.run.to_hex())));
    assert!(!audit.contains(TOKEN) && !audit.contains(OTHER_TOKEN));
}

#[tokio::test]
async fn the_shared_gateway_answers_through_the_trait() {
    let Harness {
        gateway: shared,
        sink,
        ..
    } = harness(30);
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    assert_eq!(shared.list_tools(&credentials).await.unwrap().len(), 9);
    let outcome = shared
        .call_tool(&credentials, "vikunja__list_tasks", BTreeMap::new())
        .await;
    assert!(matches!(outcome, CallOutcome::Ran(_)));
    assert_eq!(
        sink.events(),
        [
            AuditEvent::Decided(AuditDecision::Allow),
            AuditEvent::Ran { is_error: false },
        ]
    );
}

/// A harness whose `vikunja` upstream is not running.
fn harness_without_upstreams() -> Harness {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), 30);
    let sink = Arc::new(MemorySink::default());
    let clock = Arc::new(FixedClock(Mutex::new(START)));
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        RUN,
        loaded.policy,
        Plugins {
            identity: loaded.identity,
            audit: Arc::clone(&sink) as Arc<dyn AuditSink>,
            clock: Box::new(SharedClock(Arc::clone(&clock))),
            upstreams: Upstreams::new(),
            approval: fake_approval(),
            redactor: Redactor::new(secrets()),
        },
        Bounds::DEFAULT,
    ));
    Harness {
        gateway,
        sink,
        clock,
    }
}

#[tokio::test]
async fn an_allowed_call_without_its_upstream_fails_not_connected() {
    let Harness { gateway, sink, .. } = harness_without_upstreams();
    let outcome = call(&gateway, Some(TOKEN), "vikunja__list_tasks").await;
    assert!(matches!(
        outcome,
        CallOutcome::Failed(CallFault::NotConnected)
    ));
    assert_eq!(
        sink.events(),
        [
            AuditEvent::Decided(AuditDecision::Allow),
            AuditEvent::Failed(CallFault::NotConnected),
        ]
    );
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    assert_eq!(gateway.list_tools(&credentials).await, Ok(Vec::new()));
}

#[tokio::test]
async fn a_result_with_a_block_that_is_not_text_fails_bad_result() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__picture").await;
    assert!(matches!(outcome, CallOutcome::Failed(CallFault::BadResult)));
    assert_eq!(
        sink.events(),
        [
            AuditEvent::Decided(AuditDecision::Allow),
            AuditEvent::Failed(CallFault::BadResult),
        ]
    );
}

#[tokio::test]
async fn a_result_over_the_cap_fails_bad_result() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__big").await;
    assert!(matches!(outcome, CallOutcome::Failed(CallFault::BadResult)));
    assert_eq!(sink.events()[1], AuditEvent::Failed(CallFault::BadResult));
}

#[tokio::test]
async fn an_error_result_runs_with_the_error_flag() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__broken").await;
    let CallOutcome::Ran(result) = outcome else {
        panic!("{outcome:?}");
    };
    assert!(result.is_error);
    assert_eq!(result.content, ["boom"]);
    assert_eq!(sink.events()[1], AuditEvent::Ran { is_error: true });
}

/// A gateway over the fixture policy with `timeout_s` on the `vikunja`
/// grant, and its memory sink.
fn bounded(root: &std::path::Path, seconds: u64) -> (SharedGateway, Arc<MemorySink>) {
    let policy = policy_text(30).replace(
        "[apps.librechat.grants.vikunja.tools]",
        &format!(
            "[apps.librechat.grants.vikunja]\ntimeout_s = {seconds}\n\n[apps.librechat.grants.vikunja.tools]"
        ),
    );
    gateway_over(root, &policy)
}

/// A gateway over `policy`, the fake upstream and an approval channel
/// that answers at once, and its memory sink.
fn gateway_over(root: &std::path::Path, policy: &str) -> (SharedGateway, Arc<MemorySink>) {
    let plugins = plugin_tree(root);
    let config = config_dir(root, INSTALL, policy);
    let secret_files = secrets_dir(root);
    let audit_file = root.join("audit.jsonl");
    let loaded = startup::load(&config, &plugins, &audit_file, &secret_files).unwrap();
    let sink = Arc::new(MemorySink::default());
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        RUN,
        loaded.policy,
        Plugins {
            identity: loaded.identity,
            audit: Arc::clone(&sink) as Arc<dyn AuditSink>,
            clock: Box::new(FixedClock(Mutex::new(START))),
            upstreams: upstreams(),
            approval: fake_approval(),
            redactor: Redactor::new(secrets()),
        },
        Bounds::DEFAULT,
    ));
    (gateway, sink)
}

#[tokio::test]
async fn the_bound_of_the_upstream_grant_ends_a_slow_call() {
    let (short_root, long_root) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (short, short_sink) = bounded(short_root.path(), 1);
    let (long, long_sink) = bounded(long_root.path(), 2);
    let began = Instant::now();
    let timed = async {
        let outcome = call(&short, Some(TOKEN), "vikunja__slow").await;
        (outcome, began.elapsed())
    };
    let ((short_outcome, short_took), long_outcome) =
        tokio::join!(timed, call(&long, Some(TOKEN), "vikunja__slow"));
    assert!(began.elapsed() < Duration::from_secs(3));

    assert!(matches!(
        short_outcome,
        CallOutcome::Failed(CallFault::UpstreamTimeout)
    ));
    assert!(
        short_took >= Duration::from_secs(1) && short_took < SLOW,
        "{short_took:?}"
    );
    assert_eq!(
        short_sink.events(),
        [
            AuditEvent::Decided(AuditDecision::Allow),
            AuditEvent::Failed(CallFault::UpstreamTimeout),
        ]
    );

    let CallOutcome::Ran(result) = long_outcome else {
        panic!("{long_outcome:?}");
    };
    assert_eq!(result.content, ["late"]);
    assert_eq!(long_sink.events()[1], AuditEvent::Ran { is_error: false });
}

/// A gateway over the fixture policy with `max_inflight` on the `vikunja`
/// grant, and its memory sink. `gated` lists the tools that need an
/// approval besides those of the fixture.
fn limited(
    root: &std::path::Path,
    max_inflight: u32,
    gated: &[&str],
) -> (SharedGateway, Arc<MemorySink>) {
    let mut policy = policy_text(30).replace(
        "[apps.librechat.grants.vikunja.tools]",
        &format!(
            "[apps.librechat.grants.vikunja]\nmax_inflight = {max_inflight}\n\n[apps.librechat.grants.vikunja.tools]"
        ),
    );
    for tool in gated {
        policy = policy.replace(
            &format!("{tool} = {{}}"),
            &format!("{tool} = {{ approval = \"required\" }}"),
        );
    }
    gateway_over(root, &policy)
}

#[tokio::test]
async fn a_third_call_in_flight_under_a_limit_of_two_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let (gateway, sink) = limited(root.path(), 2, &[]);
    let slow = |gateway: SharedGateway| {
        tokio::spawn(async move { call(&gateway, Some(TOKEN), "vikunja__slow").await })
    };
    let first = slow(gateway.clone());
    let second = slow(gateway.clone());
    until_records(&sink, 2).await;

    // Two slow calls run. A third call to the upstream is denied, the slow
    // tool and a fast one alike.
    for tool in ["vikunja__slow", "vikunja__list_tasks"] {
        let third = call(&gateway, Some(TOKEN), tool).await;
        assert!(
            matches!(third, CallOutcome::Denied(DenyReason::RateLimited)),
            "{tool}: {third:?}"
        );
    }

    let first = first.await.unwrap();
    let CallOutcome::Ran(result) = first else {
        panic!("{first:?}");
    };
    assert_eq!(result.content, ["late"]);

    // One call ended, so the next call runs.
    let next = call(&gateway, Some(TOKEN), "vikunja__list_tasks").await;
    assert!(matches!(next, CallOutcome::Ran(_)), "{next:?}");
    let second = second.await.unwrap();
    assert!(matches!(second, CallOutcome::Ran(_)), "{second:?}");
}

#[tokio::test]
async fn an_approved_gated_call_counts_while_it_runs() {
    let root = tempfile::tempdir().unwrap();
    let (gateway, sink) = limited(root.path(), 1, &["slow"]);
    let waiting = call(&gateway, Some(TOKEN), "vikunja__slow").await;
    assert!(matches!(waiting, CallOutcome::Waiting(_)), "{waiting:?}");
    // The approval channel answers at once. The slow tool then runs for
    // longer than this wait.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(sink.records().len(), 2);

    let blocked = call(&gateway, Some(TOKEN), "vikunja__list_tasks").await;
    assert!(
        matches!(blocked, CallOutcome::Denied(DenyReason::RateLimited)),
        "{blocked:?}"
    );

    until_records(&sink, 4).await;
    let after = call(&gateway, Some(TOKEN), "vikunja__list_tasks").await;
    assert!(matches!(after, CallOutcome::Ran(_)), "{after:?}");
}

#[tokio::test]
async fn an_identical_call_waits_while_its_gate_runs() {
    let root = tempfile::tempdir().unwrap();
    let (gateway, sink) = limited(root.path(), 1, &["slow"]);
    let waiting = call(&gateway, Some(TOKEN), "vikunja__slow").await;
    let CallOutcome::Waiting(gate) = waiting else {
        panic!("{waiting:?}");
    };
    // The approval channel answers at once. The slow tool then runs, and
    // holds the only slot, for longer than this wait.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(sink.records().len(), 2);

    // An identical call sees the waiting text of the same gate.
    let again = call(&gateway, Some(TOKEN), "vikunja__slow").await;
    assert!(
        matches!(again, CallOutcome::Waiting(found) if found == gate),
        "{again:?}"
    );

    // After the run, an identical call collects the kept result.
    until_records(&sink, 5).await;
    assert!(sink.events().contains(&AuditEvent::Ran { is_error: false }));
    let collected = call(&gateway, Some(TOKEN), "vikunja__slow").await;
    let CallOutcome::Ran(result) = collected else {
        panic!("{collected:?}");
    };
    assert_eq!(result.content, ["late"]);
}
