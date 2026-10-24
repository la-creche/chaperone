//! The call path end to end, without a front door: each outcome of
//! `docs/design.md` 5.4 that build step 3 can reach, and its audit records.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chaperone::gateway::{ChaperoneGateway, DECISION_BUDGET, SharedGateway};
use chaperone::startup;
use chaperone_core::{
    AppId, AuditDecision, AuditError, AuditEvent, AuditRecord, AuditSink, AuditTool, Bearer,
    CallFault, CallNumber, CallOutcome, Caller, Clock, Credentials, DenyReason, Fence,
    FenceVerdict, Gateway, Identity, InstallFile, ListError, PluginName, Policy, PreparedFence,
    RawSection, RunId, SectionError, Timestamp, ToolCall,
};
use support::{INSTALL, TOKEN, config_dir, plugin_tree, policy_text, secrets_dir, write_manifest};

const RUN: RunId = RunId::from_bytes([9; 16]);
const START: Timestamp = Timestamp::from_unix_millis(1_761_264_000_000);
const OTHER_TOKEN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// A sink that keeps each record for the test.
#[derive(Debug, Default)]
struct MemorySink(Mutex<Vec<AuditRecord>>);

impl MemorySink {
    fn records(&self) -> Vec<AuditRecord> {
        self.0.lock().unwrap().clone()
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
        self.0.lock().unwrap().push(record.clone());
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
    fn name(&self) -> &PluginName {
        &self.0
    }

    fn prepare(&self, _: Option<RawSection<'_>>) -> Result<Box<dyn PreparedFence>, SectionError> {
        Ok(Box::new(PreparedHang))
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

struct Harness {
    gateway: ChaperoneGateway,
    sink: Arc<MemorySink>,
    clock: Arc<FixedClock>,
}

/// A gateway over the fixture policy, a memory sink and a fixed clock.
fn harness(calls_per_minute: u32) -> Harness {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), calls_per_minute);
    let sink = Arc::new(MemorySink::default());
    let clock = Arc::new(FixedClock(Mutex::new(START)));
    let gateway = ChaperoneGateway::new(
        RUN,
        loaded.policy,
        loaded.identity,
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        Box::new(SharedClock(Arc::clone(&clock))),
        DECISION_BUDGET,
    );
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
fn call(gateway: &ChaperoneGateway, token: Option<&str>, name: &str) -> CallOutcome {
    let bearer = token.map(|token| Bearer::new(token.to_owned()));
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: bearer.as_ref(),
        headers: &headers,
    };
    gateway.call_tool(&credentials, name, BTreeMap::new())
}

fn app(text: &str) -> AppId {
    AppId::try_new(text).unwrap()
}

#[test]
fn an_allowed_call_fails_not_connected_after_two_records() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__list_tasks");
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
    let record = &sink.records()[0];
    assert_eq!(record.run(), RUN);
    assert_eq!(record.call(), CallNumber::FIRST);
    assert_eq!(record.started_at(), START);
    assert_eq!(record.app(), Some(&app("librechat")));
    assert_eq!(record.tool().as_str(), "vikunja__list_tasks");
}

#[test]
fn a_tool_without_a_grant_is_denied_with_one_record() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__delete_everything");
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

#[test]
fn a_gated_call_fails_no_approval_channel_after_two_records() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "vikunja__create_task");
    assert!(matches!(
        outcome,
        CallOutcome::Failed(CallFault::NoApprovalChannel)
    ));
    let events = sink.events();
    assert!(matches!(
        events[0],
        AuditEvent::Decided(AuditDecision::Gate(_))
    ));
    assert_eq!(events[1], AuditEvent::Failed(CallFault::NoApprovalChannel));
    assert_eq!(events.len(), 2);
}

#[test]
fn a_name_that_is_not_exposed_fails_before_a_decision() {
    let Harness { gateway, sink, .. } = harness(30);
    let outcome = call(&gateway, Some(TOKEN), "not.a.tool");
    assert!(matches!(
        outcome,
        CallOutcome::Failed(CallFault::UnknownTool)
    ));
    assert_eq!(sink.events(), [AuditEvent::Failed(CallFault::UnknownTool)]);
    assert_eq!(sink.records()[0].tool().as_str(), AuditTool::UNKNOWN);
}

#[test]
fn unknown_credentials_are_denied_and_see_no_tools() {
    let Harness { gateway, sink, .. } = harness(30);
    for token in [Some(OTHER_TOKEN), Some("not-a-token"), None] {
        let outcome = call(&gateway, token, "vikunja__list_tasks");
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
        gateway.list_tools(&credentials),
        Err(ListError::UnknownCredential)
    );
}

#[test]
fn a_known_caller_sees_an_empty_tool_list_in_step_3() {
    let Harness { gateway, .. } = harness(30);
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    assert_eq!(gateway.list_tools(&credentials), Ok(Vec::new()));
}

#[test]
fn the_rate_limit_counts_every_call_of_the_minute() {
    let Harness {
        gateway,
        sink,
        clock,
    } = harness(2);
    assert!(matches!(
        call(&gateway, Some(TOKEN), "vikunja__list_tasks"),
        CallOutcome::Failed(CallFault::NotConnected)
    ));
    assert!(matches!(
        call(&gateway, Some(TOKEN), "vikunja__delete_everything"),
        CallOutcome::Denied(DenyReason::ToolNotGranted)
    ));
    assert!(matches!(
        call(&gateway, Some(TOKEN), "vikunja__list_tasks"),
        CallOutcome::Denied(DenyReason::RateLimited)
    ));

    clock.set(START.checked_add(Duration::from_secs(60)).unwrap());
    assert!(matches!(
        call(&gateway, Some(TOKEN), "vikunja__list_tasks"),
        CallOutcome::Failed(CallFault::NotConnected)
    ));

    let calls: Vec<u64> = sink
        .records()
        .iter()
        .map(|record| record.call().get())
        .collect();
    assert_eq!(calls, [1, 1, 2, 3, 4, 4]);
}

#[test]
fn an_identity_hook_that_panics_resolves_to_nothing() {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), 30);
    let sink = Arc::new(MemorySink::default());
    let gateway = ChaperoneGateway::new(
        RUN,
        loaded.policy,
        Box::new(PanicIdentity),
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        Box::new(FixedClock(Mutex::new(START))),
        DECISION_BUDGET,
    );
    let outcome = call(&gateway, Some(TOKEN), "vikunja__list_tasks");
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

#[test]
fn a_decision_that_does_not_return_fails_no_decision() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    write_manifest(
        &plugins,
        "decision/included/hang",
        r#"{"name":"hang","version":"1","kind":"decision","hooks":["fence"]}"#,
    );
    let catalog = chaperone::catalog::discover(&plugins).unwrap();
    let install =
        InstallFile::read(br#"{"version":1,"plugins":{"hang":{},"vikunja":{}}}"#).unwrap();
    let setup = chaperone_core::resolve(&install, &catalog).unwrap();
    let hang = HangFence(PluginName::try_new("hang").unwrap());
    let policy = Policy::load(policy_text(30).as_bytes(), &setup, &[&hang]).unwrap();

    let sink = Arc::new(MemorySink::default());
    let gateway = ChaperoneGateway::new(
        RUN,
        policy,
        Box::new(chaperone_plugin_bearer::BearerIdentity),
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        Box::new(FixedClock(Mutex::new(START))),
        Duration::from_millis(100),
    );
    let began = Instant::now();
    let outcome = call(&gateway, Some(TOKEN), "vikunja__list_tasks");
    assert!(began.elapsed() < Duration::from_secs(10));
    assert!(matches!(
        outcome,
        CallOutcome::Failed(CallFault::NoDecision)
    ));
    assert_eq!(sink.events(), [AuditEvent::Failed(CallFault::NoDecision)]);
}

#[test]
fn a_sink_that_refuses_the_record_fails_the_call() {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), 30);
    let gateway = ChaperoneGateway::new(
        RUN,
        loaded.policy,
        loaded.identity,
        Arc::new(RefusingSink),
        Box::new(FixedClock(Mutex::new(START))),
        DECISION_BUDGET,
    );
    for name in ["vikunja__list_tasks", "vikunja__nope", "not.a.tool"] {
        let outcome = call(&gateway, Some(TOKEN), name);
        assert!(
            matches!(outcome, CallOutcome::Failed(CallFault::AuditFailed)),
            "{name}: {outcome:?}"
        );
    }
}

#[test]
fn the_audit_file_records_each_call_and_never_the_token() {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded(root.path(), 30);
    let gateway = ChaperoneGateway::new(
        loaded.run,
        loaded.policy,
        loaded.identity,
        loaded.audit,
        Box::new(FixedClock(Mutex::new(START))),
        DECISION_BUDGET,
    );
    call(&gateway, Some(TOKEN), "vikunja__list_tasks");
    call(&gateway, Some(TOKEN), "vikunja__delete_everything");
    call(&gateway, Some(TOKEN), "vikunja__create_task");
    call(&gateway, Some(TOKEN), "not.a.tool");
    call(&gateway, Some(OTHER_TOKEN), "vikunja__list_tasks");

    let audit = std::fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
    let lines: Vec<&str> = audit.lines().collect();
    assert_eq!(lines.len(), 7, "{audit}");
    assert!(
        lines[0].contains(r#""event":"decided","detail":"allow""#),
        "{}",
        lines[0]
    );
    assert!(lines[1].contains(r#""event":"failed","detail":"not_connected""#));
    assert!(lines[2].contains(r#""detail":"deny:tool_not_granted""#));
    assert!(lines[3].contains(r#""detail":"gate:"#));
    assert!(lines[4].contains(r#""detail":"no_approval_channel""#));
    assert!(lines[5].contains(r#""detail":"unknown_tool""#));
    assert!(lines[6].contains(r#""app":null"#) && lines[6].contains("deny:unknown_credential"));
    assert!(lines.iter().all(|line| line.contains(&loaded.run.to_hex())));
    assert!(!audit.contains(TOKEN) && !audit.contains(OTHER_TOKEN));
}

#[tokio::test]
async fn the_shared_gateway_answers_through_the_trait() {
    let Harness { gateway, sink, .. } = harness(30);
    let shared = SharedGateway::new(gateway);
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    assert_eq!(shared.list_tools(&credentials).await, Ok(Vec::new()));
    let outcome = shared
        .call_tool(&credentials, "vikunja__list_tasks", BTreeMap::new())
        .await;
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
}
