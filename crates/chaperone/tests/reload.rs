//! The policy file reloads when it changes (`docs/design.md` 6). A file
//! that the strict reader refuses denies every call until a valid file
//! loads (G2).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chaperone::effect::{Redactor, Upstreams};
use chaperone::gateway::{Bounds, ChaperoneGateway, Plugins, SharedGateway};
use chaperone::reload::PolicyFile;
use chaperone::startup;
use chaperone_core::{
    AuditDecision, AuditError, AuditEvent, AuditRecord, AuditSink, Bearer, CallOutcome,
    Credentials, DenyReason, Gateway, ListError, RunId,
};
use support::{INSTALL, TOKEN, config_dir, digest, fake_approval, plugin_tree, secrets_dir};

/// A sink that keeps each record for the test.
#[derive(Debug, Default)]
struct MemorySink(Mutex<Vec<AuditRecord>>);

impl AuditSink for MemorySink {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.0.lock().unwrap().push(record.clone());
        Ok(())
    }
}

impl MemorySink {
    fn last(&self) -> AuditEvent {
        self.0.lock().unwrap().last().unwrap().event().clone()
    }
}

/// A policy that grants the one tool `tool` of `vikunja` to `librechat`.
fn policy_granting(tool: &str) -> String {
    let digest = digest(TOKEN);
    format!(
        r#"
        version = 1

        [apps.librechat]
        token_sha256 = ["{digest}"]
        limits = {{ calls_per_minute = 30, max_pending_gates = 1 }}

        [apps.librechat.grants.vikunja.tools]
        {tool} = {{}}
        "#
    )
}

/// Write `text` next to `policy.toml` and rename it over the file, as an
/// external tool lands a new policy file.
fn replace(config: &Path, text: &str) {
    let staged = config.join("policy.toml.new");
    std::fs::write(&staged, text).unwrap();
    std::fs::rename(&staged, config.join("policy.toml")).unwrap();
}

struct Harness {
    _root: tempfile::TempDir,
    config: std::path::PathBuf,
    gateway: SharedGateway,
    sink: Arc<MemorySink>,
}

/// A gateway that watches the policy file of a configuration directory.
/// No upstream runs, so an allowed call fails with `not_connected`.
fn harness(policy: &str) -> Harness {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, policy);
    let secrets = secrets_dir(root.path());
    let audit = root.path().join("audit.jsonl");
    let loaded = startup::load(&config, &plugins, &audit, &secrets).unwrap();
    let policy = PolicyFile::new(&config, loaded.setup, loaded.policy, loaded.policy_stamp);
    let sink = Arc::new(MemorySink::default());
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        RunId::from_bytes([3; 16]),
        policy,
        Plugins {
            identity: loaded.identity,
            audit: Arc::clone(&sink) as Arc<dyn AuditSink>,
            clock: loaded.clock,
            upstreams: Upstreams::new(),
            approval: fake_approval(),
            redactor: Redactor::new(BTreeMap::new()),
        },
        Bounds::DEFAULT,
    ));
    Harness {
        _root: root,
        config,
        gateway,
        sink,
    }
}

async fn call(gateway: &SharedGateway, name: &str) -> CallOutcome {
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    gateway.call_tool(&credentials, name, BTreeMap::new()).await
}

async fn list(gateway: &SharedGateway) -> Result<usize, ListError> {
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    gateway
        .list_tools(&credentials)
        .await
        .map(|tools| tools.len())
}

/// A call that the policy allows reaches the upstream step. No upstream
/// runs here, so it fails there.
fn allowed(outcome: &CallOutcome) -> bool {
    matches!(
        outcome,
        CallOutcome::Failed(chaperone_core::CallFault::NotConnected)
    )
}

#[tokio::test]
async fn the_next_call_after_a_replacement_is_decided_under_the_new_file() {
    let Harness {
        _root,
        config,
        gateway,
        sink,
    } = harness(&policy_granting("list_tasks"));
    let first = call(&gateway, "vikunja__list_tasks").await;
    assert!(allowed(&first), "{first:?}");

    replace(&config, &policy_granting("create_task"));
    let second = call(&gateway, "vikunja__list_tasks").await;
    assert!(
        matches!(second, CallOutcome::Denied(DenyReason::ToolNotGranted)),
        "{second:?}"
    );
    assert_eq!(
        sink.last(),
        AuditEvent::Decided(AuditDecision::Deny("tool_not_granted"))
    );
    let third = call(&gateway, "vikunja__create_task").await;
    assert!(allowed(&third), "{third:?}");
}

#[tokio::test]
async fn a_refused_file_denies_every_call_until_a_valid_file_loads() {
    let Harness {
        _root,
        config,
        gateway,
        sink,
    } = harness(&policy_granting("list_tasks"));
    replace(&config, "version = 1\n[apps.librechat\n");
    let refused = call(&gateway, "vikunja__list_tasks").await;
    assert!(
        matches!(refused, CallOutcome::Denied(DenyReason::PolicyNotLoaded)),
        "{refused:?}"
    );
    assert_eq!(
        sink.last(),
        AuditEvent::Decided(AuditDecision::Deny("policy_not_loaded"))
    );
    assert_eq!(list(&gateway).await, Err(ListError::PolicyNotLoaded));
    let again = call(&gateway, "vikunja__list_tasks").await;
    assert!(
        matches!(again, CallOutcome::Denied(DenyReason::PolicyNotLoaded)),
        "{again:?}"
    );

    replace(&config, &policy_granting("list_tasks"));
    let restored = call(&gateway, "vikunja__list_tasks").await;
    assert!(allowed(&restored), "{restored:?}");
    assert_eq!(list(&gateway).await, Ok(0));
}

#[tokio::test]
async fn a_removed_file_denies_every_call() {
    let Harness {
        _root,
        config,
        gateway,
        ..
    } = harness(&policy_granting("list_tasks"));
    std::fs::remove_file(config.join("policy.toml")).unwrap();
    let outcome = call(&gateway, "vikunja__list_tasks").await;
    assert!(
        matches!(outcome, CallOutcome::Denied(DenyReason::PolicyNotLoaded)),
        "{outcome:?}"
    );
}
