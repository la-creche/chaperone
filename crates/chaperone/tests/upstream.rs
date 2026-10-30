//! The effect host with a real child process: the fake upstream of
//! `src/bin/fake_upstream.rs`. It covers the launch, the secret line on
//! stdin, the env exception, the tool list and a call through the gateway
//! (`docs/design.md` 7.5 and 7.7).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chaperone::approval::ApprovalChannel;
use chaperone::effect::{self, LaunchError, Redactor};
use chaperone::gateway::{Bounds, ChaperoneGateway, Plugins, SharedGateway};
use chaperone::registry::AuditMode;
use chaperone::startup;
use std::time::Duration;

use chaperone_core::{Bearer, CallOutcome, Credentials, Gateway, SecretDelivery};
use support::{
    TOKEN, config_dir, plugin_tree, policy_text, secrets_dir, write_manifest, write_secret,
};

/// The fake upstream binary of `src/bin/fake_upstream.rs`, as Cargo built
/// it for this test run.
fn fake_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fake_upstream"))
}

/// The command that runs the fake with `args`, as an array of strings. A
/// JSON array of strings is also a TOML array.
fn fake_command(args: &[&str]) -> String {
    let mut command = vec![fake_binary().to_str().unwrap().to_owned()];
    command.extend(args.iter().map(|arg| (*arg).to_owned()));
    serde_json::to_string(&command).unwrap()
}

/// A `vikunja` manifest whose command runs the fake with `args`.
fn vikunja_manifest(args: &[&str]) -> String {
    let command = fake_command(args);
    format!(
        r#"
            name = "vikunja"
            version = "1"
            kind = "effect"
            hooks = ["upstream"]
            secrets = ["VIKUNJA_TOKEN"]
            command = {command}
        "#
    )
}

/// A `fake-approval` manifest for the approval channel slot.
fn approval_manifest() -> String {
    let command = fake_command(&["--fake-approval"]);
    format!(
        r#"
            name = "fake-approval"
            version = "1"
            kind = "effect"
            slot = "approval_channel"
            hooks = ["approval"]
            command = {command}
        "#
    )
}

struct Running {
    gateway: SharedGateway,
    audit_path: PathBuf,
    _root: tempfile::TempDir,
}

/// Load a tree where `vikunja` is the fake upstream, launch it and build
/// the gateway.
async fn running(args: &[&str], install: &str, bounds: Bounds) -> Result<Running, LaunchError> {
    running_with(args, install, &policy_text(30), bounds).await
}

/// As [`running`], with the policy `policy`.
async fn running_with(
    args: &[&str],
    install: &str,
    policy: &str,
    bounds: Bounds,
) -> Result<Running, LaunchError> {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    write_manifest(&plugins, "effect/added/vikunja", &vikunja_manifest(args));
    write_manifest(
        &plugins,
        "effect/included/fake-approval",
        &approval_manifest(),
    );
    let config = config_dir(root.path(), install, policy);
    let secrets = secrets_dir(root.path());
    write_secret(&secrets, "vikunja_token", "tok-123");
    let audit_path = root.path().join("audit.jsonl");
    let loaded = startup::load(
        &config,
        &plugins,
        &audit_path,
        AuditMode::OwnerOnly,
        &secrets,
    )
    .unwrap();
    let redactor = Redactor::new(loaded.secrets);
    let fake = fake_binary();
    let launched =
        effect::launch_all_with(&loaded.setup, &loaded.catalog, &redactor, Some(&fake)).await?;
    let gateway = SharedGateway::new(ChaperoneGateway::new(
        loaded.run,
        loaded.policy,
        Plugins {
            identity: loaded.identity,
            audit: loaded.audit,
            clock: loaded.clock,
            upstreams: launched.upstreams,
            approval: ApprovalChannel::new(launched.approval),
            redactor,
        },
        bounds,
    ));
    Ok(Running {
        gateway,
        audit_path,
        _root: root,
    })
}

const STDIN_INSTALL: &str = r#"
version = 1
slots.approval_channel = "fake-approval"
plugins.fake-approval = {}
plugins.vikunja.secrets.VIKUNJA_TOKEN = "vikunja_token"
"#;
const ENV_INSTALL: &str = r#"
version = 1
slots.approval_channel = "fake-approval"
plugins.fake-approval = {}
plugins.vikunja.secrets.VIKUNJA_TOKEN = "vikunja_token"
plugins.vikunja.secret_delivery = "env"
"#;

async fn list_and_call(running: &Running) {
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    let tools = running.gateway.list_tools(&credentials).await.unwrap();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_str()).collect();
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
    assert_eq!(
        tools[4].description.as_deref(),
        Some("the fake list_tasks tool")
    );
    assert!(tools[4].input_schema.contains_key("type"));

    let outcome = running
        .gateway
        .call_tool(&credentials, "vikunja__list_tasks", BTreeMap::new())
        .await;
    let CallOutcome::Ran(result) = outcome else {
        panic!("{outcome:?}");
    };
    assert!(!result.is_error);
    assert_eq!(result.content, ["two tasks for token [redacted]"]);

    let outcome = running
        .gateway
        .call_tool(&credentials, "vikunja__broken", BTreeMap::new())
        .await;
    let CallOutcome::Ran(result) = outcome else {
        panic!("{outcome:?}");
    };
    assert!(result.is_error);
}

#[tokio::test]
async fn the_fake_upstream_takes_its_secret_on_stdin_and_answers_calls() {
    let running = running(&["--fake-upstream"], STDIN_INSTALL, Bounds::DEFAULT)
        .await
        .unwrap();
    list_and_call(&running).await;
    let audit = std::fs::read_to_string(&running.audit_path).unwrap();
    assert!(
        audit.contains(r#""event":"ran","detail":"is_error:false""#),
        "{audit}"
    );
    assert!(
        audit.contains(r#""event":"ran","detail":"is_error:true""#),
        "{audit}"
    );
    assert!(!audit.contains("tok-123"));
}

#[tokio::test]
async fn an_upstream_learns_the_app_id_of_the_call_and_never_the_token() {
    // The policy table of `policy_text` ends with the vikunja tools, so
    // this line grants one more tool.
    let policy = format!("{}whoami = {{}}\n", policy_text(30));
    let running = running_with(
        &["--fake-upstream"],
        STDIN_INSTALL,
        &policy,
        Bounds::DEFAULT,
    )
    .await
    .unwrap();
    let (seen, text) = whoami(&running).await;
    assert_eq!(seen["meta"]["chaperone.app"], "librechat", "{text}");
    let ours: Vec<&String> = seen["meta"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|key| key.starts_with("chaperone"))
        .collect();
    assert_eq!(ours, ["chaperone.app"], "{text}");
    assert_eq!(seen["arguments"], serde_json::json!({"note": "hello"}));
    assert!(!text.contains(TOKEN), "{text}");
    assert!(!text.contains(&support::digest(TOKEN)), "{text}");
}

/// Call the `whoami` tool of the fake with one argument. Return what it
/// saw and its text.
async fn whoami(running: &Running) -> (serde_json::Value, String) {
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    let arguments = BTreeMap::from([(
        "note".to_owned(),
        chaperone_core::ArgValue::String("hello".to_owned()),
    )]);
    let outcome = running
        .gateway
        .call_tool(&credentials, "vikunja__whoami", arguments)
        .await;
    let CallOutcome::Ran(result) = outcome else {
        panic!("{outcome:?}");
    };
    let text = result.content.concat();
    (serde_json::from_str(&text).expect(&text), text)
}

#[tokio::test]
async fn a_plugin_with_a_user_starts_through_the_helper() {
    let install = format!(
        "{ENV_INSTALL}plugins.vikunja.user = \"mcp-vikunja\"\nplugins.vikunja.args = [\"--port\", \"1\"]\n"
    );
    let policy = format!("{}whoami = {{}}\n", policy_text(30));
    // The fake stands in for the helper, so it serves with the argv and
    // the environment that the helper gets.
    let running = running_with(
        &["--fake-upstream", "--env"],
        &install,
        &policy,
        Bounds::DEFAULT,
    )
    .await
    .unwrap();
    let (seen, text) = whoami(&running).await;
    let fake = fake_binary();
    let fake = fake.to_str().unwrap();
    let argv = [
        fake,
        "mcp-vikunja",
        fake,
        "--fake-upstream",
        "--env",
        "--port",
        "1",
    ];
    assert_eq!(seen["argv"], serde_json::json!(argv), "{text}");
    // The whole environment is the one variable, and its object holds only
    // the bound secret, blanked in the result. macOS adds `__CF_` names to
    // each process at start.
    let names: Vec<&str> = seen["env"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|name| !name.starts_with("__CF_"))
        .collect();
    assert_eq!(names, ["CHAPERONE_CHILD_ENV"], "{text}");
    let child_env = r#"{"VIKUNJA_TOKEN":"[redacted]"}"#;
    assert_eq!(seen["env"]["CHAPERONE_CHILD_ENV"], child_env, "{text}");
}

#[tokio::test]
async fn the_env_exception_hands_the_secret_in_the_environment() {
    let running = running(&["--fake-upstream", "--env"], ENV_INSTALL, Bounds::DEFAULT)
        .await
        .unwrap();
    list_and_call(&running).await;
}

/// A plugin tree with the upstream `vikunja` of `vikunja` and the
/// approval channel `fake-approval` of `approval`, each a manifest text,
/// loaded with the fixture policy. `vikunja` takes one secret.
fn loaded_with(root: &Path, vikunja: &str, approval: &str) -> startup::Loaded {
    let plugins = plugin_tree(root);
    write_manifest(&plugins, "effect/added/vikunja", vikunja);
    write_manifest(&plugins, "effect/included/fake-approval", approval);
    let install = r#"
        version = 1
        slots.approval_channel = "fake-approval"
        plugins.fake-approval = {}
        plugins.vikunja.secrets.VIKUNJA_TOKEN = "vikunja_token"
    "#;
    let config = config_dir(root, install, &policy_text(30));
    let secrets = secrets_dir(root);
    write_secret(&secrets, "vikunja_token", "tok-123");
    startup::load(
        &config,
        &plugins,
        &root.join("audit.jsonl"),
        AuditMode::OwnerOnly,
        &secrets,
    )
    .unwrap()
}

const MISSING_UPSTREAM: &str = r#"
    name = "vikunja"
    version = "1"
    kind = "effect"
    hooks = ["upstream"]
    secrets = ["VIKUNJA_TOKEN"]
    command = ["/nonexistent/chaperone-test-upstream"]
"#;

#[tokio::test]
async fn a_command_that_does_not_exist_marks_its_upstream_down() {
    let root = tempfile::tempdir().unwrap();
    let loaded = loaded_with(root.path(), MISSING_UPSTREAM, &approval_manifest());
    let redactor = Redactor::new(loaded.secrets);
    let launched = effect::launch_all(&loaded.setup, &loaded.catalog, &redactor)
        .await
        .unwrap();
    let vikunja = chaperone_core::PluginName::try_new("vikunja").unwrap();
    assert!(!launched.upstreams.contains_key(&vikunja));
    let error = launched.down.get(&vikunja).unwrap();
    assert!(matches!(error, LaunchError::Spawn { .. }), "{error}");
}

#[tokio::test]
async fn an_approval_channel_that_does_not_start_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let approval = r#"
        name = "fake-approval"
        version = "1"
        kind = "effect"
        slot = "approval_channel"
        hooks = ["approval"]
        command = ["/nonexistent/chaperone-test-approval"]
    "#;
    let loaded = loaded_with(
        root.path(),
        &vikunja_manifest(&["--fake-upstream"]),
        approval,
    );
    let redactor = Redactor::new(loaded.secrets);
    let error = effect::launch_all(&loaded.setup, &loaded.catalog, &redactor)
        .await
        .unwrap_err();
    assert!(matches!(error, LaunchError::Spawn { .. }), "{error}");
    assert!(error.to_string().contains("fake-approval"), "{error}");
}

#[tokio::test]
async fn a_plugin_that_does_not_speak_mcp_refuses_start() {
    let name = chaperone_core::PluginName::try_new("vikunja").unwrap();
    let redactor = Redactor::new(startup::Secrets::new());
    // `true` exits at once, so the initialize never completes.
    let error = effect::launch(
        &name,
        &["true".to_owned()],
        SecretDelivery::Stdin,
        &redactor,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, LaunchError::Initialize { .. }), "{error}");
}

#[test]
fn the_fake_binary_exists_and_exits_without_the_flag() {
    let status = std::process::Command::new(fake_binary()).status().unwrap();
    assert!(status.success());
    assert!(Path::new(&fake_binary()).is_absolute());
}

/// Wait until the audit file holds a line with `needle`, up to five seconds.
async fn until_audit(path: &Path, needle: &str) -> String {
    for _ in 0..250 {
        let audit = std::fs::read_to_string(path).unwrap_or_default();
        if audit.contains(needle) {
            return audit;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the audit file never held {needle:?}");
}

#[tokio::test]
async fn gates_go_through_the_approval_channel_process() {
    let running = running(&["--fake-upstream"], STDIN_INSTALL, Bounds::DEFAULT)
        .await
        .unwrap();
    let bearer = Bearer::new(TOKEN.to_owned());
    let headers = BTreeMap::new();
    let credentials = Credentials {
        bearer: Some(&bearer),
        headers: &headers,
    };
    let call = |name: &'static str| {
        running
            .gateway
            .call_tool(&credentials, name, BTreeMap::new())
    };

    // Approved on the phone: the call waits, runs, and the result is collected.
    let waiting = call("vikunja__create_task").await;
    assert!(matches!(waiting, CallOutcome::Waiting(_)), "{waiting:?}");
    until_audit(&running.audit_path, r#""event":"ran""#).await;
    let collected = call("vikunja__create_task").await;
    let CallOutcome::Ran(result) = collected else {
        panic!("{collected:?}");
    };
    assert_eq!(result.content, ["created"]);

    // Denied on the phone: the call waits, then an identical call is denied.
    let waiting = call("vikunja__delete_task").await;
    assert!(matches!(waiting, CallOutcome::Waiting(_)), "{waiting:?}");
    until_audit(&running.audit_path, r#""detail":"approval_denied""#).await;
    let denied = call("vikunja__delete_task").await;
    assert!(
        matches!(
            denied,
            CallOutcome::Denied(chaperone_core::DenyReason::ApprovalDenied)
        ),
        "{denied:?}"
    );

    // No answer of the right shape: a fault, and the gate holds.
    let waiting = call("vikunja__odd_task").await;
    assert!(matches!(waiting, CallOutcome::Waiting(_)), "{waiting:?}");
    until_audit(&running.audit_path, r#""detail":"approval_fault""#).await;

    let audit = std::fs::read_to_string(&running.audit_path).unwrap();
    assert!(audit.contains(r#""event":"waiting""#), "{audit}");
    assert!(audit.contains(r#""event":"delivered""#), "{audit}");
}

#[tokio::test]
async fn an_approval_channel_without_the_approve_tool_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    write_manifest(
        &plugins,
        "effect/added/vikunja",
        &vikunja_manifest(&["--fake-upstream"]),
    );
    // The fake upstream lists tools, and none of them is `approve`.
    let command = fake_command(&["--fake-upstream"]);
    write_manifest(
        &plugins,
        "effect/included/fake-approval",
        &format!(
            r#"
                name = "fake-approval"
                version = "1"
                kind = "effect"
                slot = "approval_channel"
                hooks = ["approval"]
                secrets = ["VIKUNJA_TOKEN"]
                command = {command}
            "#
        ),
    );
    let install = r#"
        version = 1
        slots.approval_channel = "fake-approval"
        plugins.vikunja.secrets.VIKUNJA_TOKEN = "vikunja_token"
        plugins.fake-approval.secrets.VIKUNJA_TOKEN = "vikunja_token"
    "#;
    let config = config_dir(root.path(), install, &policy_text(30));
    let secrets = secrets_dir(root.path());
    write_secret(&secrets, "vikunja_token", "tok-123");
    let loaded = startup::load(
        &config,
        &plugins,
        &root.path().join("audit.jsonl"),
        AuditMode::OwnerOnly,
        &secrets,
    )
    .unwrap();
    let redactor = Redactor::new(loaded.secrets);
    let error = effect::launch_all(&loaded.setup, &loaded.catalog, &redactor)
        .await
        .unwrap_err();
    assert!(
        matches!(error, LaunchError::NoApproveTool { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn install_args_are_appended_to_the_command() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    // The manifest names the program alone. The install file adds the flag
    // that makes it an upstream.
    let command = fake_command(&[]);
    write_manifest(
        &plugins,
        "effect/added/vikunja",
        &format!(
            r#"
                name = "vikunja"
                version = "1"
                kind = "effect"
                hooks = ["upstream"]
                secrets = ["VIKUNJA_TOKEN"]
                command = {command}
            "#
        ),
    );
    write_manifest(
        &plugins,
        "effect/included/fake-approval",
        &approval_manifest(),
    );
    let install = r#"
        version = 1
        slots.approval_channel = "fake-approval"
        plugins.fake-approval = {}
        plugins.vikunja.secrets.VIKUNJA_TOKEN = "vikunja_token"
        plugins.vikunja.args = ["--fake-upstream"]
    "#;
    let config = config_dir(root.path(), install, &policy_text(30));
    let secrets = secrets_dir(root.path());
    write_secret(&secrets, "vikunja_token", "tok-123");
    let loaded = startup::load(
        &config,
        &plugins,
        &root.path().join("audit.jsonl"),
        AuditMode::OwnerOnly,
        &secrets,
    )
    .unwrap();
    let redactor = Redactor::new(loaded.secrets);
    let launched = effect::launch_all(&loaded.setup, &loaded.catalog, &redactor)
        .await
        .unwrap();
    let vikunja = launched
        .upstreams
        .get(&chaperone_core::PluginName::try_new("vikunja").unwrap())
        .unwrap();
    assert!(
        vikunja
            .tools()
            .iter()
            .any(|tool| tool.name.as_str() == "list_tasks")
    );
}
