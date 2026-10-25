//! `GET /healthz` on the front door and `chaperone verify`
//! (`docs/design.md` 7.6 and 10).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use chaperone::effect::{Redactor, Upstreams};
use chaperone::gateway::{Bounds, ChaperoneGateway, Plugins, SharedGateway};
use chaperone::reload::PolicyFile;
use chaperone::{startup, verify};
use support::{INSTALL, config_dir, hanging_approval, plugin_tree, policy_text, secrets_dir};
use tokio_util::sync::CancellationToken;

/// A front door over a watched policy file, on a free loopback port.
struct Served {
    address: SocketAddr,
    config: PathBuf,
    plugins: PathBuf,
    shutdown: CancellationToken,
    _root: tempfile::TempDir,
}

async fn serve() -> Served {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let audit = root.path().join("audit.jsonl");
    let secrets = secrets_dir(root.path());
    let loaded = startup::load(&config, &plugins, &audit, &secrets).unwrap();
    let policy = PolicyFile::new(&config, loaded.setup, loaded.policy, loaded.policy_stamp);
    let gateway = Arc::new(SharedGateway::new(ChaperoneGateway::new(
        loaded.run,
        policy,
        Plugins {
            identity: loaded.identity,
            audit: loaded.audit,
            clock: loaded.clock,
            upstreams: Upstreams::new(),
            approval: hanging_approval(),
            redactor: Redactor::new(loaded.secrets),
        },
        Bounds::DEFAULT,
    )));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    tokio::spawn(chaperone_plugin_mcp_http::serve(
        gateway,
        listener,
        vec!["127.0.0.1".to_owned()],
        shutdown.clone(),
    ));
    Served {
        address,
        config,
        plugins,
        shutdown,
        _root: root,
    }
}

/// One raw `GET /healthz`. Returns the whole answer.
async fn get_healthz(address: SocketAddr) -> String {
    tokio::task::spawn_blocking(move || {
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        answer
    })
    .await
    .unwrap()
}

/// Write a policy file that the strict reader refuses.
fn break_policy(config: &std::path::Path) {
    let staged = config.join("policy.toml.new");
    std::fs::write(&staged, "version = 1\n[apps.librechat\n").unwrap();
    std::fs::rename(&staged, config.join("policy.toml")).unwrap();
}

#[tokio::test]
async fn healthz_answers_200_with_a_policy_and_503_without_one() {
    let served = serve().await;
    let answer = get_healthz(served.address).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with(r#"{"ok":true}"#), "{answer}");

    break_policy(&served.config);
    let answer = get_healthz(served.address).await;
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
    assert!(answer.ends_with(r#"{"ok":false}"#), "{answer}");
    served.shutdown.cancel();
}

#[tokio::test]
async fn verify_passes_a_healthy_service_and_fails_a_refused_policy() {
    let served = serve().await;
    let (config, plugins, address) = (
        served.config.clone(),
        served.plugins.clone(),
        served.address,
    );
    let report = tokio::task::spawn_blocking(move || verify::run(&config, &plugins, address))
        .await
        .unwrap();
    assert!(report.passed(), "{}", report.lines());

    break_policy(&served.config);
    let (config, plugins) = (served.config.clone(), served.plugins.clone());
    let report = tokio::task::spawn_blocking(move || verify::run(&config, &plugins, address))
        .await
        .unwrap();
    assert!(!report.passed());
    let lines = report.lines();
    assert!(lines.contains("PASS install.toml"), "{lines}");
    assert!(lines.contains("FAIL policy.toml"), "{lines}");
    assert!(lines.contains("FAIL healthz"), "{lines}");
    served.shutdown.cancel();
}

#[test]
fn the_cli_exits_1_with_a_json_report_when_nothing_answers() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = unused.local_addr().unwrap();
    drop(unused);

    let output = Command::new(env!("CARGO_BIN_EXE_chaperone"))
        .arg("verify")
        .arg("--json")
        .arg("--config-dir")
        .arg(&config)
        .arg("--plugins-dir")
        .arg(&plugins)
        .arg("--listen")
        .arg(address.to_string())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    let checks = report["checks"].as_array().unwrap();
    let names: Vec<&str> = checks
        .iter()
        .map(|check| check["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["install.toml", "policy.toml", "healthz"]);
    assert_eq!(checks[0]["ok"], true);
    assert_eq!(checks[2]["ok"], false);
}
