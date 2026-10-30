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
use chaperone::env_file::EnvKey;
use chaperone::gateway::{Bounds, ChaperoneGateway, Plugins, SharedGateway};
use chaperone::registry::AuditMode;
use chaperone::reload::PolicyFile;
use chaperone::verify::Target;
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
    serve_policy(&policy_text(30)).await
}

/// As [`serve`], with `policy` as the text of the policy file at start.
async fn serve_policy(policy: &str) -> Served {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, policy);
    let audit = root.path().join("audit.jsonl");
    let secrets = secrets_dir(root.path());
    let loaded = startup::load(&config, &plugins, &audit, AuditMode::OwnerOnly, &secrets).unwrap();
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
async fn a_start_with_no_policy_answers_503_until_a_valid_file_lands() {
    let served = serve_policy("version = 1\n[apps.librechat\n").await;
    let answer = get_healthz(served.address).await;
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");

    let staged = served.config.join("policy.toml.new");
    std::fs::write(&staged, policy_text(30)).unwrap();
    std::fs::rename(&staged, served.config.join("policy.toml")).unwrap();
    let answer = get_healthz(served.address).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
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
    let report = tokio::task::spawn_blocking(move || {
        verify::run(&config, &plugins, Target::Listen(address))
    })
    .await
    .unwrap();
    assert!(report.passed(), "{}", report.lines());

    break_policy(&served.config);
    let (config, plugins) = (served.config.clone(), served.plugins.clone());
    let report = tokio::task::spawn_blocking(move || {
        verify::run(&config, &plugins, Target::Listen(address))
    })
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

#[tokio::test]
async fn verify_reads_the_listen_address_from_an_env_file() {
    let served = serve().await;
    let env_file = served.config.join("site.env");
    let address = served.address;
    std::fs::write(
        &env_file,
        format!("# The site.\nSITE_TOKEN=s3cret-value\nCHAPERONE_LISTEN={address}\n"),
    )
    .unwrap();
    let (config, plugins) = (served.config.clone(), served.plugins.clone());
    let report = tokio::task::spawn_blocking(move || {
        let key: EnvKey = "CHAPERONE_LISTEN".parse().unwrap();
        let target = Target::EnvFile {
            path: &env_file,
            key: &key,
        };
        verify::run(&config, &plugins, target)
    })
    .await
    .unwrap();
    let lines = report.lines();
    assert!(report.passed(), "{lines}");
    assert!(lines.contains("PASS env-file"), "{lines}");
    assert!(lines.contains("PASS healthz"), "{lines}");
    // Nothing of the file is printed, the address included.
    assert!(!lines.contains(&address.to_string()), "{lines}");
    assert!(!lines.contains("s3cret"), "{lines}");
    served.shutdown.cancel();
}

/// Run `chaperone verify --json` over a fresh configuration with `args`.
fn verify_cli(args: &[&str]) -> std::process::Output {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    Command::new(env!("CARGO_BIN_EXE_chaperone"))
        .arg("verify")
        .arg("--json")
        .arg("--config-dir")
        .arg(&config)
        .arg("--plugins-dir")
        .arg(&plugins)
        .args(args)
        .output()
        .unwrap()
}

/// A free loopback address that nothing listens on.
fn unused_address() -> SocketAddr {
    let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    unused.local_addr().unwrap()
}

#[test]
fn the_cli_refuses_listen_with_env_file_and_a_key_without_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("site.env");
    std::fs::write(&env_file, "CHAPERONE_LISTEN=127.0.0.1:8300\n").unwrap();
    let env_file = env_file.to_str().unwrap();
    for args in [
        vec!["--listen", "127.0.0.1:8300", "--env-file", env_file],
        vec!["--listen-key", "PEP_BIND"],
        vec!["--env-file", env_file, "--listen-key", "pep_bind"],
    ] {
        let output = verify_cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn the_cli_takes_the_named_key_and_reports_a_bad_file_without_its_values() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("site.env");
    let address = unused_address();
    std::fs::write(
        &env_file,
        format!("PEP_BIND={address}\nSITE_TOKEN=s3cret-value\n"),
    )
    .unwrap();
    let path = env_file.to_str().unwrap();
    let output = verify_cli(&["--env-file", path, "--listen-key", "PEP_BIND"]);
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let checks = report["checks"].as_array().unwrap();
    let names: Vec<&str> = checks
        .iter()
        .map(|check| check["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["install.toml", "policy.toml", "env-file", "healthz"]
    );
    assert_eq!(checks[2]["ok"], true, "{report}");
    assert_eq!(checks[3]["ok"], false, "{report}");

    // The default key is absent, and a repeated key fails the file.
    for (text, detail) in [
        (format!("PEP_BIND={address}\n"), "no key CHAPERONE_LISTEN"),
        (
            "SITE_TOKEN=s3cret-value\nSITE_TOKEN=s3cret-value\n".to_owned(),
            "repeats the key of line 1",
        ),
    ] {
        std::fs::write(&env_file, text).unwrap();
        let output = verify_cli(&["--env-file", path]);
        assert_eq!(output.status.code(), Some(1));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains("s3cret"), "{stdout}");
        let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let checks = report["checks"].as_array().unwrap();
        assert_eq!(checks[2]["ok"], false, "{report}");
        assert!(
            checks[2]["detail"].as_str().unwrap().contains(detail),
            "{report}"
        );
        assert_eq!(checks[3]["detail"], "no address to probe", "{report}");
    }
}

#[test]
fn the_cli_runs_the_release_tool_command_with_no_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("site.env");
    std::fs::write(
        &env_file,
        format!("CHAPERONE_LISTEN={}\n", unused_address()),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chaperone"))
        .arg("verify")
        .arg("--json")
        .arg("--env-file")
        .arg(&env_file)
        .arg("--listen-key")
        .arg("CHAPERONE_LISTEN")
        .output()
        .unwrap();
    // A usage error exits with 2 and prints no report.
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let checks = report["checks"].as_array().unwrap();
    let names: Vec<&str> = checks
        .iter()
        .map(|check| check["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["install.toml", "policy.toml", "env-file", "healthz"]
    );
    assert_eq!(checks[2]["ok"], true, "{report}");
    assert_eq!(checks[3]["ok"], false, "{report}");
}

#[test]
fn the_cli_reports_a_missing_config_dir_as_a_failed_check() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let missing = root.path().join("no-such-dir");
    let output = Command::new(env!("CARGO_BIN_EXE_chaperone"))
        .arg("verify")
        .arg("--json")
        .arg("--config-dir")
        .arg(&missing)
        .arg("--plugins-dir")
        .arg(&plugins)
        .arg("--listen")
        .arg(unused_address().to_string())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let checks = report["checks"].as_array().unwrap();
    for check in &checks[..2] {
        assert_eq!(check["ok"], false, "{report}");
        assert!(
            check["detail"].as_str().unwrap().starts_with("cannot read"),
            "{report}"
        );
    }
}
