//! The admin functions and the admin socket (`docs/design.md` 9 and 10).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use chaperone::admin::{self, ConfigFile};
use chaperone::registry::AuditMode;
use chaperone::startup;
use chaperone_core::{Bearer, Credentials};
use support::{INSTALL, TOKEN, config_dir, plugin_tree, policy_text, secrets_dir, write_manifest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[test]
fn a_file_name_picks_the_check_and_another_is_refused() {
    assert_eq!("install.toml".parse(), Ok(ConfigFile::Install));
    assert_eq!("policy.toml".parse(), Ok(ConfigFile::Policy));
    assert!("install.json".parse::<ConfigFile>().is_err());
    assert!("policy.json".parse::<ConfigFile>().is_err());
    assert!("secrets.json".parse::<ConfigFile>().is_err());
}

#[test]
fn the_check_passes_the_fixture_and_refuses_a_broken_policy() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    admin::check(ConfigFile::Install, INSTALL.as_bytes(), &config, &plugins).unwrap();
    admin::check(
        ConfigFile::Policy,
        policy_text(30).as_bytes(),
        &config,
        &plugins,
    )
    .unwrap();

    let ungranted = policy_text(30).replace("vikunja", "nowhere");
    let error =
        admin::check(ConfigFile::Policy, ungranted.as_bytes(), &config, &plugins).unwrap_err();
    assert!(error.to_string().contains("nowhere"), "{error}");

    let error = admin::check(
        ConfigFile::Install,
        b"version = 1\nplugins.ghost = {}\n",
        &config,
        &plugins,
    )
    .unwrap_err();
    assert!(error.to_string().contains("ghost"), "{error}");
}

#[test]
fn the_check_refuses_a_delegation_chain_and_names_both_apps() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    write_manifest(
        &plugins,
        "decision/included/attendance",
        r#"
            name = "attendance"
            version = "1"
            kind = "decision"
            hooks = ["fence"]
        "#,
    );
    let install = "version = 1\nplugins = { attendance = {}, vikunja = {} }\n";
    let config = config_dir(root.path(), install, &policy_text(30));
    let policy = |beta_delegates: &str| {
        format!(
            r#"
            version = 1

            [apps.alpha]
            token_sha256 = ["{}"]
            limits = {{ calls_per_minute = 1, max_pending_gates = 1 }}
            plugins.attendance = {{ delegates = ["beta"] }}

            [apps.beta]
            token_sha256 = ["{}"]
            limits = {{ calls_per_minute = 1, max_pending_gates = 1 }}
            plugins.attendance = {{ delegates = [{beta_delegates}] }}
            "#,
            "a".repeat(64),
            "b".repeat(64)
        )
    };

    let chain = policy("\"gamma\"");
    let error = admin::check(ConfigFile::Policy, chain.as_bytes(), &config, &plugins).unwrap_err();
    let shown = error.to_string();
    assert!(shown.contains("caller app alpha"), "{shown}");
    assert!(shown.contains("target app beta"), "{shown}");
    assert!(shown.contains("one_hop"), "{shown}");

    let one_hop = policy("");
    admin::check(ConfigFile::Policy, one_hop.as_bytes(), &config, &plugins).unwrap();
}

#[test]
fn the_check_names_each_refused_app_on_its_own_line() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let app = |id: &str, digest: char, upstream: &str| {
        format!(
            "\n[apps.{id}]\ntoken_sha256 = [\"{}\"]\n\
             limits = {{ calls_per_minute = 1, max_pending_gates = 1 }}\n\
             grants.{upstream}.tools.list_tasks = {{}}\n",
            digest.to_string().repeat(64)
        )
    };
    let text = policy_text(30) + &app("one", 'b', "nowhere") + &app("two", 'c', "ghost");
    let error = admin::check(ConfigFile::Policy, text.as_bytes(), &config, &plugins).unwrap_err();
    let shown = error.to_string();
    let lines: Vec<&str> = shown.lines().collect();
    assert_eq!(lines.len(), 2, "{shown}");
    assert!(lines[0].starts_with("the app one is refused: "), "{shown}");
    assert!(lines[0].contains("nowhere"), "{shown}");
    assert!(lines[1].starts_with("the app two is refused: "), "{shown}");
    assert!(!shown.contains("librechat"), "{shown}");
}

#[test]
fn the_check_refuses_an_unknown_guard() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let install = format!("{INSTALL}plugins.mcp-http.guard = \"tls\"\n");
    let error =
        admin::check(ConfigFile::Install, install.as_bytes(), &config, &plugins).unwrap_err();
    assert!(error.to_string().contains("at line 3"), "{error}");
}

#[test]
fn a_new_token_authenticates_and_the_previous_file_is_kept() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let before = std::fs::read_to_string(config.join("policy.toml")).unwrap();

    let token = admin::token_new(&config, "librechat").unwrap();
    let text = token.reveal().to_owned();
    assert_eq!(text.len(), 64);
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(format!("{token:?}"), "Token(..)");

    let after = std::fs::read_to_string(config.join("policy.toml")).unwrap();
    assert!(
        after.contains("# The app instance of the tests."),
        "{after}"
    );
    assert!(!after.contains("$schema"), "{after}");
    assert!(
        !after.contains(&text),
        "the token itself must not be stored"
    );
    assert_eq!(
        std::fs::read_to_string(config.join("policy.toml.prev")).unwrap(),
        before
    );
    assert!(!config.join("policy.toml.tmp").exists());

    let secrets = secrets_dir(root.path());
    let loaded = startup::load(
        &config,
        &plugins,
        &root.path().join("audit.jsonl"),
        AuditMode::OwnerOnly,
        &secrets,
    )
    .unwrap();
    for bearer in [TOKEN, &text] {
        let bearer = Bearer::new(bearer.to_owned());
        let headers = BTreeMap::new();
        let credentials = Credentials {
            bearer: Some(&bearer),
            headers: &headers,
        };
        assert!(
            loaded
                .identity
                .resolve(&credentials, &loaded.policy)
                .is_some()
        );
    }

    // Two digests are the most. A third is refused and the file is kept.
    let error = admin::token_new(&config, "librechat").unwrap_err();
    assert!(error.to_string().contains("already holds"), "{error}");
    assert_eq!(
        std::fs::read_to_string(config.join("policy.toml")).unwrap(),
        after
    );
    assert!(admin::token_new(&config, "nobody").is_err());
}

/// One HTTP request over the Unix socket. Returns the status line and the
/// body.
async fn request(socket: &Path, method: &str, path: &str, body: &str) -> (String, String) {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: chaperone\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.lines().next().unwrap().to_owned();
    (status, body.to_owned())
}

#[tokio::test]
async fn the_socket_serves_check_and_token_only() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let socket = root.path().join("admin.sock");
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(admin::serve_socket(
        socket.clone(),
        config.clone(),
        plugins.clone(),
        shutdown.clone(),
    ));
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);

    let (status, _) = request(&socket, "GET", "/schema", "").await;
    assert!(status.contains("404"), "{status}");

    let good = serde_json::json!({ "file": "policy.toml", "content": policy_text(30) });
    let (status, body) = request(&socket, "POST", "/check", &good.to_string()).await;
    assert!(status.contains("200"), "{status} {body}");
    assert!(body.contains(r#""ok":true"#));

    let bad = serde_json::json!({ "file": "policy.toml", "content": "version = 2\n" });
    let (status, body) = request(&socket, "POST", "/check", &bad.to_string()).await;
    assert!(status.contains("422"), "{status} {body}");
    assert!(body.contains("version"));

    let install = serde_json::json!({ "file": "install.toml", "content": INSTALL });
    let (status, body) = request(&socket, "POST", "/check", &install.to_string()).await;
    assert!(status.contains("200"), "{status} {body}");

    let (status, body) = request(&socket, "POST", "/token", r#"{"app":"librechat"}"#).await;
    assert!(status.contains("200"), "{status} {body}");
    let minted: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(minted["token"].as_str().unwrap().len(), 64);

    let (status, _) = request(&socket, "POST", "/token", r#"{"app":"nobody"}"#).await;
    assert!(status.contains("422"), "{status}");

    shutdown.cancel();
    server.await.unwrap().unwrap();
}
