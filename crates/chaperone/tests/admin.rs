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
use chaperone::startup;
use chaperone_core::{Bearer, Credentials};
use support::{INSTALL, TOKEN, config_dir, plugin_tree, policy_text, secrets_dir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[test]
fn a_file_name_picks_the_check_and_another_is_refused() {
    assert_eq!("install.toml".parse(), Ok(ConfigFile::Install));
    assert_eq!("policy.json".parse(), Ok(ConfigFile::Policy));
    assert!("install.json".parse::<ConfigFile>().is_err());
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
fn a_new_token_authenticates_and_the_previous_file_is_kept() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let before = std::fs::read_to_string(config.join("policy.json")).unwrap();

    let token = admin::token_new(&config, "librechat").unwrap();
    let text = token.reveal().to_owned();
    assert_eq!(text.len(), 64);
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(format!("{token:?}"), "Token(..)");

    let after = std::fs::read_to_string(config.join("policy.json")).unwrap();
    assert!(
        after.contains(r#""$schema": "urn:chaperone:policy:1""#),
        "{after}"
    );
    assert!(
        !after.contains(&text),
        "the token itself must not be stored"
    );
    assert_eq!(
        std::fs::read_to_string(config.join("policy.json.prev")).unwrap(),
        before
    );
    assert!(!config.join("policy.json.tmp").exists());

    let secrets = secrets_dir(root.path());
    let loaded = startup::load(
        &config,
        &plugins,
        &root.path().join("audit.jsonl"),
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
        std::fs::read_to_string(config.join("policy.json")).unwrap(),
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

    let good = serde_json::json!({ "file": "policy.json", "content": policy_text(30) });
    let (status, body) = request(&socket, "POST", "/check", &good.to_string()).await;
    assert!(status.contains("200"), "{status} {body}");
    assert!(body.contains(r#""ok":true"#));

    let bad = serde_json::json!({ "file": "policy.json", "content": "{\"version\":2}" });
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
