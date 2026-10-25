//! The editor binary against a fake admin socket: the token challenge, the
//! form built from the schema, a check, a save with the previous file kept,
//! a refused save, and a new token shown once.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::net::UnixListener;
use tokio::process::{Child, Command};

const EDITOR_TOKEN: &str = "editor-secret-token";

/// What the fake admin socket saw and how it answers.
#[derive(Debug, Default)]
struct FakeState {
    checks: Vec<String>,
    refuse: bool,
}

type Fake = Arc<Mutex<FakeState>>;

/// A schema like the one chaperone prints: a map of apps with a note,
/// digests, limits and plugin sections.
fn schema() -> serde_json::Value {
    serde_json::json!({
        "install.json": {"type": "object", "properties": {}, "additionalProperties": false},
        "plugin.json": {"type": "object", "properties": {}, "additionalProperties": false},
        "policy.json": {
            "type": "object",
            "properties": {
                "$schema": {"type": ["string", "null"]},
                "version": {"type": "integer", "description": "The version of the file shape."},
                "apps": {"type": "object", "additionalProperties": {"$ref": "#/$defs/App"}}
            },
            "required": ["version"],
            "additionalProperties": false,
            "$defs": {
                "App": {
                    "type": "object",
                    "properties": {
                        "note": {"type": ["string", "null"]},
                        "token_sha256": {"type": "array", "items": {"$ref": "#/$defs/token%20digest"}},
                        "limits": {"$ref": "#/$defs/Limits"},
                        "plugins": {"type": "object", "additionalProperties": true}
                    },
                    "required": ["token_sha256", "limits"],
                    "additionalProperties": false
                },
                "Limits": {
                    "type": "object",
                    "properties": {
                        "calls_per_minute": {"type": "integer"},
                        "max_pending_gates": {"type": "integer"}
                    },
                    "required": ["calls_per_minute", "max_pending_gates"],
                    "additionalProperties": false
                },
                "token digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
            }
        },
        "sections": {
            "ha-call": {
                "type": "object",
                "properties": {"entities": {"type": "array", "items": {"type": "string"}}},
                "required": ["entities"],
                "additionalProperties": false
            }
        }
    })
}

async fn fake_schema() -> Json<serde_json::Value> {
    Json(schema())
}

async fn fake_check(
    State(fake): State<Fake>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut state = fake.lock().unwrap();
    state
        .checks
        .push(body["content"].as_str().unwrap().to_owned());
    if state.refuse {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"ok": false, "error": "the app x grants nothing"})),
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

async fn fake_token(Json(body): Json<serde_json::Value>) -> (StatusCode, Json<serde_json::Value>) {
    if body["app"] == "librechat" {
        (
            StatusCode::OK,
            Json(serde_json::json!({"token": "f".repeat(64)})),
        )
    } else {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"ok": false, "error": "the app nobody is not in policy.json"})),
        )
    }
}

async fn fake_socket(path: &Path, fake: Fake) {
    let listener = UnixListener::bind(path).unwrap();
    let router = Router::new()
        .route("/schema", get(fake_schema))
        .route("/check", post(fake_check))
        .route("/token", post(fake_token))
        .with_state(fake);
    tokio::spawn(axum::serve(listener, router).into_future());
}

struct Running {
    base: String,
    config: PathBuf,
    fake: Fake,
    client: reqwest::Client,
    _child: Child,
    _root: tempfile::TempDir,
}

const POLICY: &str = r#"{
  "version": 1,
  "apps": {
    "librechat": {
      "note": "the chat app",
      "token_sha256": ["aa", "bb"],
      "limits": {"calls_per_minute": 30, "max_pending_gates": 1},
      "plugins": {"ha-call": {"entities": ["light.kitchen"]}}
    }
  }
}
"#;

async fn start() -> Running {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(config.join("policy.json"), POLICY).unwrap();
    let token_file = root.path().join("editor.token");
    std::fs::write(&token_file, format!("{EDITOR_TOKEN}\n")).unwrap();
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let socket = root.path().join("admin.sock");
    let fake = Fake::default();
    fake_socket(&socket, Arc::clone(&fake)).await;

    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let listen = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_chaperone-editor"))
        .arg("--listen")
        .arg(&listen)
        .arg("--admin-socket")
        .arg(&socket)
        .arg("--config-dir")
        .arg(&config)
        .arg("--token-file")
        .arg(&token_file)
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let base = format!("http://{listen}");
    let client = reqwest::Client::new();
    for _ in 0..200 {
        if client.get(format!("{base}/policy")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Running {
        base,
        config,
        fake,
        client,
        _child: child,
        _root: root,
    }
}

impl Running {
    async fn get(&self) -> (StatusCode, String) {
        let response = self
            .client
            .get(format!("{}/policy", self.base))
            .basic_auth("operator", Some(EDITOR_TOKEN))
            .send()
            .await
            .unwrap();
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
        (status, response.text().await.unwrap())
    }

    async fn post(&self, path: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .basic_auth("operator", Some(EDITOR_TOKEN))
            .header("Origin", &self.base)
            .form(fields)
            .send()
            .await
            .unwrap();
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
        (status, response.text().await.unwrap())
    }
}

/// The hidden draft of a page, decoded.
fn draft_of(html: &str) -> String {
    let start = html.find("name=\"draft\" value=\"").unwrap() + "name=\"draft\" value=\"".len();
    let end = html[start..].find('"').unwrap() + start;
    html[start..end]
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[tokio::test]
async fn the_editor_needs_the_token_and_shows_the_form_from_the_schema() {
    let running = start().await;
    let plain = running
        .client
        .get(format!("{}/policy", running.base))
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status().as_u16(), 401);
    assert!(plain.headers().contains_key("www-authenticate"));
    let wrong = running
        .client
        .get(format!("{}/policy", running.base))
        .basic_auth("operator", Some("not-it"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status().as_u16(), 401);

    let (status, html) = running.get().await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("2 token digest(s) present"), "{html}");
    assert!(!html.contains("\"aa\""), "a digest must not show");
    assert!(html.contains("name=\"f:i:/apps/librechat/limits/calls_per_minute\" value=\"30\""));
    assert!(html.contains("name=\"f:lines:/apps/librechat/plugins/ha-call/entities\""));
    assert!(html.contains("light.kitchen"));
    assert!(html.contains("The version of the file shape."));
    assert!(html.contains("New token for librechat"));
}

#[tokio::test]
async fn a_check_sends_the_draft_and_a_save_keeps_the_previous_file() {
    let running = start().await;
    let (_, html) = running.get().await;
    let draft = draft_of(&html);

    let (status, html) = running
        .post(
            "/policy",
            &[
                ("draft", draft.as_str()),
                ("f:i:/apps/librechat/limits/calls_per_minute", "42"),
                ("action", "check"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("The check passed"), "{html}");
    assert!(html.contains("value=\"42\""));
    let sent = running.fake.lock().unwrap().checks.clone();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].contains("\"calls_per_minute\": 42"), "{}", sent[0]);
    assert!(
        std::fs::read_to_string(running.config.join("policy.json"))
            .unwrap()
            .contains("30"),
        "a check saves nothing"
    );

    let (status, html) = running
        .post(
            "/policy",
            &[
                ("draft", draft.as_str()),
                ("f:i:/apps/librechat/limits/calls_per_minute", "42"),
                ("action", "save"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Saved."), "{html}");
    let saved = std::fs::read_to_string(running.config.join("policy.json")).unwrap();
    assert!(saved.contains("\"calls_per_minute\": 42"), "{saved}");
    assert!(saved.contains("light.kitchen"));
    assert_eq!(
        std::fs::read_to_string(running.config.join("policy.json.prev")).unwrap(),
        POLICY
    );
    assert!(!running.config.join("policy.json.tmp").exists());
}

#[tokio::test]
async fn a_refused_check_saves_nothing_and_shows_the_error() {
    let running = start().await;
    running.fake.lock().unwrap().refuse = true;
    let (_, html) = running.get().await;
    let draft = draft_of(&html);
    let (status, html) = running
        .post("/policy", &[("draft", draft.as_str()), ("action", "save")])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Not saved"), "{html}");
    assert!(html.contains("the app x grants nothing"));
    assert_eq!(
        std::fs::read_to_string(running.config.join("policy.json")).unwrap(),
        POLICY
    );
    assert!(!running.config.join("policy.json.prev").exists());
}

#[tokio::test]
async fn add_remove_and_a_new_token_round_trip() {
    let running = start().await;
    let (_, html) = running.get().await;
    let draft = draft_of(&html);
    let (_, html) = running
        .post(
            "/policy",
            &[
                ("draft", draft.as_str()),
                ("key:/apps", "openwebui"),
                (
                    "tpl:/apps",
                    r#"{"token_sha256":[],"limits":{"calls_per_minute":0,"max_pending_gates":0}}"#,
                ),
                ("action", "add:/apps"),
            ],
        )
        .await;
    assert!(html.contains("remove:/apps/openwebui"), "{html}");
    assert!(html.contains("0 token digest(s) present"));
    let draft = draft_of(&html);
    let (_, html) = running
        .post(
            "/policy",
            &[
                ("draft", draft.as_str()),
                ("action", "remove:/apps/openwebui"),
            ],
        )
        .await;
    assert!(!html.contains("remove:/apps/openwebui"));

    let (status, html) = running
        .post("/token", &[("action", "token:librechat")])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(&"f".repeat(64)), "{html}");
    let (_, html) = running.post("/token", &[("action", "token:nobody")]).await;
    assert!(html.contains("not in policy.json"), "{html}");

    // A form from another origin is refused.
    let foreign = running
        .client
        .post(format!("{}/policy", running.base))
        .basic_auth("operator", Some(EDITOR_TOKEN))
        .header("Origin", "http://192.0.2.10:8301")
        .form(&[("draft", "{}"), ("action", "save")])
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status().as_u16(), 403);
}
