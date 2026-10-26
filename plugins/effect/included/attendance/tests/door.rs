//! The plugin binary end to end against a fake session service on a temp
//! Unix socket. It checks the bearer, the path and the exact body of each
//! door call, the result each answer gives and the error mapping.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::collections::VecDeque;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::routing::post;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult, MetaObject, RequestMetaObject};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

const DELEGATE: &str = "delegate-token-0123456789abcdef0123456789";
const DISPATCH: &str = "dispatch-token-0123456789abcdef0123456789";

/// One request the fake door saw.
#[derive(Debug)]
struct Seen {
    path: String,
    bearer: String,
    body: Value,
}

#[derive(Clone)]
struct Fake {
    seen: mpsc::UnboundedSender<Seen>,
    answers: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
}

async fn door(
    State(fake): State<Fake>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, String) {
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = serde_json::from_slice(&body).unwrap();
    let path = uri.path().to_owned();
    fake.seen.send(Seen { path, bearer, body }).unwrap();
    fake.answers.lock().unwrap().pop_front().unwrap()
}

struct Running {
    client: Client,
    seen: mpsc::UnboundedReceiver<Seen>,
    answers: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
    _dir: tempfile::TempDir,
    _child: Child,
}

impl Running {
    fn answer(&self, status: u16, body: Value) {
        let status = StatusCode::from_u16(status).unwrap();
        self.answers
            .lock()
            .unwrap()
            .push_back((status, body.to_string()));
    }

    async fn call(&self, app: Option<&str>, tool: &str, arguments: Value) -> CallToolResult {
        call(&self.client, app, tool, arguments).await
    }
}

/// Call `tool` as the app `app`, or with no app ID for `None`.
async fn call(client: &Client, app: Option<&str>, tool: &str, arguments: Value) -> CallToolResult {
    let mut request = CallToolRequestParams::new(tool.to_owned())
        .with_arguments(arguments.as_object().unwrap().clone());
    if let Some(app) = app {
        let mut members = serde_json::Map::new();
        members.insert("chaperone.app".to_owned(), json!(app));
        request.meta = Some(RequestMetaObject(MetaObject::from(members)));
    }
    client.call_tool(request).await.unwrap()
}

type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

/// Launch the plugin on `socket` and write the secret line with
/// `delegate` as the delegate token.
async fn launch(socket: &Path, delegate: &str) -> (Child, tokio::process::ChildStdin) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_chaperone-attendance"))
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let line = json!({"secrets": {"DELEGATE_TOKEN": delegate, "DISPATCH_TOKEN": DISPATCH}});
    stdin
        .write_all(format!("{line}\n").as_bytes())
        .await
        .unwrap();
    (child, stdin)
}

/// Launch the plugin on `socket` and connect an MCP client to it.
async fn connect(socket: &Path) -> (Client, Child) {
    let (mut child, stdin) = launch(socket, DELEGATE).await;
    let stdout = child.stdout.take().unwrap();
    (().serve((stdout, stdin)).await.unwrap(), child)
}

async fn start() -> Running {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("door.sock");
    let (sender, seen) = mpsc::unbounded_channel();
    let answers = Arc::new(Mutex::new(VecDeque::new()));
    let fake = Fake {
        seen: sender,
        answers: Arc::clone(&answers),
    };
    let router = Router::new()
        .route("/delegate", post(door))
        .route("/dispatch", post(door))
        .route("/dispatch/jobs", post(door))
        .with_state(fake);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(axum::serve(listener, router).into_future());

    let (client, child) = connect(&socket).await;
    Running {
        client,
        seen,
        answers,
        _dir: dir,
        _child: child,
    }
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect()
}

fn value_of(result: &CallToolResult) -> Value {
    serde_json::from_str(&text_of(result)).unwrap()
}

/// The reason of an error result.
fn reason_of(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true), "{}", text_of(result));
    let value = value_of(result);
    assert_eq!(value["ok"], false);
    value["reason"].as_str().unwrap().to_owned()
}

fn is_ulid(text: &str) -> bool {
    text.len() == 26
        && text
            .bytes()
            .all(|byte| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&byte))
}

#[tokio::test]
async fn a_delegate_call_sends_the_exact_body_and_wraps_the_answer() {
    let mut running = start().await;
    let tools = running.client.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(names, ["invoke_agent", "enqueue", "job_status"]);

    running.answer(
        200,
        json!({"status": "ok", "session_id": "s1", "content": "42"}),
    );
    let result = running
        .call(
            Some("chat"),
            "invoke_agent",
            json!({"family": "research", "message": "why?", "attachments": ["a.txt"]}),
        )
        .await;
    assert_ne!(result.is_error, Some(true), "{}", text_of(&result));
    assert_eq!(
        value_of(&result),
        json!({"untrusted": true, "source": "family:research", "content": "42"})
    );
    let seen = running.seen.recv().await.unwrap();
    assert_eq!(seen.path, "/delegate");
    assert_eq!(seen.bearer, format!("Bearer {DELEGATE}"));
    let id = seen.body["delegation_id"].as_str().unwrap().to_owned();
    assert!(is_ulid(&id), "{id}");
    assert_eq!(
        seen.body,
        json!({
            "caller_family": "chat", "target_family": "research", "delegation_id": id,
            "claimed_session_id": null, "message": "why?"
        })
    );

    // A long answer is cut to 64 KiB.
    running.answer(200, json!({"status": "ok", "content": "a".repeat(70_000)}));
    let result = running
        .call(
            Some("chat"),
            "invoke_agent",
            json!({"family": "research", "message": "m"}),
        )
        .await;
    assert_eq!(
        value_of(&result)["content"].as_str().unwrap().len(),
        64 * 1024
    );
}

#[tokio::test]
async fn a_delegate_answer_that_is_not_clean_is_an_error_result() {
    let running = start().await;
    let cases = [
        (
            200,
            json!({"status": "timeout", "error": "slow"}),
            "delegate_timeout",
        ),
        (
            200,
            json!({"status": "failed", "error": "broke"}),
            "upstream_failed",
        ),
        (200, json!({"status": "maybe"}), "upstream_failed"),
        (200, json!(["ok"]), "upstream_failed"),
        (500, json!({"status": "ok"}), "upstream_failed"),
    ];
    for (status, body, reason) in cases {
        running.answer(status, body.clone());
        let result = running
            .call(
                Some("chat"),
                "invoke_agent",
                json!({"family": "research", "message": "m"}),
            )
            .await;
        assert_eq!(reason_of(&result), reason, "{body}");
    }
}

#[tokio::test]
async fn an_enqueue_repeat_answers_created_false() {
    let mut running = start().await;
    for created in [json!(true), json!(false)] {
        running.answer(
            200,
            json!({"session_id": "auto-1", "status": "queued", "created": created}),
        );
        let result = running
            .call(
                Some("chat"),
                "enqueue",
                json!({"family": "builder", "message": "go", "idempotency_key": "k1"}),
            )
            .await;
        assert_eq!(
            value_of(&result),
            json!({"session": "auto-1", "family": "builder", "status": "queued", "created": created})
        );
        let seen = running.seen.recv().await.unwrap();
        assert_eq!(seen.path, "/dispatch");
        assert_eq!(seen.bearer, format!("Bearer {DISPATCH}"));
        let id = seen.body["delegation_id"].as_str().unwrap().to_owned();
        assert!(is_ulid(&id), "{id}");
        assert_eq!(
            seen.body,
            json!({
                "caller_family": "chat", "target_family": "builder", "delegation_id": id,
                "chain": ["chat", "builder"], "claimed_session_id": null,
                "message": "go", "idempotency_key": "k1"
            })
        );
    }
    // No session in the answer is a failure.
    running.answer(200, json!({"status": "queued"}));
    let result = running
        .call(
            Some("chat"),
            "enqueue",
            json!({"family": "builder", "message": "go"}),
        )
        .await;
    assert_eq!(reason_of(&result), "upstream_failed");
    let seen = running.seen.recv().await.unwrap();
    assert!(seen.body.get("idempotency_key").is_none());
}

#[tokio::test]
async fn job_status_caps_the_rows_and_drops_rows_that_are_not_objects() {
    let mut running = start().await;
    let mut rows: Vec<Value> = (0..250)
        .map(|n| json!({"session": format!("s{n}")}))
        .collect();
    rows[3] = json!("not a row");
    running.answer(200, json!({"jobs": rows}));
    let result = running
        .call(
            Some("chat"),
            "job_status",
            json!({"session": "auto-1", "since": "2026-09-20T06:00:01Z", "limit": 200}),
        )
        .await;
    let jobs = value_of(&result)["jobs"].as_array().unwrap().clone();
    assert_eq!(jobs.len(), 199);
    assert!(jobs.iter().all(Value::is_object));
    let seen = running.seen.recv().await.unwrap();
    assert_eq!(seen.path, "/dispatch/jobs");
    assert_eq!(
        seen.body,
        json!({"caller_family": "chat", "session": "auto-1",
               "since": "2026-09-20T06:00:01Z", "limit": 200})
    );

    running.answer(200, json!({"jobs": []}));
    running.call(Some("chat"), "job_status", json!({})).await;
    let seen = running.seen.recv().await.unwrap();
    assert_eq!(seen.body, json!({"caller_family": "chat"}));
}

#[tokio::test]
async fn each_dispatch_error_code_is_mapped() {
    let running = start().await;
    let cases = [
        ("dispatch_not_declared", "tool_not_granted"),
        ("forbidden", "tool_not_granted"),
        ("family_unknown", "tool_not_granted"),
        ("family_invalid", "tool_not_granted"),
        ("bad_request", "arg_validation"),
        ("idempotency_mismatch", "arg_validation"),
        ("payload_too_large", "arg_validation"),
        ("queue_full", "rate_limited"),
        ("something_else", "upstream_failed"),
    ];
    for (code, reason) in cases {
        running.answer(
            403,
            json!({"error": {"code": code, "message": format!("said {code}")}}),
        );
        let result = running
            .call(
                Some("chat"),
                "enqueue",
                json!({"family": "builder", "message": "go"}),
            )
            .await;
        assert_eq!(reason_of(&result), reason, "{code}");
        let detail = value_of(&result)["detail"].as_str().unwrap().to_owned();
        if reason == "upstream_failed" {
            assert_eq!(detail, "the dispatch door answered HTTP 403");
        } else {
            assert_eq!(detail, format!("said {code}"));
        }
    }
    // With no message, the detail is the code.
    running.answer(429, json!({"error": {"code": "queue_full"}}));
    let result = running.call(Some("chat"), "job_status", json!({})).await;
    assert_eq!(value_of(&result)["detail"], "queue_full");
}

#[tokio::test]
async fn a_call_without_a_family_app_id_or_with_bad_arguments_sends_nothing() {
    let mut running = start().await;
    for app in [None, Some("Chat"), Some("x"), Some("chat_app")] {
        let result = running
            .call(
                app,
                "invoke_agent",
                json!({"family": "research", "message": "m"}),
            )
            .await;
        assert_eq!(reason_of(&result), "upstream_failed", "{app:?}");
    }
    let bad = [
        (
            "invoke_agent",
            json!({"family": "Research", "message": "m"}),
        ),
        ("invoke_agent", json!({"family": "research", "message": ""})),
        (
            "invoke_agent",
            json!({"family": "research", "message": "m", "attachments": [1]}),
        ),
        (
            "invoke_agent",
            json!({"family": "research", "message": "m", "extra": 1}),
        ),
        (
            "enqueue",
            json!({"family": "builder", "message": "m", "idempotency_key": "k".repeat(129)}),
        ),
        ("job_status", json!({"session": "-x"})),
        ("job_status", json!({"since": "yesterday"})),
        ("job_status", json!({"limit": 201})),
    ];
    for (tool, arguments) in bad {
        let result = running.call(Some("chat"), tool, arguments.clone()).await;
        assert_eq!(reason_of(&result), "arg_validation", "{arguments}");
    }
    assert!(
        running.seen.try_recv().is_err(),
        "a request reached the door"
    );
}

#[tokio::test]
async fn no_token_appears_in_any_error_text() {
    let running = start().await;
    running.answer(
        200,
        json!({"status": "failed", "error": format!("bad {DELEGATE}")}),
    );
    let delegated = running
        .call(
            Some("chat"),
            "invoke_agent",
            json!({"family": "research", "message": "m"}),
        )
        .await;
    running.answer(
        403,
        json!({"error": {"code": "forbidden", "message": DISPATCH}}),
    );
    let dispatched = running
        .call(
            Some("chat"),
            "enqueue",
            json!({"family": "builder", "message": "m"}),
        )
        .await;
    for result in [delegated, dispatched] {
        let text = text_of(&result);
        assert_eq!(result.is_error, Some(true));
        assert!(text.contains("[redacted]"), "{text}");
        assert!(
            !text.contains(DELEGATE) && !text.contains(DISPATCH),
            "{text}"
        );
    }
}

#[tokio::test]
async fn an_unreachable_door_is_upstream_failed_and_names_no_path() {
    let dir = tempfile::tempdir().unwrap();
    let (client, _child) = connect(&dir.path().join("missing.sock")).await;
    for (tool, arguments) in [
        (
            "invoke_agent",
            json!({"family": "research", "message": "m"}),
        ),
        ("enqueue", json!({"family": "builder", "message": "m"})),
    ] {
        let result = call(&client, Some("chat"), tool, arguments).await;
        assert_eq!(reason_of(&result), "upstream_failed");
        assert!(
            !text_of(&result).contains("missing.sock"),
            "{}",
            text_of(&result)
        );
    }
}

#[tokio::test]
async fn a_short_token_refuses_start() {
    let dir = tempfile::tempdir().unwrap();
    let (mut child, _stdin) = launch(&dir.path().join("door.sock"), "short").await;
    assert!(!child.wait().await.unwrap().success());
}
