//! The plugin binary end to end: a fake flow hook takes the request, the
//! test taps through `/resume`, and the `approve` call answers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

const APPROVAL_TOKEN: &str = "approval-secret-1234";
const RESUME_TOKEN: &str = "resume-secret-5678";
const GATE_HEX: &str = "ff00123456789abcdef0112233445566";

/// A fake flow hook. It checks the bearer and hands each body to the test.
async fn hook(
    State(sender): State<mpsc::UnboundedSender<serde_json::Value>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if bearer != format!("Bearer {APPROVAL_TOKEN}") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"unauthorized"})),
        );
    }
    sender.send(body).unwrap();
    (StatusCode::OK, Json(serde_json::json!({"status":"sent"})))
}

struct Flow {
    url: String,
    requests: mpsc::UnboundedReceiver<serde_json::Value>,
}

async fn fake_flow() -> Flow {
    let (sender, requests) = mpsc::unbounded_channel();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route("/hook/approval", post(hook))
        .with_state(sender);
    tokio::spawn(axum::serve(listener, router).into_future());
    Flow {
        url: format!("http://{address}/hook/approval"),
        requests,
    }
}

/// A loopback port that is free at this moment.
async fn free_port() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

struct Running {
    client: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    resume_url: String,
    _child: Child,
}

async fn start(flow: &Flow) -> Running {
    let listen = free_port().await;
    let mut child = Command::new(env!("CARGO_BIN_EXE_chaperone-ha-approval"))
        .arg("--hook-url")
        .arg(&flow.url)
        .arg("--listen")
        .arg(listen.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let line = serde_json::json!({
        "secrets": { "APPROVAL_TOKEN": APPROVAL_TOKEN, "RESUME_TOKEN": RESUME_TOKEN }
    })
    .to_string();
    stdin
        .write_all(format!("{line}\n").as_bytes())
        .await
        .unwrap();
    let client = ().serve((stdout, stdin)).await.unwrap();
    // The listener is up before the MCP initialize completes.
    Running {
        client,
        resume_url: format!("http://{listen}/resume"),
        _child: child,
    }
}

fn approve_request(gate_hex: &str) -> CallToolRequestParams {
    let mut arguments = serde_json::Map::new();
    arguments.insert("gate".into(), gate_hex.into());
    arguments.insert("app".into(), "librechat".into());
    arguments.insert("tool".into(), "vikunja__create_task".into());
    arguments.insert(
        "arguments".into(),
        serde_json::json!({ "title": "buy milk" }),
    );
    CallToolRequestParams::new("approve").with_arguments(arguments)
}

fn text_of(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect()
}

async fn resume(
    url: &str,
    token: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = reqwest::Client::new()
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap();
    (StatusCode::from_u16(status.as_u16()).unwrap(), body)
}

#[tokio::test]
async fn a_tap_on_approve_answers_approved() {
    let mut flow = fake_flow().await;
    let running = start(&flow).await;

    let tools = running.client.list_all_tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "approve");

    let client = running.client.peer().clone();
    let asked = tokio::spawn(async move { client.call_tool(approve_request(GATE_HEX)).await });

    let request = tokio::time::timeout(Duration::from_secs(5), flow.requests.recv())
        .await
        .unwrap()
        .unwrap();
    let job = request["job_id"].as_str().unwrap().to_owned();
    let gate = request["gate_id"].as_str().unwrap().to_owned();
    assert_eq!(job.len(), 26);
    assert!(
        job.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    );
    assert_eq!(gate, "ff00123456789abc");
    assert_eq!(request["agent"], "librechat");
    assert_eq!(request["kind"], "approval");
    let summary = request["summary"].as_str().unwrap();
    assert!(summary.starts_with("vikunja__create_task "), "{summary}");
    assert!(summary.contains("buy milk"), "{summary}");

    // A wrong bearer, a bad job and an unknown gate are refused first.
    let (status, _) = resume(
        &running.resume_url,
        "wrong",
        serde_json::json!({"job": job, "gate": gate, "decision": "approve"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = resume(
        &running.resume_url,
        RESUME_TOKEN,
        serde_json::json!({"job": "not-a-job", "gate": gate, "decision": "approve"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = resume(
        &running.resume_url,
        RESUME_TOKEN,
        serde_json::json!({"job": "0".repeat(26), "gate": "0".repeat(16), "decision": "approve"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = resume(
        &running.resume_url,
        RESUME_TOKEN,
        serde_json::json!({"job": job, "gate": gate, "decision": "approve"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "resumed");

    let result = asked.await.unwrap().unwrap();
    assert_eq!(text_of(&result), r#"{"answer":"approved"}"#);

    // A repeat is idle. A contradiction is refused and changes nothing.
    let (status, body) = resume(
        &running.resume_url,
        RESUME_TOKEN,
        serde_json::json!({"job": job, "gate": gate, "decision": "approve"}),
    )
    .await;
    assert_eq!(
        (status, body["status"].as_str()),
        (StatusCode::OK, Some("already_decided"))
    );
    let (status, _) = resume(
        &running.resume_url,
        RESUME_TOKEN,
        serde_json::json!({"job": job, "gate": gate, "decision": "deny"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_tap_on_deny_answers_denied() {
    let mut flow = fake_flow().await;
    let running = start(&flow).await;
    let gate_hex = "00".repeat(15) + "01";
    let client = running.client.peer().clone();
    let asked = tokio::spawn(async move { client.call_tool(approve_request(&gate_hex)).await });
    let request = tokio::time::timeout(Duration::from_secs(5), flow.requests.recv())
        .await
        .unwrap()
        .unwrap();
    let (status, _) = resume(
        &running.resume_url,
        RESUME_TOKEN,
        serde_json::json!({
            "job": request["job_id"], "gate": request["gate_id"], "decision": "deny"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let result = asked.await.unwrap().unwrap();
    assert_eq!(
        text_of(&result),
        r#"{"answer":"denied","reason":"denied on the phone"}"#
    );
}

#[tokio::test]
async fn a_hook_that_refuses_is_a_denial() {
    let flow = Flow {
        url: format!("http://{}/hook/approval", free_port().await),
        requests: mpsc::unbounded_channel().1,
    };
    let running = start(&flow).await;
    let result = running
        .client
        .call_tool(approve_request(GATE_HEX))
        .await
        .unwrap();
    assert_eq!(
        text_of(&result),
        r#"{"answer":"denied","reason":"the approval request did not reach the phone"}"#
    );
}
