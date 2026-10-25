//! The plugin binary end to end against a fake Home Assistant. It checks
//! the bearer, the path and the body. It checks the answers for a good
//! call, a refused call and bad arguments.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::process::Stdio;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

const TOKEN: &str = "ha-long-lived-token";

/// One request the fake saw.
#[derive(Debug)]
struct Seen {
    path: String,
    body: serde_json::Value,
}

async fn service(
    State(sender): State<mpsc::UnboundedSender<Seen>>,
    Path((domain, service)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if bearer != format!("Bearer {TOKEN}") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"message":"Unauthorized"})),
        );
    }
    sender
        .send(Seen {
            path: format!("/api/services/{domain}/{service}"),
            body,
        })
        .unwrap();
    if service == "explode" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"no such service"})),
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!([{"entity_id":"light.kitchen","state":"on"}])),
    )
}

struct Running {
    client: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    seen: mpsc::UnboundedReceiver<Seen>,
    _child: Child,
}

async fn start(token: &str) -> Running {
    let (sender, seen) = mpsc::unbounded_channel();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route("/api/services/{domain}/{service}", post(service))
        .with_state(sender);
    tokio::spawn(axum::serve(listener, router).into_future());

    let mut child = Command::new(env!("CARGO_BIN_EXE_chaperone-ha-call"))
        .arg("--url")
        .arg(format!("http://{address}/"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let line = serde_json::json!({ "secrets": { "HA_TOKEN": token } }).to_string();
    stdin
        .write_all(format!("{line}\n").as_bytes())
        .await
        .unwrap();
    let client = ().serve((stdout, stdin)).await.unwrap();
    Running {
        client,
        seen,
        _child: child,
    }
}

fn request(arguments: serde_json::Value) -> CallToolRequestParams {
    let members = arguments.as_object().unwrap().clone();
    CallToolRequestParams::new("call_service").with_arguments(members)
}

fn text_of(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect()
}

#[tokio::test]
async fn a_service_call_reaches_home_assistant_with_the_token() {
    let mut running = start(TOKEN).await;
    let tools = running.client.list_all_tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "call_service");

    let result = running
        .client
        .call_tool(request(serde_json::json!({
            "domain": "light", "service": "turn_on",
            "entity_id": "light.kitchen", "data": {"brightness": 128}
        })))
        .await
        .unwrap();
    assert_ne!(result.is_error, Some(true), "{}", text_of(&result));
    assert!(text_of(&result).contains(r#""state":"on""#));
    let seen = running.seen.recv().await.unwrap();
    assert_eq!(seen.path, "/api/services/light/turn_on");
    assert_eq!(seen.body["entity_id"], serde_json::json!(["light.kitchen"]));
    assert_eq!(seen.body["brightness"], 128);

    let many = running
        .client
        .call_tool(request(serde_json::json!({
            "domain": "switch", "service": "turn_off",
            "entity_id": ["switch.a", "switch.b"]
        })))
        .await
        .unwrap();
    assert_ne!(many.is_error, Some(true));
    let seen = running.seen.recv().await.unwrap();
    assert_eq!(
        seen.body["entity_id"],
        serde_json::json!(["switch.a", "switch.b"])
    );
}

#[tokio::test]
async fn a_refused_call_and_bad_arguments_are_error_results() {
    let mut running = start(TOKEN).await;
    let refused = running
        .client
        .call_tool(request(serde_json::json!({
            "domain": "light", "service": "explode", "entity_id": "light.kitchen"
        })))
        .await
        .unwrap();
    assert_eq!(refused.is_error, Some(true));
    assert!(text_of(&refused).contains("400"), "{}", text_of(&refused));
    running.seen.recv().await.unwrap();

    for bad in [
        serde_json::json!({"domain": "Light", "service": "turn_on", "entity_id": "light.kitchen"}),
        serde_json::json!({"domain": "light", "service": "turn_on", "entity_id": "kitchen"}),
        serde_json::json!({"domain": "light", "service": "turn_on", "entity_id": []}),
        serde_json::json!({"domain": "light", "service": "turn_on"}),
        serde_json::json!({"domain": "light", "service": "turn_on", "entity_id": "light.k", "x": 1}),
    ] {
        let result = running
            .client
            .call_tool(request(bad.clone()))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true), "{bad}");
        assert!(running.seen.try_recv().is_err(), "{bad} reached the server");
    }
    assert!(
        running
            .client
            .call_tool(CallToolRequestParams::new("other"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_wrong_token_is_an_error_result_that_never_shows_the_token() {
    let running = start("wrong-token").await;
    let result = running
        .client
        .call_tool(request(serde_json::json!({
            "domain": "light", "service": "turn_on", "entity_id": "light.kitchen"
        })))
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    assert!(text_of(&result).contains("401"), "{}", text_of(&result));
    assert!(!text_of(&result).contains("wrong-token"));
}
