//! The plugin binary over MCP: the one tool, a call that files a request,
//! and a refused call that files nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::path::Path;
use std::process::Stdio;

use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use tokio::process::{Child, Command};

fn launch(dir: &Path, requested_by: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chaperone-release"));
    command
        .arg("--requests-dir")
        .arg(dir)
        .arg("--requested-by")
        .arg(requested_by)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    command
}

async fn start(dir: &Path) -> (rmcp::service::RunningService<rmcp::RoleClient, ()>, Child) {
    let mut child = launch(dir, "agent-control").spawn().unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    (().serve((stdout, stdin)).await.unwrap(), child)
}

fn call(arguments: serde_json::Value) -> CallToolRequestParams {
    CallToolRequestParams::new("request").with_arguments(arguments.as_object().unwrap().clone())
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect()
}

#[tokio::test]
async fn a_call_files_one_request_and_a_bad_call_files_none() {
    let dir = tempfile::tempdir().unwrap();
    let (client, _child) = start(dir.path()).await;
    let tools = client.list_all_tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "request");

    let filed = client
        .call_tool(call(
            serde_json::json!({"components": {"chaperone": "1.2.3"}}),
        ))
        .await
        .unwrap();
    assert_ne!(filed.is_error, Some(true), "{}", text_of(&filed));
    let answer: serde_json::Value = serde_json::from_str(&text_of(&filed)).unwrap();
    assert_eq!(answer["status"], "filed");
    let id = answer["request"].as_str().unwrap();
    let body = std::fs::read_to_string(dir.path().join(format!("{id}.json"))).unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["id"], id);
    assert_eq!(body["requested_by"], "agent-control");

    let refused = client
        .call_tool(call(
            serde_json::json!({"components": {"../zz-marker": "1.2.3"}}),
        ))
        .await
        .unwrap();
    assert_eq!(refused.is_error, Some(true));
    assert!(
        !text_of(&refused).contains("zz-marker"),
        "{}",
        text_of(&refused)
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

    let other = client.call_tool(CallToolRequestParams::new("other")).await;
    assert!(other.is_err());
}

#[tokio::test]
async fn a_bad_requester_refuses_start() {
    let dir = tempfile::tempdir().unwrap();
    let status = launch(dir.path(), "Not A Name").status().await.unwrap();
    assert!(!status.success());
}
