//! The plugin binary over MCP. It lists one tool. A call files a request
//! under the app ID of the call. A refused call files nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::path::Path;
use std::process::Stdio;

use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult, MetaObject, RequestMetaObject};
use tokio::process::{Child, Command};

fn launch(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chaperone-release"));
    command
        .arg("--requests-dir")
        .arg(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    command
}

async fn start(dir: &Path) -> (rmcp::service::RunningService<rmcp::RoleClient, ()>, Child) {
    let mut child = launch(dir).spawn().unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    (().serve((stdout, stdin)).await.unwrap(), child)
}

/// A call of `request` from the app `app`, as chaperone sends it: the app
/// ID in `_meta`.
fn call_from(app: Option<&str>, arguments: serde_json::Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::new("request")
        .with_arguments(arguments.as_object().unwrap().clone());
    if let Some(app) = app {
        let mut members = serde_json::Map::new();
        members.insert("chaperone.app".to_owned(), serde_json::json!(app));
        params.meta = Some(RequestMetaObject(MetaObject::from(members)));
    }
    params
}

fn call(arguments: serde_json::Value) -> CallToolRequestParams {
    call_from(Some("code"), arguments)
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
    assert_eq!(body["requested_by"], "code");

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
async fn a_call_with_no_app_id_that_is_a_name_files_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (client, _child) = start(dir.path()).await;
    let components = serde_json::json!({"components": {"chaperone": "1.2.3"}});
    for app in [None, Some("Not A Name")] {
        let refused = client
            .call_tool(call_from(app, components.clone()))
            .await
            .unwrap();
        assert_eq!(refused.is_error, Some(true), "{app:?}");
        assert!(
            text_of(&refused).contains("no app ID"),
            "{}",
            text_of(&refused)
        );
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn the_old_requester_flag_refuses_start() {
    let dir = tempfile::tempdir().unwrap();
    let status = launch(dir.path())
        .arg("--requested-by")
        .arg("code")
        .status()
        .await
        .unwrap();
    assert!(!status.success());
}
