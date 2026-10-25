//! The deny-all binary, driven as chaperone drives it: MCP over its stdio.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::process::Stdio;

use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use tokio::process::Command;

#[tokio::test]
async fn it_lists_approve_and_denies_every_gate() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_chaperone-deny-all"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let client = ().serve((stdout, stdin)).await.unwrap();

    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(names, ["approve"]);

    let mut arguments = serde_json::Map::new();
    arguments.insert(
        "gate".to_owned(),
        serde_json::Value::String("00".repeat(16)),
    );
    let result = client
        .call_tool(CallToolRequestParams::new("approve").with_arguments(arguments))
        .await
        .unwrap();
    assert_ne!(result.is_error, Some(true));
    let text: String = result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect();
    assert_eq!(
        text,
        r#"{"answer":"denied","reason":"no approval channel"}"#
    );

    assert!(
        client
            .call_tool(CallToolRequestParams::new("other"))
            .await
            .is_err()
    );
    client.cancel().await.unwrap();
}
