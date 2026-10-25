//! A fake upstream for the effect host tests. Cargo builds this file as a
//! test binary with no harness. Run with no argument, it exits at once, so
//! `cargo test` passes it. Run with `--fake-upstream`, it serves MCP on
//! stdio: it reads the secret line of `docs/design.md` 7.5 first, or the
//! `VIKUNJA_TOKEN` variable with `--env`, and offers these tools:
//!
//! | Tool | Result |
//! |---|---|
//! | `list_tasks` | Text that holds the token, to test the blanking |
//! | `create_task` | Text `created` |
//! | `picture` | An image block |
//! | `big` | One byte more text than the result cap |
//! | `broken` | An error result |
//! | `slow` | Text, after two seconds |
//! | `secret_echo` | The token, for an ungranted tool |
//! | `delete_task`, `wait_task`, `odd_task` | Text, for the gated calls |
//! | `whoami` | The `_meta` and the arguments of the call, as JSON text |
//!
//! Run with `--fake-approval`, it serves the approval channel instead: one
//! tool, `approve`, that answers by the `tool` argument. `create_task` is
//! approved, `delete_task` is denied, `wait_task` is approved after two
//! seconds, `odd_task` gets text that is no answer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test fixture fails loudly"
)]

use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, ServiceExt};
use tokio::io::{AsyncBufReadExt, BufReader};

const TOOLS: [&str; 11] = [
    "list_tasks",
    "create_task",
    "picture",
    "big",
    "broken",
    "slow",
    "secret_echo",
    "delete_task",
    "wait_task",
    "odd_task",
    "whoami",
];

#[derive(Debug, Clone)]
struct Fake {
    token: String,
}

impl ServerHandler for Fake {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = TOOLS
            .iter()
            .map(|name| {
                let mut schema = serde_json::Map::new();
                schema.insert(
                    "type".to_owned(),
                    serde_json::Value::String("object".into()),
                );
                Tool::new_with_raw(
                    (*name).to_owned(),
                    Some(format!("the fake {name} tool").into()),
                    Arc::new(schema),
                )
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let text = |text: String| CallToolResult::success(vec![ContentBlock::text(text)]);
        let result = match request.name.as_ref() {
            "list_tasks" => text(format!("two tasks for token {}", self.token)),
            "create_task" => text("created".to_owned()),
            "picture" => CallToolResult::success(vec![ContentBlock::image(
                "iVBORw0KGgo=".to_owned(),
                "image/png".to_owned(),
            )]),
            "big" => text("a".repeat(1024 * 1024 + 1)),
            "broken" => CallToolResult::error(vec![ContentBlock::text("boom".to_owned())]),
            "slow" => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                text("late".to_owned())
            }
            "secret_echo" => text(self.token.clone()),
            "delete_task" => text("deleted".to_owned()),
            "wait_task" => text("waited".to_owned()),
            "odd_task" => text("odd".to_owned()),
            "whoami" => text(
                serde_json::json!({"meta": context.meta, "arguments": request.arguments})
                    .to_string(),
            ),
            other => {
                return Err(ErrorData::invalid_params(
                    format!("no tool named {other}"),
                    None,
                ));
            }
        };
        Ok(result.into())
    }
}

/// The approval channel fake.
#[derive(Debug, Clone, Copy)]
struct FakeApproval;

impl ServerHandler for FakeApproval {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut schema = serde_json::Map::new();
        schema.insert(
            "type".to_owned(),
            serde_json::Value::String("object".into()),
        );
        let tool = Tool::new_with_raw(
            "approve",
            Some("the fake approval".into()),
            Arc::new(schema),
        );
        Ok(ListToolsResult::with_all_items(vec![tool]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let tool = request
            .arguments
            .as_ref()
            .and_then(|arguments| arguments.get("tool"))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_owned();
        let answer =
            |text: &str| CallToolResult::success(vec![ContentBlock::text(text.to_owned())]);
        let result = if tool.ends_with("delete_task") {
            answer(r#"{"answer":"denied","reason":"not today"}"#)
        } else if tool.ends_with("wait_task") {
            tokio::time::sleep(Duration::from_secs(2)).await;
            answer(r#"{"answer":"approved"}"#)
        } else if tool.ends_with("odd_task") {
            answer("yes")
        } else {
            answer(r#"{"answer":"approved"}"#)
        };
        Ok(result.into())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if args.iter().any(|arg| arg == "--fake-approval") {
        runtime.block_on(async {
            let service = FakeApproval.serve(rmcp::transport::stdio()).await.unwrap();
            service.waiting().await.unwrap();
        });
        return;
    }
    if !args.iter().any(|arg| arg == "--fake-upstream") {
        return;
    }
    let from_env = args.iter().any(|arg| arg == "--env");
    runtime.block_on(serve(from_env));
}

async fn serve(from_env: bool) {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let token = if from_env {
        std::env::var("VIKUNJA_TOKEN").unwrap()
    } else {
        let mut line = String::new();
        stdin.read_line(&mut line).await.unwrap();
        let message: serde_json::Value = serde_json::from_str(&line).unwrap();
        message["secrets"]["VIKUNJA_TOKEN"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    eprintln!("fake upstream started");
    let service = Fake { token }
        .serve((stdin, tokio::io::stdout()))
        .await
        .unwrap();
    service.waiting().await.unwrap();
}
