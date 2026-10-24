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

const TOOLS: [&str; 7] = [
    "list_tasks",
    "create_task",
    "picture",
    "big",
    "broken",
    "slow",
    "secret_echo",
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
        _context: RequestContext<RoleServer>,
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|arg| arg == "--fake-upstream") {
        return;
    }
    let from_env = args.iter().any(|arg| arg == "--env");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
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
