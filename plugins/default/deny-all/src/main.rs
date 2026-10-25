//! The default approval channel (`docs/design.md` 7.2). It serves MCP on
//! stdio with one tool, `approve`, and answers every call with a denial.
//! Every gated call thus fails closed until the operator enables a real
//! channel (G2). It declares no secret, so it reads no secret line.

use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, ServiceExt};

/// The tool chaperone calls for each gate (`docs/design.md` 5.3).
const APPROVE_TOOL: &str = "approve";

/// The answer to every gate.
const ANSWER: &str = r#"{"answer":"denied","reason":"no approval channel"}"#;

#[derive(Debug, Clone, Copy)]
struct DenyAll;

impl ServerHandler for DenyAll {
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
            serde_json::Value::String("object".to_owned()),
        );
        let tool = Tool::new_with_raw(
            APPROVE_TOOL,
            Some("Denies every gate".into()),
            Arc::new(schema),
        );
        Ok(ListToolsResult::with_all_items(vec![tool]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name != APPROVE_TOOL {
            return Err(ErrorData::invalid_params("no such tool", None));
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(ANSWER)]).into())
    }
}

fn main() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("chaperone-deny-all: cannot start the runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        let service = match DenyAll.serve(rmcp::transport::stdio()).await {
            Ok(service) => service,
            Err(error) => {
                eprintln!("chaperone-deny-all: the MCP initialize failed: {error}");
                return std::process::ExitCode::FAILURE;
            }
        };
        match service.waiting().await {
            Ok(_) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("chaperone-deny-all: the service task failed: {error}");
                std::process::ExitCode::FAILURE
            }
        }
    })
}
