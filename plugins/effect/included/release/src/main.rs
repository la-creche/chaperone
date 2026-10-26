//! The `release` upstream binary. It serves MCP on stdio with one tool,
//! `request`. Each call writes one request file into the directory of
//! `--requests-dir` and answers the request ID. The plugin takes no secret.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chaperone_plugin_release::{Arguments, Request, Requester, file};
use clap::Parser;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, ServiceExt};

/// The one tool of the upstream.
const REQUEST: &str = "request";

#[derive(Debug, Parser)]
#[command(name = "chaperone-release")]
struct Args {
    /// The requests/ directory of the release spool.
    #[arg(long)]
    requests_dir: PathBuf,
    /// The requester that each request states: a-z, then 1 to 30 of a-z,
    /// 0-9 and -.
    #[arg(long)]
    requested_by: String,
}

#[derive(Debug, Clone)]
struct Plugin {
    requests_dir: Arc<PathBuf>,
    requester: Requester,
}

fn error_text(text: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text)])
}

impl Plugin {
    /// Check the arguments and write one request file.
    fn request(&self, arguments: serde_json::Map<String, serde_json::Value>) -> CallToolResult {
        let arguments = match Arguments::parse(arguments) {
            Ok(arguments) => arguments,
            Err(error) => return error_text(error.to_string()),
        };
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return error_text("the clock of the host is before 1970".into());
        };
        let mut entropy = [0_u8; 10];
        if getrandom::fill(&mut entropy).is_err() {
            return error_text("the OS random source failed".into());
        }
        let request = Request::new(arguments, self.requester.clone(), now, entropy);
        match file(&self.requests_dir, &request) {
            Ok(_) => {
                let answer = serde_json::json!({
                    "request": request.id().as_str(),
                    "status": "filed",
                });
                CallToolResult::success(vec![ContentBlock::text(answer.to_string())])
            }
            Err(error) => error_text(error.to_string()),
        }
    }
}

impl ServerHandler for Plugin {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["components"],
            "properties": {
                "kind": {"enum": ["release", "rollback"], "default": "release"},
                "components": {
                    "type": "object",
                    "description": "Each component name with a version x.y.z or latest",
                    "minProperties": 1,
                    "maxProperties": 8,
                    "additionalProperties": {
                        "type": "string",
                        "pattern": "^(latest|[0-9]+\\.[0-9]+\\.[0-9]+)$"
                    }
                },
                "rollback_of": {
                    "type": ["string", "null"],
                    "description": "The request ID to reverse, only for kind rollback",
                    "pattern": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$"
                }
            }
        });
        let Some(schema) = schema.as_object() else {
            return Err(ErrorData::internal_error(
                "the schema is not an object",
                None,
            ));
        };
        let tool = Tool::new_with_raw(
            REQUEST,
            Some("Asks for one release or rollback of the named components".into()),
            Arc::new(schema.clone()),
        );
        Ok(ListToolsResult::with_all_items(vec![tool]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name != REQUEST {
            return Err(ErrorData::invalid_params("no such tool", None));
        }
        Ok(self.request(request.arguments.unwrap_or_default()).into())
    }
}

async fn run(plugin: Plugin) -> Result<(), String> {
    let service = plugin
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .map_err(|error| format!("the MCP initialize failed: {error}"))?;
    service
        .waiting()
        .await
        .map_err(|error| format!("the service task failed: {error}"))?;
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let Some(requester) = Requester::parse(&args.requested_by) else {
        eprintln!("release: --requested-by is not a-z, then 1 to 30 of a-z, 0-9 and -");
        return std::process::ExitCode::FAILURE;
    };
    let plugin = Plugin {
        requests_dir: Arc::new(args.requests_dir),
        requester,
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("release: cannot start the runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(plugin)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("release: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
