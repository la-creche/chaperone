//! The default front door: MCP over streamable HTTP, built on `rmcp`.
//!
//! For each request, the front door does these steps:
//!
//! 1. It reads the body through the strict reader, before `rmcp` parses it.
//! 2. It reads the bearer token from the `Authorization` header.
//! 3. It passes the request to the [`Gateway`].
//! 4. It turns the answer into an MCP result.
//!
//! It decides nothing and caches nothing (`plugins/adapter/AGENTS.md`).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use chaperone_core::strict::{self, ByteCap};
use chaperone_core::{ArgValue, Bearer, CallOutcome, Credentials, Gateway, ListedTool};
use http::{Method, StatusCode};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, ServerHandler};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// The path where the front door serves MCP.
pub const MCP_PATH: &str = "/mcp";

/// The largest request body the front door reads (`docs/design.md` 7.6).
pub const BODY_CAP: ByteCap = ByteCap::new(1024 * 1024);

/// The MCP server that one front door runs.
#[derive(Debug)]
struct Front<G> {
    gateway: Arc<G>,
}

impl<G> Clone for Front<G> {
    fn clone(&self) -> Self {
        Self {
            gateway: Arc::clone(&self.gateway),
        }
    }
}

/// The bearer token and the other headers of one request. The
/// `Authorization` header goes only into the [`Bearer`], so no other code
/// sees the token as text (G9).
struct RequestFacts {
    bearer: Option<Bearer>,
    headers: BTreeMap<String, String>,
}

impl RequestFacts {
    fn of(context: &RequestContext<RoleServer>) -> Self {
        let Some(parts) = context.extensions.get::<http::request::Parts>() else {
            return Self {
                bearer: None,
                headers: BTreeMap::new(),
            };
        };
        let mut bearer = None;
        let mut headers = BTreeMap::new();
        for (name, value) in &parts.headers {
            let Ok(text) = value.to_str() else {
                continue;
            };
            if name == http::header::AUTHORIZATION {
                bearer = bearer_token(text).map(|token| Bearer::new(token.to_owned()));
            } else {
                headers.insert(name.as_str().to_owned(), text.to_owned());
            }
        }
        Self { bearer, headers }
    }

    fn credentials(&self) -> Credentials<'_> {
        Credentials {
            bearer: self.bearer.as_ref(),
            headers: &self.headers,
        }
    }
}

/// The token of an `Authorization: Bearer <token>` header. The scheme is
/// case-insensitive (RFC 9110, section 11.1).
fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

fn to_tool(listed: ListedTool) -> Tool {
    let schema: serde_json::Map<String, serde_json::Value> = listed
        .input_schema
        .iter()
        .map(|(key, value)| (key.clone(), value.to_json()))
        .collect();
    Tool::new_with_raw(
        listed.name.as_str().to_owned(),
        listed.description.map(Into::into),
        Arc::new(schema),
    )
}

fn error_text(text: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text)])
}

/// The MCP result of one outcome. `name` is the tool as the app named it.
fn render(name: &str, outcome: CallOutcome) -> CallToolResult {
    match outcome {
        CallOutcome::Ran(result) => {
            let blocks = result.content.into_iter().map(ContentBlock::text).collect();
            if result.is_error {
                CallToolResult::error(blocks)
            } else {
                CallToolResult::success(blocks)
            }
        }
        CallOutcome::Denied(reason) => {
            error_text(format!("chaperone denied this call: {}", reason.code()))
        }
        // The same text for every identical call (`docs/design.md` 5.3).
        CallOutcome::Waiting(gate) => error_text(format!(
            "Awaiting permission for tool call {name} (gate {gate}). Call again \
             with the exact same arguments to gather the result."
        )),
        CallOutcome::Failed(fault) => error_text(format!(
            "chaperone could not run this call: {}",
            fault.code()
        )),
    }
}

/// The top-level arguments of a call. `rmcp` parsed them from a body that
/// [`strict_body`] already checked.
fn arguments(request: &CallToolRequestParams) -> BTreeMap<String, ArgValue> {
    let Some(members) = &request.arguments else {
        return BTreeMap::new();
    };
    match ArgValue::from_json(serde_json::Value::Object(members.clone())) {
        ArgValue::Object(members) => members,
        ArgValue::Null
        | ArgValue::Bool(_)
        | ArgValue::Int(_)
        | ArgValue::UInt(_)
        | ArgValue::Float(_)
        | ArgValue::String(_)
        | ArgValue::Array(_) => BTreeMap::new(),
    }
}

impl<G: Gateway> ServerHandler for Front<G> {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let facts = RequestFacts::of(&context);
        match self.gateway.list_tools(&facts.credentials()).await {
            Ok(tools) => Ok(ListToolsResult::with_all_items(
                tools.into_iter().map(to_tool).collect(),
            )),
            Err(error) => Err(ErrorData::invalid_request(error.to_string(), None)),
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let facts = RequestFacts::of(&context);
        let arguments = arguments(&request);
        let outcome = self
            .gateway
            .call_tool(&facts.credentials(), &request.name, arguments)
            .await;
        Ok(render(&request.name, outcome).into())
    }
}

/// Refuse a `POST` body that is not strict JSON, or that is over
/// [`BODY_CAP`], before `rmcp` sees it. A duplicate key, a byte order mark
/// or invalid UTF-8 never reaches the parser. Other methods carry no body
/// that `rmcp` reads.
async fn strict_body(request: Request, next: Next) -> Response {
    if request.method() != Method::POST {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, BODY_CAP.bytes()).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    if let Err(error) = strict::read_value(&bytes, BODY_CAP) {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// Serve MCP on `listener` until `shutdown` is cancelled. `allowed_hosts`
/// lists the `Host` values to accept. `rmcp` refuses every other host, to
/// stop DNS rebinding.
///
/// # Errors
///
/// Returns the I/O error of the HTTP server.
pub async fn serve<G: Gateway>(
    gateway: Arc<G>,
    listener: TcpListener,
    allowed_hosts: Vec<String>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let front = Front { gateway };
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(allowed_hosts)
        .with_cancellation_token(shutdown.child_token());
    let service = StreamableHttpService::new(
        move || Ok(front.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let router = axum::Router::new()
        .nest_service(MCP_PATH, service)
        .layer(middleware::from_fn(strict_body));
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { shutdown.cancelled_owned().await })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_bearer_header() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer  abc "), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("Bearer"), None);
    }

    #[test]
    fn a_denial_renders_as_an_error_result_with_the_code() {
        let result = render(
            "x__y",
            CallOutcome::Denied(chaperone_core::DenyReason::ToolNotGranted),
        );
        assert_eq!(result.is_error, Some(true));
        let text: String = result
            .content
            .iter()
            .filter_map(|block| block.as_text().map(|text| text.text.clone()))
            .collect();
        assert_eq!(text, "chaperone denied this call: tool_not_granted");
    }
}
