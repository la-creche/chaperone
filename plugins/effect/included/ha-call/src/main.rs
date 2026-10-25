//! The effect half of `ha-call` (`docs/design.md` section 12). It serves
//! MCP on stdio with one tool, `call_service`. Each call becomes one
//! `POST /api/services/<domain>/<service>` on Home Assistant, with the
//! long-lived token from the secret line. The decision half fences the
//! entities before a call reaches this process. The token stays in memory
//! only (G9).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, ServiceExt};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};

/// The one tool of the upstream.
const CALL_SERVICE: &str = "call_service";

/// The secret parameter of the manifest.
const HA_TOKEN: &str = "HA_TOKEN";

/// The most of a Home Assistant answer the plugin passes on, in bytes.
const ANSWER_CAP: usize = 64 * 1024;

/// The longest a call to Home Assistant may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Parser)]
#[command(name = "chaperone-ha-call")]
struct Args {
    /// The base URL of Home Assistant, such as http://192.0.2.10:8123.
    #[arg(long)]
    url: String,
}

/// The secret line of `docs/design.md` 7.5.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretLine {
    secrets: BTreeMap<String, String>,
}

/// The arguments of `call_service`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    domain: String,
    service: String,
    entity_id: EntityIds,
    #[serde(default)]
    data: serde_json::Map<String, serde_json::Value>,
}

/// One entity, or a list of them, as Home Assistant takes `entity_id`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EntityIds {
    One(String),
    Many(Vec<String>),
}

impl EntityIds {
    fn all(&self) -> Vec<&str> {
        match self {
            Self::One(entity) => vec![entity.as_str()],
            Self::Many(entities) => entities.iter().map(String::as_str).collect(),
        }
    }
}

/// Whether `text` is one word of `a-z`, `0-9` and `_`.
fn is_word(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Whether `text` is `domain.object_id` of two words.
fn is_entity_id(text: &str) -> bool {
    text.split_once('.')
        .is_some_and(|(domain, object)| is_word(domain) && is_word(object))
}

struct Plugin {
    url: String,
    token: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct Shared(Arc<Plugin>);

fn error_text(text: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text)])
}

impl Plugin {
    /// Check the call and send it to Home Assistant.
    async fn call(&self, call: Call) -> CallToolResult {
        if !is_word(&call.domain) || !is_word(&call.service) {
            return error_text("domain and service are each one word of a-z, 0-9 and _".into());
        }
        let entities = call.entity_id.all();
        if entities.is_empty() || !entities.iter().all(|entity| is_entity_id(entity)) {
            return error_text("entity_id is one domain.object_id, or a list of them".into());
        }
        let mut body = call.data;
        body.insert(
            "entity_id".to_owned(),
            serde_json::Value::Array(
                entities
                    .iter()
                    .map(|entity| serde_json::Value::String((*entity).to_owned()))
                    .collect(),
            ),
        );
        let url = format!(
            "{}/api/services/{}/{}",
            self.url.trim_end_matches('/'),
            call.domain,
            call.service
        );
        let sent = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(error) => {
                return error_text(format!(
                    "Home Assistant is not reachable: {}",
                    error.without_url()
                ));
            }
        };
        let status = response.status();
        let text = match response.text().await {
            Ok(text) => text,
            Err(error) => {
                return error_text(format!(
                    "the answer of Home Assistant could not be read: {}",
                    error.without_url()
                ));
            }
        };
        let text: String = text.chars().take(ANSWER_CAP).collect();
        if status.is_success() {
            CallToolResult::success(vec![ContentBlock::text(text)])
        } else {
            error_text(format!("Home Assistant answered HTTP {status}: {text}"))
        }
    }
}

impl ServerHandler for Shared {
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
            "properties": {
                "domain": {"type": "string", "description": "The service domain, such as light"},
                "service": {"type": "string", "description": "The service, such as turn_on"},
                "entity_id": {
                    "description": "One entity ID, such as light.kitchen, or a list of them",
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}}
                    ]
                },
                "data": {"type": "object", "description": "Other service data"}
            },
            "required": ["domain", "service", "entity_id"]
        });
        let Some(schema) = schema.as_object() else {
            return Err(ErrorData::internal_error(
                "the schema is not an object",
                None,
            ));
        };
        let tool = Tool::new_with_raw(
            CALL_SERVICE,
            Some("Calls one Home Assistant service on the named entities".into()),
            Arc::new(schema.clone()),
        );
        Ok(ListToolsResult::with_all_items(vec![tool]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name != CALL_SERVICE {
            return Err(ErrorData::invalid_params("no such tool", None));
        }
        let arguments = serde_json::Value::Object(request.arguments.unwrap_or_default());
        let call: Call = match serde_json::from_value(arguments) {
            Ok(call) => call,
            Err(error) => {
                return Ok(
                    error_text(format!("the arguments are not a service call: {error}")).into(),
                );
            }
        };
        Ok(self.0.call(call).await.into())
    }
}

/// Read the secret line and take the token.
async fn read_token(stdin: &mut BufReader<tokio::io::Stdin>) -> Result<String, String> {
    let mut line = String::new();
    stdin
        .read_line(&mut line)
        .await
        .map_err(|error| format!("cannot read the secret line: {error}"))?;
    let mut parsed: SecretLine = serde_json::from_str(&line)
        .map_err(|_| "the secret line is not a secret line".to_owned())?;
    parsed
        .secrets
        .remove(HA_TOKEN)
        .ok_or_else(|| format!("the secret line has no {HA_TOKEN}"))
}

async fn run(args: Args) -> Result<(), String> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let token = read_token(&mut stdin).await?;
    let client = reqwest::Client::builder()
        .timeout(CALL_TIMEOUT)
        .build()
        .map_err(|error| format!("cannot build the HTTP client: {error}"))?;
    let shared = Shared(Arc::new(Plugin {
        url: args.url,
        token,
        client,
    }));
    let service = shared
        .serve((stdin, tokio::io::stdout()))
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
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ha-call: cannot start the runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ha-call: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_and_entity_ids_are_checked() {
        assert!(is_word("turn_on"));
        assert!(!is_word("Turn-On") && !is_word(""));
        assert!(is_entity_id("light.kitchen_1"));
        assert!(!is_entity_id("kitchen") && !is_entity_id("light.") && !is_entity_id("a.b.c"));
    }
}
