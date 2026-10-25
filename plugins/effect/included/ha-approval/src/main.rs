//! The approval channel through the operator's Node-RED and Home Assistant
//! flow (`docs/design.md` section 12). The plugin serves MCP on stdio with
//! one tool, `approve`. For each gate it posts a request to the flow's
//! hook, then waits for the tap. The flow posts the tap back to `/resume`
//! on this plugin. The plugin holds the two tokens in memory only (G9).

mod ids;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, ServiceExt};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::oneshot;

use crate::ids::Gate;

/// The tool chaperone calls for each gate (`docs/design.md` 5.3).
const APPROVE_TOOL: &str = "approve";

/// The life of a gate (`docs/design.md` 5.5). A tap after it is refused.
const GATE_LIFE: Duration = Duration::from_secs(600);

/// The longest summary the push carries, in characters.
const SUMMARY_CAP: usize = 400;

/// The largest `/resume` body the plugin reads.
const RESUME_BODY_CAP: usize = 4 * 1024;

const APPROVAL_TOKEN: &str = "APPROVAL_TOKEN";
const RESUME_TOKEN: &str = "RESUME_TOKEN";

#[derive(Debug, Parser)]
#[command(name = "chaperone-ha-approval")]
struct Args {
    /// The flow's hook, such as http://127.0.0.1:1881/hook/approval.
    #[arg(long)]
    hook_url: String,
    /// Where this plugin serves POST /resume. Not an unspecified address.
    #[arg(long)]
    listen: SocketAddr,
}

/// The secret line of `docs/design.md` 7.5.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretLine {
    secrets: BTreeMap<String, String>,
}

/// The tap of the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Decision {
    Approve,
    Deny,
}

/// The body the flow posts to `/resume`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resume {
    job: String,
    gate: String,
    decision: Decision,
}

/// One gate the plugin asked about.
#[derive(Debug)]
struct Pending {
    waiter: Option<oneshot::Sender<Decision>>,
    decided: Option<Decision>,
    asked: Instant,
}

#[derive(Debug, Default)]
struct Gates {
    gates: BTreeMap<[u8; 16], Pending>,
}

impl Gates {
    fn prune(&mut self, now: Instant) {
        self.gates
            .retain(|_, pending| now.duration_since(pending.asked) < GATE_LIFE);
    }
}

/// What a tap did to its gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tap {
    /// The first tap. The waiting call is answered.
    Recorded,
    /// The same decision again.
    Repeated,
    /// The other decision. The first one stands.
    Contradicted,
    /// No such gate, or an expired one.
    Unknown,
}

struct Plugin {
    hook_url: String,
    approval_token: String,
    resume_token: String,
    client: reqwest::Client,
    gates: Mutex<Gates>,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("hook_url", &self.hook_url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct Shared(Arc<Plugin>);

/// The request the flow's hook takes.
#[derive(Debug, serde::Serialize)]
struct HookBody<'a> {
    job_id: String,
    gate_id: String,
    agent: &'a str,
    summary: String,
    kind: &'static str,
}

fn answer(text: &str) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text.to_owned())])
}

fn denied(reason: &str) -> CallToolResult {
    let body = serde_json::json!({ "answer": "denied", "reason": reason });
    answer(&body.to_string())
}

/// The text of the push: the tool and the canonical arguments, cut to
/// [`SUMMARY_CAP`] characters.
fn summary(tool: &str, arguments: Option<&serde_json::Map<String, serde_json::Value>>) -> String {
    let arguments = arguments
        .map(|members| serde_json::Value::Object(members.clone()).to_string())
        .unwrap_or_else(|| "{}".to_owned());
    format!("{tool} {arguments}")
        .chars()
        .take(SUMMARY_CAP)
        .collect()
}

fn argument_text<'a>(
    arguments: Option<&'a serde_json::Map<String, serde_json::Value>>,
    key: &str,
) -> Option<&'a str> {
    arguments?.get(key)?.as_str()
}

impl Plugin {
    /// Register the gate and wait for the tap, after the hook took the
    /// request.
    async fn ask(&self, gate: Gate, app: &str, summary: String) -> CallToolResult {
        let (sender, receiver) = oneshot::channel();
        {
            let Ok(mut gates) = self.gates.lock() else {
                return denied("the plugin's gate state is poisoned");
            };
            let now = Instant::now();
            gates.prune(now);
            if let Some(pending) = gates.gates.get(&gate.0)
                && let Some(decision) = pending.decided
            {
                return decision_answer(decision);
            }
            gates.gates.insert(
                gate.0,
                Pending {
                    waiter: Some(sender),
                    decided: None,
                    asked: now,
                },
            );
        }

        let body = HookBody {
            job_id: gate.job_id(),
            gate_id: gate.gate_id(),
            agent: app,
            summary,
            kind: "approval",
        };
        let sent = self
            .client
            .post(&self.hook_url)
            .bearer_auth(&self.approval_token)
            .json(&body)
            .send()
            .await;
        match sent {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                self.forget(gate);
                eprintln!(
                    "ha-approval: the hook refused the request with HTTP {}",
                    response.status()
                );
                return denied("the approval request did not reach the phone");
            }
            Err(error) => {
                self.forget(gate);
                eprintln!(
                    "ha-approval: the hook is not reachable: {}",
                    error.without_url()
                );
                return denied("the approval request did not reach the phone");
            }
        }

        match tokio::time::timeout(GATE_LIFE, receiver).await {
            Ok(Ok(decision)) => decision_answer(decision),
            Ok(Err(_)) => denied("the gate was dropped before the tap"),
            Err(_) => {
                self.forget(gate);
                denied("no tap came in the life of the gate")
            }
        }
    }

    fn forget(&self, gate: Gate) {
        if let Ok(mut gates) = self.gates.lock() {
            gates.gates.remove(&gate.0);
        }
    }

    /// Record the tap on its gate.
    fn resume(&self, gate: Gate, decision: Decision) -> Tap {
        let Ok(mut gates) = self.gates.lock() else {
            return Tap::Unknown;
        };
        gates.prune(Instant::now());
        let Some(pending) = gates.gates.get_mut(&gate.0) else {
            return Tap::Unknown;
        };
        match pending.decided {
            Some(earlier) if earlier == decision => Tap::Repeated,
            Some(_) => Tap::Contradicted,
            None => {
                pending.decided = Some(decision);
                if let Some(waiter) = pending.waiter.take() {
                    // A receiver that is gone has already answered chaperone.
                    let _ = waiter.send(decision);
                }
                Tap::Recorded
            }
        }
    }

    fn bearer_matches(&self, headers: &HeaderMap) -> bool {
        let Some(given) = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.strip_prefix("Bearer "))
        else {
            return false;
        };
        let given = given.trim().as_bytes();
        let expected = self.resume_token.as_bytes();
        given.len() == expected.len() && bool::from(given.ct_eq(expected))
    }
}

fn decision_answer(decision: Decision) -> CallToolResult {
    match decision {
        Decision::Approve => answer(r#"{"answer":"approved"}"#),
        Decision::Deny => denied("denied on the phone"),
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
        let mut schema = serde_json::Map::new();
        schema.insert(
            "type".to_owned(),
            serde_json::Value::String("object".to_owned()),
        );
        let tool = Tool::new_with_raw(
            APPROVE_TOOL,
            Some("Asks the operator's phone about one gate".into()),
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
        let arguments = request.arguments.as_ref();
        let Some(gate) = argument_text(arguments, "gate").and_then(Gate::from_hex) else {
            return Err(ErrorData::invalid_params(
                "gate is not 32 hex characters",
                None,
            ));
        };
        let Some(app) = argument_text(arguments, "app") else {
            return Err(ErrorData::invalid_params("app is missing", None));
        };
        let tool = argument_text(arguments, "tool").unwrap_or("");
        let call_arguments = arguments
            .and_then(|members| members.get("arguments"))
            .and_then(|value| value.as_object());
        let text = summary(tool, call_arguments);
        Ok(self.0.ask(gate, app, text).await.into())
    }
}

async fn resume_handler(
    State(shared): State<Shared>,
    headers: HeaderMap,
    body: Result<Json<Resume>, axum::extract::rejection::JsonRejection>,
) -> (StatusCode, Json<serde_json::Value>) {
    let reply =
        |status: StatusCode, text: &str| (status, Json(serde_json::json!({ "status": text })));
    if !shared.0.bearer_matches(&headers) {
        return reply(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(Json(resume)) = body else {
        return reply(StatusCode::BAD_REQUEST, "the body is not a resume");
    };
    let Some(gate) = Gate::from_job_id(&resume.job) else {
        return reply(StatusCode::BAD_REQUEST, "job is not a job id");
    };
    if gate.gate_id() != resume.gate {
        return reply(StatusCode::BAD_REQUEST, "gate does not match job");
    }
    match shared.0.resume(gate, resume.decision) {
        Tap::Recorded => reply(StatusCode::OK, "resumed"),
        Tap::Repeated => reply(StatusCode::OK, "already_decided"),
        Tap::Contradicted => reply(StatusCode::CONFLICT, "already_decided_otherwise"),
        Tap::Unknown => reply(StatusCode::NOT_FOUND, "unknown gate"),
    }
}

/// Read the secret line and take the two tokens.
async fn read_secrets(stdin: &mut BufReader<tokio::io::Stdin>) -> Result<(String, String), String> {
    let mut line = String::new();
    stdin
        .read_line(&mut line)
        .await
        .map_err(|error| format!("cannot read the secret line: {error}"))?;
    let mut parsed: SecretLine = serde_json::from_str(&line)
        .map_err(|_| "the secret line is not a secret line".to_owned())?;
    let approval = parsed
        .secrets
        .remove(APPROVAL_TOKEN)
        .ok_or_else(|| format!("the secret line has no {APPROVAL_TOKEN}"))?;
    let resume = parsed
        .secrets
        .remove(RESUME_TOKEN)
        .ok_or_else(|| format!("the secret line has no {RESUME_TOKEN}"))?;
    Ok((approval, resume))
}

async fn run(args: Args) -> Result<(), String> {
    if args.listen.ip().is_unspecified() {
        return Err("--listen must not be an unspecified address".to_owned());
    }
    let mut stdin = BufReader::new(tokio::io::stdin());
    let (approval_token, resume_token) = read_secrets(&mut stdin).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| format!("cannot build the HTTP client: {error}"))?;
    let shared = Shared(Arc::new(Plugin {
        hook_url: args.hook_url,
        approval_token,
        resume_token,
        client,
        gates: Mutex::new(Gates::default()),
    }));

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|error| format!("cannot bind {}: {error}", args.listen))?;
    let router = Router::new()
        .route("/resume", post(resume_handler))
        .layer(DefaultBodyLimit::max(RESUME_BODY_CAP))
        .with_state(shared.clone());
    let server = tokio::spawn(axum::serve(listener, router).into_future());
    eprintln!("ha-approval: serving /resume on {}", args.listen);

    let service = shared
        .serve((stdin, tokio::io::stdout()))
        .await
        .map_err(|error| format!("the MCP initialize failed: {error}"))?;
    service
        .waiting()
        .await
        .map_err(|error| format!("the service task failed: {error}"))?;
    server.abort();
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
            eprintln!("ha-approval: cannot start the runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ha-approval: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_holds_the_tool_and_the_arguments_and_is_cut() {
        let mut members = serde_json::Map::new();
        members.insert("n".to_owned(), serde_json::Value::from(1));
        assert_eq!(
            summary("vikunja__create_task", Some(&members)),
            "vikunja__create_task {\"n\":1}"
        );
        assert_eq!(summary("t", None), "t {}");
        let long = "x".repeat(SUMMARY_CAP * 2);
        assert_eq!(summary(&long, None).chars().count(), SUMMARY_CAP);
    }

    #[test]
    fn a_denial_answer_is_strict_json() {
        let result = denied("why");
        let text = result.content[0].as_text().unwrap().text.clone();
        assert_eq!(text, r#"{"answer":"denied","reason":"why"}"#);
    }
}
