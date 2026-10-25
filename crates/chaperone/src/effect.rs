//! The effect host (`docs/design.md` 7.7). It launches each upstream with
//! the command of its manifest and speaks MCP to it over stdio as the
//! client. It checks each result before the call path returns it. Build
//! step 6 adds the approval channel.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use chaperone_core::{
    ArgValue, Catalog, PluginKind, PluginName, Policy, Runtime, SecretDelivery, Setup, ToolName,
    UpstreamResult,
};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult, Tool};
use rmcp::service::{RoleClient, RunningService, ServiceError};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStderr, Command};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

use crate::startup::Secrets;

/// The longest the host waits for one upstream call (`docs/design.md` 5.5).
pub const UPSTREAM_BUDGET: Duration = Duration::from_secs(30);

/// The most text one result may hold, over all its blocks
/// (`docs/design.md` 7.7).
pub const RESULT_CAP: usize = 1024 * 1024;

/// The longest stderr line the host logs. A longer line is cut.
const STDERR_LINE_CAP: usize = 8 * 1024;

/// The key of the secret line on stdin (`docs/design.md` 7.5).
const SECRETS_KEY: &str = "secrets";

/// One tool that an upstream lists.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamTool {
    pub name: ToolName,
    pub description: Option<String>,
    pub input_schema: BTreeMap<String, ArgValue>,
}

/// Why a call to an upstream gave no result to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamFault {
    /// The upstream is not running, or its connection is closed.
    NotConnected,
    /// The upstream answered with something that is not a tool result.
    BadResult,
}

/// A running upstream, as the call path sees it.
pub trait Upstream: Send + Sync + fmt::Debug {
    /// The tools the upstream listed at start.
    fn tools(&self) -> &[UpstreamTool];

    /// Send one `tools/call` and return the raw result. The call path
    /// bounds the wait and checks the result.
    fn call<'a>(
        &'a self,
        tool: &'a ToolName,
        arguments: BTreeMap<String, ArgValue>,
    ) -> Pin<Box<dyn Future<Output = Result<CallToolResult, UpstreamFault>> + Send + 'a>>;
}

/// Every running upstream, by plugin name.
pub type Upstreams = BTreeMap<PluginName, Box<dyn Upstream>>;

/// Every secret chaperone holds, for blanking (G9). Clones share one set.
#[derive(Debug, Clone)]
pub struct Redactor(Arc<Secrets>);

impl Redactor {
    #[must_use]
    pub fn new(secrets: Secrets) -> Self {
        Self(Arc::new(secrets))
    }

    /// `text` with each exact copy of each secret value replaced.
    #[must_use]
    pub fn blank(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for secret in self.0.values().flat_map(BTreeMap::values) {
            text = secret.blank(&text);
        }
        text
    }
}

/// Check one raw result (`docs/design.md` 7.7): text blocks only, at most
/// [`RESULT_CAP`] bytes of text, each secret value blanked.
///
/// # Errors
///
/// Returns [`UpstreamFault::BadResult`] for a block of another type or for
/// more text than the cap.
pub fn check_result(
    result: CallToolResult,
    redactor: &Redactor,
) -> Result<UpstreamResult, UpstreamFault> {
    let mut content = Vec::with_capacity(result.content.len());
    let mut total = 0_usize;
    for block in &result.content {
        let Some(text) = block.as_text() else {
            return Err(UpstreamFault::BadResult);
        };
        total = total.saturating_add(text.text.len());
        if total > RESULT_CAP {
            return Err(UpstreamFault::BadResult);
        }
        content.push(redactor.blank(&text.text));
    }
    Ok(UpstreamResult {
        content,
        is_error: result.is_error.unwrap_or(false),
    })
}

/// Why an upstream did not start. Each one refuses start (G2).
#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("{plugin} has no effect manifest with a command")]
    NoCommand { plugin: PluginName },
    #[error("{plugin} did not start: {error}")]
    Spawn {
        plugin: PluginName,
        error: std::io::Error,
    },
    #[error("{plugin} did not take its secrets on stdin: {error}")]
    SecretLine {
        plugin: PluginName,
        error: std::io::Error,
    },
    #[error("{plugin} did not complete the MCP initialize: {error}")]
    Initialize { plugin: PluginName, error: String },
    #[error("{plugin} did not list its tools: {error}")]
    ListTools { plugin: PluginName, error: String },
}

/// An upstream that runs as a child process.
pub struct ProcessUpstream {
    name: PluginName,
    tools: Vec<UpstreamTool>,
    service: RunningService<RoleClient, ()>,
    /// Held so the child is killed when the upstream is dropped.
    _child: Child,
}

impl fmt::Debug for ProcessUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessUpstream")
            .field("name", &self.name)
            .field("tools", &self.tools.len())
            .finish_non_exhaustive()
    }
}

impl Upstream for ProcessUpstream {
    fn tools(&self) -> &[UpstreamTool] {
        &self.tools
    }

    fn call<'a>(
        &'a self,
        tool: &'a ToolName,
        arguments: BTreeMap<String, ArgValue>,
    ) -> Pin<Box<dyn Future<Output = Result<CallToolResult, UpstreamFault>> + Send + 'a>> {
        Box::pin(async move {
            let members: serde_json::Map<String, serde_json::Value> = arguments
                .iter()
                .map(|(key, value)| (key.clone(), value.to_json()))
                .collect();
            let request =
                CallToolRequestParams::new(tool.as_str().to_owned()).with_arguments(members);
            match self.service.call_tool(request).await {
                Ok(result) => Ok(result),
                // An MCP error is the upstream's answer to this call.
                Err(ServiceError::McpError(error)) => Ok(CallToolResult::error(vec![
                    rmcp::model::ContentBlock::text(error.message.to_string()),
                ])),
                Err(ServiceError::TransportSend(_))
                | Err(ServiceError::TransportClosed)
                | Err(ServiceError::Cancelled { .. }) => Err(UpstreamFault::NotConnected),
                // The error enum of the library is open. Any other error is
                // an answer that is not a tool result (G2).
                Err(_) => Err(UpstreamFault::BadResult),
            }
        })
    }
}

/// Launch every active upstream of `setup`, in plugin name order
/// (`docs/design.md` 7.7).
///
/// # Errors
///
/// Returns the first [`LaunchError`] found. chaperone then refuses start.
pub async fn launch_all(
    setup: &Setup,
    catalog: &Catalog,
    redactor: &Redactor,
) -> Result<Upstreams, LaunchError> {
    let mut upstreams = Upstreams::new();
    for name in setup.upstreams() {
        let command = catalog
            .iter()
            .find(|(key, _)| key.kind == PluginKind::Effect && key.name == *name)
            .and_then(|(_, found)| match found.manifest.runtime() {
                Runtime::Process { command } => Some(command.as_slice()),
                Runtime::Compiled => None,
            })
            .ok_or_else(|| LaunchError::NoCommand {
                plugin: name.clone(),
            })?;
        let delivery = setup
            .binding(name)
            .map_or(SecretDelivery::Stdin, |binding| binding.delivery);
        let upstream = launch(name, command, delivery, redactor).await?;
        upstreams.insert(name.clone(), Box::new(upstream));
    }
    Ok(upstreams)
}

/// Launch one upstream: spawn it, hand it its secrets, initialize MCP and
/// list its tools.
///
/// # Errors
///
/// Returns the [`LaunchError`] of the step that failed.
pub async fn launch(
    name: &PluginName,
    command: &[String],
    delivery: SecretDelivery,
    redactor: &Redactor,
) -> Result<ProcessUpstream, LaunchError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| LaunchError::NoCommand {
            plugin: name.clone(),
        })?;
    let mut spawn = Command::new(program);
    spawn
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let secrets = redactor.0.get(name);
    if delivery == SecretDelivery::Env
        && let Some(secrets) = secrets
    {
        for (param, secret) in secrets {
            #[expect(
                clippy::disallowed_methods,
                reason = "G9: the env exception of docs/design.md 7.5, warned at each start"
            )]
            let value = secret.expose();
            spawn.env(param.as_str(), value);
        }
    }
    let spawn_error = |error| LaunchError::Spawn {
        plugin: name.clone(),
        error,
    };
    let mut child = spawn.spawn().map_err(spawn_error)?;
    let mut stdin = child.stdin.take().ok_or_else(|| spawn_error(no_pipe()))?;
    let stdout = child.stdout.take().ok_or_else(|| spawn_error(no_pipe()))?;
    let stderr = child.stderr.take().ok_or_else(|| spawn_error(no_pipe()))?;
    tokio::spawn(log_stderr(name.clone(), stderr, redactor.clone()));

    if delivery == SecretDelivery::Stdin
        && let Some(secrets) = secrets
        && !secrets.is_empty()
    {
        let line = secret_line(secrets);
        let written = async {
            stdin.write_all(line.as_bytes()).await?;
            stdin.flush().await
        }
        .await;
        written.map_err(|error| LaunchError::SecretLine {
            plugin: name.clone(),
            error,
        })?;
    }

    let service =
        ().serve((stdout, stdin))
            .await
            .map_err(|error| LaunchError::Initialize {
                plugin: name.clone(),
                error: redactor.blank(&error.to_string()),
            })?;
    let listed = service
        .list_all_tools()
        .await
        .map_err(|error| LaunchError::ListTools {
            plugin: name.clone(),
            error: redactor.blank(&error.to_string()),
        })?;
    let tools = listed
        .into_iter()
        .filter_map(|tool| upstream_tool(name, tool))
        .collect();
    Ok(ProcessUpstream {
        name: name.clone(),
        tools,
        service,
        _child: child,
    })
}

fn no_pipe() -> std::io::Error {
    std::io::Error::other("the child has no stdio pipe")
}

/// The first line on stdin (`docs/design.md` 7.5).
fn secret_line(secrets: &BTreeMap<chaperone_core::SecretParam, chaperone_core::Secret>) -> String {
    let values: serde_json::Map<String, serde_json::Value> = secrets
        .iter()
        .map(|(param, secret)| {
            #[expect(
                clippy::disallowed_methods,
                reason = "G9: the one place that hands a secret to its plugin, on stdin"
            )]
            let value = secret.expose();
            (
                param.as_str().to_owned(),
                serde_json::Value::String(value.to_owned()),
            )
        })
        .collect();
    let mut line = serde_json::json!({ SECRETS_KEY: values }).to_string();
    line.push('\n');
    line
}

/// One listed tool, or `None` with a warning when its name is not a tool
/// name. Such a tool can never be granted.
fn upstream_tool(plugin: &PluginName, tool: Tool) -> Option<UpstreamTool> {
    let Ok(name) = ToolName::try_new(&tool.name) else {
        tracing::warn!(%plugin, "the upstream lists a tool whose name is not a tool name");
        return None;
    };
    let input_schema = tool
        .input_schema
        .iter()
        .map(|(key, value)| (key.clone(), ArgValue::from_json(value.clone())))
        .collect();
    Some(UpstreamTool {
        name,
        description: tool.description.map(|text| text.into_owned()),
        input_schema,
    })
}

/// Log each stderr line of the plugin, with each secret value blanked
/// (G9).
async fn log_stderr(plugin: PluginName, stderr: ChildStderr, redactor: Redactor) {
    let mut lines = FramedRead::new(stderr, LinesCodec::new_with_max_length(STDERR_LINE_CAP));
    while let Some(line) = lines.next().await {
        match line {
            Ok(line) => tracing::warn!(%plugin, "{}", redactor.blank(&line)),
            Err(error) => {
                tracing::warn!(%plugin, %error, "stderr closed");
                return;
            }
        }
    }
}

/// Warn once at start for each granted tool that its upstream does not
/// list (`docs/design.md` 7.7).
pub fn warn_unlisted(policy: &Policy, upstreams: &Upstreams) {
    for (app, instance) in policy.apps() {
        for (upstream, tool) in instance.granted() {
            let listed = upstreams
                .get(upstream)
                .is_some_and(|running| running.tools().iter().any(|t| t.name == *tool));
            if !listed {
                tracing::warn!(%app, %upstream, %tool, "the policy grants a tool the upstream does not list");
            }
        }
    }
}
