//! The policy editor (`docs/design.md` 11). It serves HTML forms over
//! `policy.json` on its own loopback port, behind its own admin token. It
//! builds every form from the schema the chaperone admin socket returns,
//! and it saves only after that socket's check passes. It never reads a
//! secret, never writes `install.json` and never links `crates/core`.

mod form;
mod socket;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use base64::Engine as _;
use clap::Parser;
use serde_json::Value;
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

use crate::form::{Action, Schemas, escape};
use crate::socket::AdminSocket;

/// The largest posted form the editor reads.
const FORM_CAP: usize = 4 * 1024 * 1024;

/// The file the editor edits, inside the configuration directory.
const POLICY_FILE: &str = "policy.json";

#[derive(Debug, Parser)]
#[command(name = "chaperone-editor")]
struct Args {
    /// Where to serve. Loopback, or a LAN address. Not an unspecified
    /// address.
    #[arg(long, default_value = "127.0.0.1:8301")]
    listen: SocketAddr,
    /// The chaperone admin socket.
    #[arg(long)]
    admin_socket: PathBuf,
    /// The directory that holds policy.json.
    #[arg(long)]
    config_dir: PathBuf,
    /// The file that holds the editor's admin token: one line.
    #[arg(long)]
    token_file: PathBuf,
}

struct Editor {
    socket: AdminSocket,
    config_dir: PathBuf,
    token: String,
    origin: String,
}

impl std::fmt::Debug for Editor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Editor")
            .field("config_dir", &self.config_dir)
            .finish_non_exhaustive()
    }
}

type Shared = Arc<Editor>;

/// Whether the request carries the editor's token as HTTP basic auth.
fn authorized(editor: &Editor, headers: &HeaderMap) -> bool {
    let Some(given) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.strip_prefix("Basic "))
        .and_then(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        return false;
    };
    // The user name is free. The password is the token.
    let password = given.split_once(':').map_or(given.as_str(), |(_, p)| p);
    let expected = editor.token.as_bytes();
    password.len() == expected.len() && bool::from(password.as_bytes().ct_eq(expected))
}

fn challenge() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"chaperone editor\"")],
        "the editor's admin token is the password",
    )
        .into_response()
}

/// Whether a posted form came from this editor's own pages.
fn same_origin(editor: &Editor, headers: &HeaderMap) -> bool {
    let source = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|value| value.to_str().ok());
    source.is_some_and(|source| source.starts_with(&editor.origin))
}

fn page(title: &str, notices: &[(bool, String)], body: &str) -> Html<String> {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>");
    html.push_str(&escape(title));
    html.push_str(
        "</title><style>\
         body{font:15px/1.4 system-ui,sans-serif;max-width:60rem;margin:1.5rem auto;padding:0 1rem}\
         fieldset{border:1px solid #bbb;margin:.6rem 0;padding:.6rem}\
         legend{font-weight:600}.field{margin:.4rem 0}.label,label{display:inline-block;min-width:12rem}\
         input,select,textarea{font:inherit;padding:.15rem .3rem}textarea{width:100%;max-width:40rem;vertical-align:top}\
         .help{margin:.1rem 0 .3rem 12rem;color:#555;font-size:.9em;white-space:pre-line}\
         .entry{border-left:3px solid #ddd;padding-left:.6rem;margin:.6rem 0}.remove{float:right}\
         .notice{padding:.5rem .8rem;margin:.6rem 0;border-radius:4px}\
         .ok{background:#e6f4ea}.bad{background:#fbe9e7}.bar button{margin-right:.6rem}\
         .token{font-family:monospace;word-break:break-all;background:#fff8c5;padding:.5rem}\
         </style></head><body><h1>",
    );
    html.push_str(&escape(title));
    html.push_str("</h1>");
    for (ok, text) in notices {
        let class = if *ok { "ok" } else { "bad" };
        html.push_str(&format!(
            "<div class=\"notice {class}\">{}</div>",
            escape(text)
        ));
    }
    html.push_str(body);
    html.push_str("</body></html>");
    Html(html)
}

impl Editor {
    fn policy_path(&self) -> PathBuf {
        self.config_dir.join(POLICY_FILE)
    }

    async fn schemas(&self) -> Result<Schemas, String> {
        let answer = self
            .socket
            .schema()
            .await
            .map_err(|error| error.to_string())?;
        if answer.status != 200 {
            return Err(format!("the admin socket answered HTTP {}", answer.status));
        }
        let mut body = answer.body;
        let sections = body
            .as_object_mut()
            .and_then(|o| o.remove("sections"))
            .and_then(|s| s.as_object().cloned())
            .unwrap_or_default();
        let file = body
            .get(POLICY_FILE)
            .cloned()
            .ok_or_else(|| "the schema has no policy.json".to_owned())?;
        Ok(Schemas { file, sections })
    }

    fn read_policy(&self) -> Result<Value, String> {
        let bytes = std::fs::read(self.policy_path())
            .map_err(|error| format!("cannot read {POLICY_FILE}: {error}"))?;
        serde_json::from_slice(&bytes).map_err(|_| format!("{POLICY_FILE} is not JSON"))
    }

    /// The text of a draft as it would be saved.
    fn text_of(draft: &Value) -> String {
        let mut text = serde_json::to_string_pretty(draft).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Ask the admin socket about a draft. `Ok(())` when it passes.
    async fn check(&self, text: &str) -> Result<(), String> {
        let answer = self
            .socket
            .check(POLICY_FILE, text)
            .await
            .map_err(|error| error.to_string())?;
        if answer.status == 200 && answer.body["ok"] == true {
            return Ok(());
        }
        Err(answer.body["error"].as_str().map_or_else(
            || format!("the check answered HTTP {}", answer.status),
            str::to_owned,
        ))
    }

    /// Keep the previous file, write the new one beside it, rename it into
    /// place (`docs/design.md` 11).
    fn write_policy(&self, text: &str) -> Result<(), String> {
        let path = self.policy_path();
        let previous = self.config_dir.join(format!("{POLICY_FILE}.prev"));
        let temporary = self.config_dir.join(format!("{POLICY_FILE}.tmp"));
        if let Ok(old) = std::fs::read(&path) {
            std::fs::write(&previous, old)
                .map_err(|error| format!("cannot keep the previous file: {error}"))?;
        }
        std::fs::write(&temporary, text)
            .map_err(|error| format!("cannot write the new file: {error}"))?;
        std::fs::rename(&temporary, &path)
            .map_err(|error| format!("cannot rename the new file: {error}"))
    }

    fn render(&self, schemas: &Schemas, draft: &Value, notices: &[(bool, String)]) -> Html<String> {
        let fields = form::render_policy(schemas, draft);
        let apps: Vec<&str> = draft
            .get("apps")
            .and_then(Value::as_object)
            .map(|apps| apps.keys().map(String::as_str).collect())
            .unwrap_or_default();
        let mut tokens = String::new();
        for app in apps {
            tokens.push_str(&format!(
                "<button name=\"action\" value=\"token:{0}\" formaction=\"/token\">New token for {0}</button> ",
                escape(app)
            ));
        }
        let body = format!(
            "<form method=\"post\" action=\"/policy\">\
             <input type=\"hidden\" name=\"draft\" value=\"{}\">\
             {fields}\
             <div class=\"bar\"><button name=\"action\" value=\"check\">Check</button>\
             <button name=\"action\" value=\"save\">Check and save</button></div>\
             <p>A new token is shown once and its digest is stored at once. The form above is then shown from the saved file.</p>\
             <div class=\"bar\">{tokens}</div>\
             </form>",
            escape(&draft.to_string())
        );
        page("chaperone policy", notices, &body)
    }
}

async fn root() -> Redirect {
    Redirect::to("/policy")
}

async fn show(State(editor): State<Shared>, headers: HeaderMap) -> Response {
    if !authorized(&editor, &headers) {
        return challenge();
    }
    let schemas = match editor.schemas().await {
        Ok(schemas) => schemas,
        Err(error) => return page("chaperone policy", &[(false, error)], "").into_response(),
    };
    match editor.read_policy() {
        Ok(draft) => editor.render(&schemas, &draft, &[]).into_response(),
        Err(error) => page("chaperone policy", &[(false, error)], "").into_response(),
    }
}

fn fields_of(body: &Bytes) -> Vec<(String, String)> {
    serde_urlencoded::from_bytes::<Vec<(String, String)>>(body).unwrap_or_default()
}

async fn edit(State(editor): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&editor, &headers) {
        return challenge();
    }
    if !same_origin(&editor, &headers) {
        return (StatusCode::FORBIDDEN, "the form must come from this editor").into_response();
    }
    let schemas = match editor.schemas().await {
        Ok(schemas) => schemas,
        Err(error) => return page("chaperone policy", &[(false, error)], "").into_response(),
    };
    let fields = fields_of(&body);
    let (draft, action) = match form::apply(&fields) {
        Ok(applied) => applied,
        Err(error) => {
            let draft = editor.read_policy().unwrap_or(Value::Null);
            return editor
                .render(&schemas, &draft, &[(false, error.to_string())])
                .into_response();
        }
    };
    let text = Editor::text_of(&draft);
    let notices = match action {
        Action::Edit => Vec::new(),
        Action::Check => match editor.check(&text).await {
            Ok(()) => vec![(true, "The check passed. Nothing is saved yet.".to_owned())],
            Err(error) => vec![(false, format!("The check failed: {error}"))],
        },
        Action::Save => match editor.check(&text).await {
            Ok(()) => match editor.write_policy(&text) {
                Ok(()) => vec![(
                    true,
                    "Saved. The previous file is policy.json.prev.".to_owned(),
                )],
                Err(error) => vec![(false, error)],
            },
            Err(error) => vec![(false, format!("Not saved. The check failed: {error}"))],
        },
    };
    editor.render(&schemas, &draft, &notices).into_response()
}

async fn token(State(editor): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&editor, &headers) {
        return challenge();
    }
    if !same_origin(&editor, &headers) {
        return (StatusCode::FORBIDDEN, "the form must come from this editor").into_response();
    }
    let fields = fields_of(&body);
    let Some(app) = fields
        .iter()
        .find(|(name, _)| name == "action")
        .and_then(|(_, value)| value.strip_prefix("token:"))
    else {
        return (StatusCode::BAD_REQUEST, "no app named").into_response();
    };
    let notice = match editor.socket.token(app).await {
        Ok(answer) if answer.status == 200 => match answer.body["token"].as_str() {
            Some(token) => (
                true,
                format!("The new token for {app}, shown once: {token}"),
            ),
            None => (false, "the admin socket sent no token".to_owned()),
        },
        Ok(answer) => (
            false,
            answer.body["error"].as_str().map_or_else(
                || format!("no token: HTTP {}", answer.status),
                |text| format!("no token: {text}"),
            ),
        ),
        Err(error) => (false, error.to_string()),
    };
    let schemas = match editor.schemas().await {
        Ok(schemas) => schemas,
        Err(error) => {
            return page("chaperone policy", &[notice, (false, error)], "").into_response();
        }
    };
    match editor.read_policy() {
        Ok(draft) => editor.render(&schemas, &draft, &[notice]).into_response(),
        Err(error) => page("chaperone policy", &[notice, (false, error)], "").into_response(),
    }
}

/// The router of the editor over `editor`.
fn router(editor: Shared) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/policy", get(show).post(edit))
        .route("/token", axum::routing::post(token))
        .layer(axum::extract::DefaultBodyLimit::max(FORM_CAP))
        .with_state(editor)
}

fn read_token(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read the token file {}: {error}", path.display()))?;
    let token = text.trim().to_owned();
    if token.is_empty() {
        return Err("the token file is empty".to_owned());
    }
    Ok(token)
}

async fn run(args: Args) -> Result<(), String> {
    if args.listen.ip().is_unspecified() {
        return Err("--listen must not be an unspecified address".to_owned());
    }
    let token = read_token(&args.token_file)?;
    let editor = Arc::new(Editor {
        socket: AdminSocket::new(args.admin_socket),
        config_dir: args.config_dir,
        token,
        origin: format!("http://{}", args.listen),
    });
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|error| format!("cannot bind {}: {error}", args.listen))?;
    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown.cancel();
        }
    });
    eprintln!("chaperone-editor: serving on http://{}/policy", args.listen);
    axum::serve(listener, router(editor))
        .with_graceful_shutdown(async move { shutdown.cancelled_owned().await })
        .await
        .map_err(|error| format!("the server stopped: {error}"))
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("chaperone-editor: cannot start the runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chaperone-editor: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
