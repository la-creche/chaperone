//! The admin functions (`docs/design.md` 10): the check and the token. The
//! CLI and the admin socket call the same two functions, so they cannot
//! drift. The socket is a Unix socket for the owner and the group of its
//! file. It is never on the front-door port.

use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use chaperone_core::{
    AppId, INSTALL_FILE_CAP, NameError, POLICY_FILE_CAP, PolicyError, TokenDigest, with_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use crate::files::{self, ReadError};
use crate::startup::{self, StartError};

/// The file name of the install file in a configuration directory.
pub const INSTALL_FILE: &str = "install.toml";
/// The file name of the policy file in a configuration directory.
pub const POLICY_FILE: &str = "policy.toml";

/// The mode of the admin socket: the owner and the group, nobody else.
const SOCKET_MODE: u32 = 0o660;

/// The largest request body the admin socket reads: a policy file plus
/// its JSON wrapping.
const BODY_CAP: usize = 2 * 1024 * 1024;

/// One of the two files the operator writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFile {
    Install,
    Policy,
}

impl ConfigFile {
    /// The file name, as a configuration directory holds it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Install => INSTALL_FILE,
            Self::Policy => POLICY_FILE,
        }
    }
}

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A file name that is neither configuration file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the file to check is {INSTALL_FILE} or {POLICY_FILE}, not {0}")]
pub struct NotConfigFile(String);

impl FromStr for ConfigFile {
    type Err = NotConfigFile;

    fn from_str(name: &str) -> Result<Self, NotConfigFile> {
        match name {
            INSTALL_FILE => Ok(Self::Install),
            POLICY_FILE => Ok(Self::Policy),
            other => Err(NotConfigFile(other.to_owned())),
        }
    }
}

/// Why a file does not pass the check.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error(transparent)]
    Start(#[from] StartError),
    /// `policy.toml` loads, but refuses these apps. One line for each app.
    #[error("{0}")]
    Refused(String),
}

/// `chaperone check` and `POST /check`: the strict reader and every
/// cross-file rule over `bytes` as the file `file`. The other files come
/// from `config_dir` and `plugins_dir`.
///
/// # Errors
///
/// Returns the first [`CheckError`] found.
pub fn check(
    file: ConfigFile,
    bytes: &[u8],
    config_dir: &Path,
    plugins_dir: &Path,
) -> Result<(), CheckError> {
    match file {
        ConfigFile::Install => {
            startup::setup_from(bytes, plugins_dir)?;
        }
        ConfigFile::Policy => {
            let install = files::read_capped(&config_dir.join(INSTALL_FILE), INSTALL_FILE_CAP)?;
            let (_, setup) = startup::setup_from(&install, plugins_dir)?;
            let policy = startup::policy_from(bytes, &setup)?;
            let lines: Vec<String> = policy
                .refused()
                .map(|(app, error)| format!("the app {app} is refused: {error}"))
                .collect();
            if !lines.is_empty() {
                return Err(CheckError::Refused(lines.join("\n")));
            }
        }
    }
    Ok(())
}

/// A bearer token, shown once. `Debug` hides it (G9).
pub struct Token(String);

impl Token {
    /// The token text: 64 lower-case hex characters. Print it once.
    #[must_use]
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

/// Why no token was made.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("the app ID is not valid: {0}")]
    App(#[from] NameError),
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("the OS random source failed: {0}")]
    Random(getrandom::Error),
    #[error("cannot write {}: {error}", path.display())]
    Write {
        path: PathBuf,
        error: std::io::Error,
    },
}

/// `chaperone token new` and `POST /token` (`docs/design.md` 9): a token
/// for `app`, its digest added to `policy.toml` in `config_dir`. The
/// previous file stays as `policy.toml.prev`. The new file lands by an
/// atomic rename.
///
/// # Errors
///
/// Returns the first [`TokenError`] found. The policy file is untouched
/// then.
pub fn token_new(config_dir: &Path, app: &str) -> Result<Token, TokenError> {
    let app = AppId::try_new(app)?;
    let path = config_dir.join(POLICY_FILE);
    let before = files::read_capped(&path, POLICY_FILE_CAP)?;

    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(TokenError::Random)?;
    let token = hex::encode(bytes);
    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let after = with_digest(&before, &app, TokenDigest::from_bytes(digest))?;

    let write = |path: &Path, error| TokenError::Write {
        path: path.to_owned(),
        error,
    };
    let previous = config_dir.join(format!("{POLICY_FILE}.prev"));
    std::fs::write(&previous, &before).map_err(|error| write(&previous, error))?;
    let temporary = config_dir.join(format!("{POLICY_FILE}.tmp"));
    std::fs::write(&temporary, &after).map_err(|error| write(&temporary, error))?;
    std::fs::rename(&temporary, &path).map_err(|error| write(&path, error))?;
    Ok(Token(token))
}

/// Where the admin socket finds the configuration.
#[derive(Debug, Clone)]
struct Dirs {
    config_dir: PathBuf,
    plugins_dir: PathBuf,
}

/// The body of `POST /check`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckRequest {
    /// `install.toml` or `policy.toml`.
    file: String,
    /// The candidate text of that file.
    content: String,
}

/// The body of `POST /token`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    app: String,
}

/// The answer of `POST /check` and the error answer of `POST /token`.
#[derive(Debug, Serialize)]
struct Verdict {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn verdict(result: Result<(), String>) -> (StatusCode, Json<Verdict>) {
    match result {
        Ok(()) => (
            StatusCode::OK,
            Json(Verdict {
                ok: true,
                error: None,
            }),
        ),
        Err(error) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(Verdict {
                ok: false,
                error: Some(error),
            }),
        ),
    }
}

async fn check_handler(
    State(dirs): State<Dirs>,
    Json(request): Json<CheckRequest>,
) -> (StatusCode, Json<Verdict>) {
    let result = ConfigFile::from_str(&request.file)
        .map_err(|error| error.to_string())
        .and_then(|file| {
            check(
                file,
                request.content.as_bytes(),
                &dirs.config_dir,
                &dirs.plugins_dir,
            )
            .map_err(|error| error.to_string())
        });
    verdict(result)
}

/// The answer of `POST /token`.
#[derive(Debug, Serialize)]
struct Minted {
    token: String,
}

async fn token_handler(
    State(dirs): State<Dirs>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<Minted>, (StatusCode, Json<Verdict>)> {
    match token_new(&dirs.config_dir, &request.app) {
        Ok(token) => Ok(Json(Minted {
            token: token.reveal().to_owned(),
        })),
        Err(error) => Err(verdict(Err(error.to_string()))),
    }
}

/// Serve the admin socket at `path` until `shutdown` is cancelled. A stale
/// socket file at `path` is replaced. The file gets mode 0660, so the
/// owner and the group open it and nobody else.
///
/// # Errors
///
/// Returns the I/O error of the bind or of the server.
pub async fn serve_socket(
    path: PathBuf,
    config_dir: PathBuf,
    plugins_dir: PathBuf,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    let router = Router::new()
        .route("/check", post(check_handler))
        .route("/token", post(token_handler))
        .layer(axum::extract::DefaultBodyLimit::max(BODY_CAP))
        .with_state(Dirs {
            config_dir,
            plugins_dir,
        });
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { shutdown.cancelled_owned().await })
        .await
}
