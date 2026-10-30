//! The command line (`docs/design.md` 10). `chaperone serve` loads the
//! configuration, then serves the front door and the admin socket until
//! SIGINT or SIGTERM. The other commands work with the service down, so a
//! broken policy can be fixed.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use chaperone::admin::{self, ConfigFile};
use chaperone::approval::ApprovalChannel;
use chaperone::effect::{self, Redactor};
use chaperone::env_file::{DEFAULT_LISTEN_KEY, EnvKey};
use chaperone::gateway::{Bounds, ChaperoneGateway, Plugins, SharedGateway};
use chaperone::registry::AuditMode;
use chaperone::reload::PolicyFile;
use chaperone::{startup, verify};
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(
    name = "chaperone",
    version,
    about = "A deterministic policy layer between an agent app and its tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load the configuration and serve the front door and the admin socket.
    Serve(Serve),
    /// Run the strict reader and every cross-file rule over one file.
    Check(Check),
    /// Tokens of app instances.
    Token(TokenCommand),
    /// Check the configuration and probe the running front door. Exit 0
    /// when every check passes.
    Verify(Verify),
}

#[derive(Debug, clap::Args)]
struct Verify {
    /// The directory that holds install.toml and policy.toml.
    #[arg(long, default_value = DEFAULT_CONFIG_DIR)]
    config_dir: PathBuf,
    /// The plugin tree: default/, then <kind>/included and <kind>/added.
    #[arg(long, default_value = DEFAULT_PLUGINS_DIR)]
    plugins_dir: PathBuf,
    /// The front door address that `chaperone serve` listens on. Cannot be
    /// used with --env-file.
    #[arg(long, default_value = DEFAULT_LISTEN, conflicts_with = "env_file")]
    listen: SocketAddr,
    /// An env file of the service: one KEY=VALUE per line, # comments and
    /// empty lines. The front door address is the value of --listen-key.
    #[arg(long)]
    env_file: Option<PathBuf>,
    /// The key of the front door address in the env file.
    #[arg(long, default_value = DEFAULT_LISTEN_KEY, requires = "env_file")]
    listen_key: EnvKey,
    /// Print one JSON object instead of one line per check.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
struct Check {
    /// The file: install.toml or policy.toml, in its configuration
    /// directory.
    file: PathBuf,
    /// The plugin tree: default/, then <kind>/included and <kind>/added.
    #[arg(long, default_value = DEFAULT_PLUGINS_DIR)]
    plugins_dir: PathBuf,
}

#[derive(Debug, clap::Args)]
struct TokenCommand {
    #[command(subcommand)]
    action: TokenAction,
}

#[derive(Debug, Subcommand)]
enum TokenAction {
    /// Create a token for an app instance and store its digest in
    /// policy.toml. The token is printed once.
    New(TokenNew),
}

#[derive(Debug, clap::Args)]
struct TokenNew {
    /// The app ID in policy.toml.
    app: String,
    /// The directory that holds policy.toml.
    #[arg(long, default_value = DEFAULT_CONFIG_DIR)]
    config_dir: PathBuf,
}

#[derive(Debug, clap::Args)]
struct Serve {
    /// The directory that holds install.toml and policy.toml.
    #[arg(long, default_value = DEFAULT_CONFIG_DIR)]
    config_dir: PathBuf,
    /// The plugin tree: default/, then <kind>/included and <kind>/added.
    #[arg(long, default_value = DEFAULT_PLUGINS_DIR)]
    plugins_dir: PathBuf,
    /// The audit file. chaperone creates it with the --audit-mode.
    #[arg(long)]
    audit_file: PathBuf,
    /// The mode of the audit file: 0600 or 0640. 0600 lets only the
    /// chaperone user read the audit, under a directory of mode 0700. 0640
    /// lets the group of the file read it too, under a directory of mode
    /// 0750. With 0640, chaperone sets a file of mode 0600 to 0640. It
    /// refuses a file of any other mode.
    #[arg(long, default_value = "0600")]
    audit_mode: AuditMode,
    /// The secrets directory: one file per secret, mode 0600, owned by the
    /// user that runs chaperone.
    #[arg(long)]
    secrets_dir: PathBuf,
    /// The admin socket path. chaperone creates it with mode 0660.
    #[arg(long)]
    admin_socket: PathBuf,
    /// The front door address. A LAN address needs the guard
    /// host-firewall in install.toml.
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: SocketAddr,
    /// A Host header value to accept, such as host.docker.internal:8300.
    /// Loopback hosts are always accepted. Repeat for more.
    #[arg(long = "allowed-host")]
    allowed_hosts: Vec<String>,
}

/// The configuration directory of the production layout
/// (`docs/design.md` 8).
const DEFAULT_CONFIG_DIR: &str = "/etc/chaperone";

/// The plugin tree of the production layout (`docs/design.md` 8).
const DEFAULT_PLUGINS_DIR: &str = "/etc/chaperone/plugins";

/// The front door address when no `--listen` is given.
const DEFAULT_LISTEN: &str = "127.0.0.1:8300";

/// The `Host` values the front door accepts without a flag.
const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

fn main() -> ExitCode {
    // A second subscriber would refuse. The first one then keeps logging.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .try_init();
    let Cli { command } = Cli::parse();
    match command {
        Command::Serve(args) => serve(args),
        Command::Check(args) => check(&args),
        Command::Token(TokenCommand {
            action: TokenAction::New(args),
        }) => token_new(&args),
        Command::Verify(args) => verify(&args),
    }
}

fn verify(args: &Verify) -> ExitCode {
    let target = match &args.env_file {
        Some(path) => verify::Target::EnvFile {
            path,
            key: &args.listen_key,
        },
        None => verify::Target::Listen(args.listen),
    };
    let report = verify::run(&args.config_dir, &args.plugins_dir, target);
    if args.json {
        println!("{}", report.json());
    } else {
        print!("{}", report.lines());
    }
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn check(args: &Check) -> ExitCode {
    let name = args
        .file
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let file: ConfigFile = match name.parse() {
        Ok(file) => file,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let config_dir = args.file.parent().unwrap_or(std::path::Path::new("."));
    let bytes = match std::fs::read(&args.file) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {}: {error}", args.file.display());
            return ExitCode::FAILURE;
        }
    };
    match admin::check(file, &bytes, config_dir, &args.plugins_dir) {
        Ok(()) => {
            println!("{file}: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{file}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn token_new(args: &TokenNew) -> ExitCode {
    match admin::token_new(&args.config_dir, &args.app) {
        Ok(token) => {
            println!("{}", token.reveal());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("no token: {error}");
            ExitCode::FAILURE
        }
    }
}

fn serve(args: Serve) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "cannot start the runtime");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run(args))
}

async fn run(args: Serve) -> ExitCode {
    let Serve {
        config_dir,
        plugins_dir,
        audit_file,
        audit_mode,
        secrets_dir,
        admin_socket,
        listen,
        mut allowed_hosts,
    } = args;

    let mut loaded = match startup::load(
        &config_dir,
        &plugins_dir,
        &audit_file,
        audit_mode,
        &secrets_dir,
    ) {
        Ok(loaded) => loaded,
        Err(error) => {
            tracing::error!(%error, "refusing to start");
            return ExitCode::FAILURE;
        }
    };
    match startup::check_listen(listen, loaded.setup.guard()) {
        Ok(warning) => loaded.warnings.extend(warning),
        Err(error) => {
            tracing::error!(%error, "refusing to start");
            return ExitCode::FAILURE;
        }
    }
    for warning in &loaded.warnings {
        tracing::warn!(%warning);
    }
    let redactor = Redactor::new(loaded.secrets);
    let launched = match effect::launch_all(&loaded.setup, &loaded.catalog, &redactor).await {
        Ok(launched) => launched,
        Err(error) => {
            tracing::error!(%error, "refusing to start");
            return ExitCode::FAILURE;
        }
    };
    for (upstream, error) in &launched.down {
        tracing::error!(%upstream, %error, "the upstream is down, and each app granted it is refused");
    }
    if !launched.down.is_empty() {
        let down = launched.down.keys().cloned().collect();
        match startup::mark_down(&loaded.setup, &loaded.policy_bytes, &down) {
            Ok((setup, policy)) => {
                loaded.setup = setup;
                loaded.policy = policy;
            }
            Err(error) => {
                tracing::error!(%error, "refusing to start");
                return ExitCode::FAILURE;
            }
        }
        for warning in startup::down_warnings(&loaded.policy) {
            tracing::warn!(%warning);
        }
    }
    effect::warn_unlisted(&loaded.policy, &launched.upstreams);
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, %listen, "cannot bind the front door");
            return ExitCode::FAILURE;
        }
    };

    allowed_hosts.extend(LOOPBACK_HOSTS.map(str::to_owned));
    let gateway = Arc::new(SharedGateway::new(ChaperoneGateway::new(
        loaded.run,
        PolicyFile::new(
            &config_dir,
            loaded.setup,
            loaded.policy,
            loaded.policy_stamp,
        ),
        Plugins {
            identity: loaded.identity,
            audit: loaded.audit,
            clock: loaded.clock,
            upstreams: launched.upstreams,
            approval: ApprovalChannel::new(launched.approval),
            redactor,
        },
        Bounds::DEFAULT,
    )));
    let shutdown = CancellationToken::new();
    tokio::spawn(shutdown_on_signal(shutdown.clone()));
    let admin = tokio::spawn(admin::serve_socket(
        admin_socket.clone(),
        config_dir,
        plugins_dir,
        shutdown.clone(),
    ));
    tracing::info!(socket = %admin_socket.display(), "serving the admin socket");

    tracing::info!(%listen, run = %loaded.run, "serving the front door");
    let front = chaperone_plugin_mcp_http::serve(gateway, listener, allowed_hosts, shutdown).await;
    let admin = admin.await;
    match (front, admin) {
        (Ok(()), Ok(Ok(()))) => ExitCode::SUCCESS,
        (Err(error), _) => {
            tracing::error!(%error, "the front door stopped");
            ExitCode::FAILURE
        }
        (Ok(()), Ok(Err(error))) => {
            tracing::error!(%error, "the admin socket stopped");
            ExitCode::FAILURE
        }
        (Ok(()), Err(error)) => {
            tracing::error!(%error, "the admin socket task did not return");
            ExitCode::FAILURE
        }
    }
}

/// Cancel `shutdown` on SIGINT or SIGTERM.
async fn shutdown_on_signal(shutdown: CancellationToken) {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
    shutdown.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        Cli::try_parse_from(std::iter::once("chaperone").chain(args.iter().copied()))
            .unwrap()
            .command
    }

    #[test]
    fn verify_takes_the_release_tool_command_with_the_layout_dirs() {
        let Command::Verify(args) = parse(&[
            "verify",
            "--json",
            "--env-file",
            "/etc/creche/site.env",
            "--listen-key",
            "CHAPERONE_LISTEN",
        ]) else {
            panic!("not verify");
        };
        assert_eq!(args.config_dir, PathBuf::from(DEFAULT_CONFIG_DIR));
        assert_eq!(args.plugins_dir, PathBuf::from(DEFAULT_PLUGINS_DIR));
        assert_eq!(args.env_file, Some(PathBuf::from("/etc/creche/site.env")));
        assert!(args.json);
    }

    #[test]
    fn serve_takes_the_same_layout_dirs_as_verify() {
        let Command::Serve(args) = parse(&[
            "serve",
            "--audit-file",
            "/var/lib/chaperone/audit.jsonl",
            "--secrets-dir",
            "/etc/chaperone/secrets",
            "--admin-socket",
            "/run/chaperone/admin.sock",
        ]) else {
            panic!("not serve");
        };
        assert_eq!(args.config_dir, PathBuf::from(DEFAULT_CONFIG_DIR));
        assert_eq!(args.plugins_dir, PathBuf::from(DEFAULT_PLUGINS_DIR));
        assert_eq!(args.audit_mode, AuditMode::OwnerOnly);
    }

    const SERVE_PATHS: [&str; 7] = [
        "serve",
        "--audit-file",
        "/var/lib/chaperone/audit.jsonl",
        "--secrets-dir",
        "/etc/chaperone/secrets",
        "--admin-socket",
        "/run/chaperone/admin.sock",
    ];

    fn try_serve(mode: &str) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(
            std::iter::once("chaperone")
                .chain(SERVE_PATHS)
                .chain(["--audit-mode", mode]),
        )
    }

    #[test]
    fn serve_takes_audit_mode_0600_or_0640() {
        for (text, mode) in [
            ("0600", AuditMode::OwnerOnly),
            ("0640", AuditMode::GroupRead),
        ] {
            let Command::Serve(args) = try_serve(text).unwrap().command else {
                panic!("not serve");
            };
            assert_eq!(args.audit_mode, mode, "{text}");
        }
    }

    #[test]
    fn serve_refuses_any_other_audit_mode() {
        for text in ["0644", "0700", "640", "group"] {
            assert!(try_serve(text).is_err(), "{text}");
        }
    }

    #[test]
    fn an_explicit_dir_overrules_the_layout() {
        let Command::Verify(args) = parse(&[
            "verify",
            "--config-dir",
            "/srv/config",
            "--plugins-dir",
            "/srv/plugins",
        ]) else {
            panic!("not verify");
        };
        assert_eq!(args.config_dir, PathBuf::from("/srv/config"));
        assert_eq!(args.plugins_dir, PathBuf::from("/srv/plugins"));
    }

    #[test]
    fn check_and_token_take_the_layout_dirs() {
        let Command::Check(args) = parse(&["check", "/etc/chaperone/policy.toml"]) else {
            panic!("not check");
        };
        assert_eq!(args.plugins_dir, PathBuf::from(DEFAULT_PLUGINS_DIR));
        let Command::Token(TokenCommand {
            action: TokenAction::New(args),
        }) = parse(&["token", "new", "research"])
        else {
            panic!("not token new");
        };
        assert_eq!(args.config_dir, PathBuf::from(DEFAULT_CONFIG_DIR));
    }
}
