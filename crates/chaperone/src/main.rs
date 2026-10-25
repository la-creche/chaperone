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
use chaperone::gateway::{Bounds, ChaperoneGateway, Plugins, SharedGateway};
use chaperone::startup;
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
}

#[derive(Debug, clap::Args)]
struct Check {
    /// The file: install.toml or policy.json, in its configuration
    /// directory.
    file: PathBuf,
    /// The plugin tree: default/, then <kind>/included and <kind>/added.
    #[arg(long)]
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
    /// policy.json. The token is printed once.
    New(TokenNew),
}

#[derive(Debug, clap::Args)]
struct TokenNew {
    /// The app ID in policy.json.
    app: String,
    /// The directory that holds policy.json.
    #[arg(long)]
    config_dir: PathBuf,
}

#[derive(Debug, clap::Args)]
struct Serve {
    /// The directory that holds install.toml and policy.json.
    #[arg(long)]
    config_dir: PathBuf,
    /// The plugin tree: default/, then <kind>/included and <kind>/added.
    #[arg(long)]
    plugins_dir: PathBuf,
    /// The audit file. chaperone creates it with mode 0600.
    #[arg(long)]
    audit_file: PathBuf,
    /// The secrets directory: one file per secret, mode 0600, owned by the
    /// user that runs chaperone.
    #[arg(long)]
    secrets_dir: PathBuf,
    /// The admin socket path. chaperone creates it with mode 0660.
    #[arg(long)]
    admin_socket: PathBuf,
    /// The front door address. Only loopback in version 1.
    #[arg(long, default_value = "127.0.0.1:8300")]
    listen: SocketAddr,
    /// A Host header value to accept, such as host.docker.internal:8300.
    /// Loopback hosts are always accepted. Repeat for more.
    #[arg(long = "allowed-host")]
    allowed_hosts: Vec<String>,
}

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
        secrets_dir,
        admin_socket,
        listen,
        mut allowed_hosts,
    } = args;

    if let Err(error) = startup::check_listen(listen) {
        tracing::error!(%error, "refusing to start");
        return ExitCode::FAILURE;
    }
    let loaded = match startup::load(&config_dir, &plugins_dir, &audit_file, &secrets_dir) {
        Ok(loaded) => loaded,
        Err(error) => {
            tracing::error!(%error, "refusing to start");
            return ExitCode::FAILURE;
        }
    };
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
        loaded.policy,
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
