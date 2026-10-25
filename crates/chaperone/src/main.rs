//! `chaperone serve`: load the configuration, then serve the front door
//! until SIGINT or SIGTERM.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

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
    /// Load the configuration and serve the front door.
    Serve(Serve),
}

#[derive(Debug, clap::Args)]
struct Serve {
    /// The directory that holds install.json and policy.json.
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
    let upstreams = match effect::launch_all(&loaded.setup, &loaded.catalog, &redactor).await {
        Ok(upstreams) => upstreams,
        Err(error) => {
            tracing::error!(%error, "refusing to start");
            return ExitCode::FAILURE;
        }
    };
    effect::warn_unlisted(&loaded.policy, &upstreams);
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
            upstreams,
            redactor,
        },
        Bounds::DEFAULT,
    )));
    let shutdown = CancellationToken::new();
    tokio::spawn(shutdown_on_signal(shutdown.clone()));

    tracing::info!(%listen, run = %loaded.run, "serving the front door");
    match chaperone_plugin_mcp_http::serve(gateway, listener, allowed_hosts, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "the front door stopped");
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
