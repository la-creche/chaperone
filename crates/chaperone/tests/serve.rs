//! End to end: an MCP client talks to the front door over HTTP, and the
//! audit file records each call. Raw requests check the strict body read
//! and the `Host` check.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use chaperone::effect::{Redactor, Upstreams};
use chaperone::gateway::{Bounds, ChaperoneGateway, Plugins, SharedGateway};
use chaperone::registry::AuditMode;
use chaperone::startup;
use chaperone_plugin_mcp_http::BODY_CAP;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use support::{
    INSTALL, TOKEN, config_dir, hanging_approval, plugin_tree, policy_text, secrets_dir,
};
use tokio_util::sync::CancellationToken;

const OTHER_TOKEN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// A front door over the fixture, served on a free loopback port.
struct Served {
    address: SocketAddr,
    url: String,
    audit_path: std::path::PathBuf,
    shutdown: CancellationToken,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    _root: tempfile::TempDir,
}

async fn serve() -> Served {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let audit_path = root.path().join("audit.jsonl");
    let secrets = secrets_dir(root.path());
    let loaded = startup::load(
        &config,
        &plugins,
        &audit_path,
        AuditMode::OwnerOnly,
        &secrets,
    )
    .unwrap();
    let gateway = Arc::new(SharedGateway::new(ChaperoneGateway::new(
        loaded.run,
        loaded.policy.unwrap(),
        Plugins {
            identity: loaded.identity,
            audit: loaded.audit,
            clock: loaded.clock,
            upstreams: Upstreams::new(),
            approval: hanging_approval(),
            redactor: Redactor::new(loaded.secrets),
        },
        Bounds::DEFAULT,
    )));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(chaperone_plugin_mcp_http::serve(
        gateway,
        listener,
        vec!["127.0.0.1".to_owned()],
        shutdown.clone(),
    ));
    Served {
        address,
        url: format!("http://{address}/mcp"),
        audit_path,
        shutdown,
        server,
        _root: root,
    }
}

impl Served {
    async fn stop(self) -> String {
        self.shutdown.cancel();
        self.server.await.unwrap().unwrap();
        std::fs::read_to_string(&self.audit_path).unwrap()
    }
}

fn text_of(result: &rmcp::model::CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect()
}

async fn client(
    url: &str,
    token: Option<&str>,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let mut config = StreamableHttpClientTransportConfig::with_uri(url.to_owned());
    if let Some(token) = token {
        config = config.auth_header(token.to_owned());
    }
    ().serve(StreamableHttpClientTransport::from_config(config))
        .await
        .unwrap()
}

/// One raw `POST /mcp` with `Connection: close`. Returns the status line.
async fn raw_post(address: SocketAddr, host: &str, body: Vec<u8>) -> String {
    let host = host.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        let head = format!(
            "POST /mcp HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\
             Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response.lines().next().unwrap_or_default().to_owned()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn the_front_door_decides_and_audits_each_call() {
    let served = serve().await;

    let known = client(&served.url, Some(TOKEN)).await;
    let tools = known.list_all_tools().await.unwrap();
    assert!(tools.is_empty(), "no upstream runs in this test: {tools:?}");

    let allowed = known
        .call_tool(CallToolRequestParams::new("vikunja__list_tasks"))
        .await
        .unwrap();
    assert_eq!(allowed.is_error, Some(true));
    assert!(
        text_of(&allowed).contains("not_connected"),
        "{}",
        text_of(&allowed)
    );

    let ungranted = known
        .call_tool(CallToolRequestParams::new("vikunja__delete_everything"))
        .await
        .unwrap();
    assert!(text_of(&ungranted).contains("tool_not_granted"));

    // The approval channel never answers, so the gate stays pending.
    let gated = known
        .call_tool(CallToolRequestParams::new("vikunja__create_task"))
        .await
        .unwrap();
    assert_eq!(gated.is_error, Some(true));
    assert!(
        text_of(&gated)
            .starts_with("Awaiting permission for tool call vikunja__create_task (gate "),
        "{}",
        text_of(&gated)
    );

    let bad_name = known
        .call_tool(CallToolRequestParams::new("not.a.tool"))
        .await
        .unwrap();
    assert!(text_of(&bad_name).contains("unknown_tool"));
    known.cancel().await.unwrap();

    let stranger = client(&served.url, Some(OTHER_TOKEN)).await;
    assert!(stranger.list_all_tools().await.is_err());
    let denied = stranger
        .call_tool(CallToolRequestParams::new("vikunja__list_tasks"))
        .await
        .unwrap();
    assert!(text_of(&denied).contains("unknown_credential"));
    stranger.cancel().await.unwrap();

    let audit = served.stop().await;
    let lines: Vec<&str> = audit.lines().collect();
    // An allowed call writes `decided` and `failed`. An ungranted call writes
    // `decided`. A gated call writes `decided` and `waiting`. A bad name
    // writes `failed`. An unknown caller writes `decided`.
    assert_eq!(lines.len(), 7, "{audit}");
    assert!(
        lines[0].contains(r#""event":"decided","detail":"allow""#),
        "{}",
        lines[0]
    );
    assert!(lines[1].contains(r#""detail":"not_connected""#));
    assert!(lines[2].contains(r#""detail":"deny:tool_not_granted""#));
    assert!(lines[3].contains(r#""detail":"gate:"#));
    assert!(lines[4].contains(r#""event":"waiting""#), "{}", lines[4]);
    assert!(lines[5].contains(r#""detail":"unknown_tool""#));
    assert!(lines[6].contains(r#""app":null"#) && lines[6].contains("deny:unknown_credential"));
    assert!(
        !audit.contains(TOKEN) && !audit.contains(OTHER_TOKEN),
        "a token must never reach the audit file"
    );
}

#[tokio::test]
async fn a_body_that_is_not_strict_json_is_refused_before_the_parser() {
    let served = serve().await;
    let host = served.address.to_string();

    let duplicate = br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"a":2}}"#;
    let status = raw_post(served.address, &host, duplicate.to_vec()).await;
    assert!(status.starts_with("HTTP/1.1 400"), "{status}");

    let bom = b"\xef\xbb\xbf{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";
    let status = raw_post(served.address, &host, bom.to_vec()).await;
    assert!(status.starts_with("HTTP/1.1 400"), "{status}");

    let large = vec![b' '; BODY_CAP.bytes() + 1];
    let status = raw_post(served.address, &host, large).await;
    assert!(status.starts_with("HTTP/1.1 413"), "{status}");

    let audit = served.stop().await;
    assert!(audit.is_empty(), "no call reached the gateway: {audit}");
}

#[tokio::test]
async fn a_host_header_outside_the_allowed_list_is_refused() {
    let served = serve().await;
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let status = raw_post(served.address, "evil.example", body.to_vec()).await;
    assert!(status.starts_with("HTTP/1.1 4"), "{status}");
    served.stop().await;
}
