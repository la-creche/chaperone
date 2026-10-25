//! The plugin tree and the start checks: what loads, and what refuses start
//! (G2, G10).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use chaperone::catalog::{self, CatalogError};
use chaperone::startup::{self, Loaded, StartError, Warning};
use chaperone_core::{INSTALL_FILE_CAP, PluginKind, PluginName, SecretError, SecretParam, Slot};
use support::{
    INSTALL, config_dir, plugin_tree, policy_text, repo_plugins, secrets_dir, write_manifest,
    write_secret,
};

fn name(text: &str) -> PluginName {
    PluginName::try_new(text).unwrap()
}

/// Load the fixture tree with `install` and `policy`.
fn load(root: &Path, install: &str, policy: &str) -> Result<Loaded, StartError> {
    let plugins = plugin_tree(root);
    let config = config_dir(root, install, policy);
    let secrets = secrets_dir(root);
    startup::load(&config, &plugins, &root.join("audit.jsonl"), &secrets)
}

#[test]
fn the_repository_plugin_tree_holds_the_defaults_and_the_included() {
    let catalog = catalog::discover(&repo_plugins()).unwrap();
    let names: Vec<&str> = catalog.keys().map(|key| key.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "bearer",
            "ha-call",
            "audit-jsonl",
            "mcp-http",
            "secret-files",
            "system-clock",
            "deny-all",
            "ha-approval",
            "ha-call"
        ]
    );
    let defaults = catalog
        .values()
        .filter(|found| found.location == chaperone_core::Location::Default)
        .count();
    assert_eq!(defaults, Slot::ALL.len());
}

#[test]
fn a_manifest_in_a_directory_of_another_name_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    write_manifest(
        &plugins,
        "effect/added/other",
        r#"{"name":"vikunja","version":"1","kind":"effect","hooks":["upstream"],"command":["x"]}"#,
    );
    let error = catalog::discover(&plugins).unwrap_err();
    assert!(
        matches!(error, CatalogError::NameMismatch { .. }),
        "{error}"
    );
}

#[test]
fn a_manifest_in_the_directory_of_another_kind_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    write_manifest(
        &plugins,
        "decision/included/misplaced",
        r#"{"name":"misplaced","version":"1","kind":"effect","hooks":["upstream"],"command":["x"]}"#,
    );
    let error = catalog::discover(&plugins).unwrap_err();
    assert!(
        matches!(
            error,
            CatalogError::KindMismatch {
                expected: PluginKind::Decision,
                found: PluginKind::Effect,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn two_directories_with_one_plugin_refuse_start() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    write_manifest(
        &plugins,
        "decision/included/bearer",
        r#"{"name":"bearer","version":"2","kind":"decision","slot":"identity","hooks":["identity"]}"#,
    );
    let error = catalog::discover(&plugins).unwrap_err();
    assert!(matches!(error, CatalogError::Duplicate { .. }), "{error}");
}

#[test]
fn the_defaults_load_and_open_the_audit_file() {
    let root = tempfile::tempdir().unwrap();
    let loaded = load(root.path(), INSTALL, &policy_text(30)).unwrap();
    assert_eq!(loaded.setup.slot(Slot::Identity), Some(&name("bearer")));
    assert!(format!("{:?}", loaded.identity).contains("BearerIdentity"));
    assert_eq!(loaded.setup.slot(Slot::Clock), Some(&name("system-clock")));
    assert!(format!("{:?}", loaded.clock).contains("SystemClock"));
    assert!(loaded.warnings.is_empty());
    let mode = std::fs::metadata(root.path().join("audit.jsonl"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_missing_install_file_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    std::fs::remove_file(config.join("install.toml")).unwrap();
    let secrets = secrets_dir(root.path());
    let error = startup::load(
        &config,
        &plugins,
        &root.path().join("audit.jsonl"),
        &secrets,
    )
    .unwrap_err();
    assert!(matches!(error, StartError::Read(_)), "{error}");
}

#[test]
fn an_install_file_over_the_cap_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let padding = " ".repeat(INSTALL_FILE_CAP.bytes());
    let error = load(
        root.path(),
        &format!("{INSTALL}{padding}"),
        &policy_text(30),
    )
    .unwrap_err();
    assert!(matches!(error, StartError::Read(_)), "{error}");
}

#[test]
fn a_policy_that_does_not_parse_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let error = load(root.path(), INSTALL, r#"{"version":1,"apps":{},"apps":{}}"#).unwrap_err();
    assert!(matches!(error, StartError::Policy(_)), "{error}");
}

/// A tree where `vikunja` declares one secret, and an install file that
/// binds it to the secret file `vikunja_token`.
fn tree_with_a_bound_secret(root: &Path) -> (PathBuf, PathBuf) {
    let plugins = plugin_tree(root);
    write_manifest(
        &plugins,
        "effect/added/vikunja",
        r#"{"name":"vikunja","version":"1","kind":"effect","hooks":["upstream"],
            "secrets":["VIKUNJA_TOKEN"],"command":["vikunja-mcp"]}"#,
    );
    let install = "version = 1\nplugins.vikunja.secrets.VIKUNJA_TOKEN = \"vikunja_token\"\n";
    let config = config_dir(root, install, &policy_text(30));
    (plugins, config)
}

#[test]
fn a_bound_secret_is_read_at_start() {
    let root = tempfile::tempdir().unwrap();
    let (plugins, config) = tree_with_a_bound_secret(root.path());
    let secrets = secrets_dir(root.path());
    write_secret(&secrets, "vikunja_token", "tok-123");
    let loaded = startup::load(
        &config,
        &plugins,
        &root.path().join("audit.jsonl"),
        &secrets,
    )
    .unwrap();
    let vikunja = loaded.secrets.get(&name("vikunja")).unwrap();
    let secret = vikunja
        .get(&SecretParam::try_new("VIKUNJA_TOKEN").unwrap())
        .unwrap();
    assert_eq!(secret.name().as_str(), "vikunja_token");
    #[expect(clippy::disallowed_methods, reason = "the test checks the value")]
    let value = secret.expose();
    assert_eq!(value, "tok-123");
    assert!(!format!("{loaded:?}").contains("tok-123"));
}

#[test]
fn a_bound_secret_that_is_missing_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let (plugins, config) = tree_with_a_bound_secret(root.path());
    let secrets = secrets_dir(root.path());
    let error = startup::load(
        &config,
        &plugins,
        &root.path().join("audit.jsonl"),
        &secrets,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            StartError::Secret {
                ref plugin,
                error: SecretError::Missing,
                ..
            } if plugin == &name("vikunja")
        ),
        "{error}"
    );
    assert!(error.to_string().contains("vikunja_token"), "{error}");
}

#[test]
fn a_setup_without_secrets_never_needs_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let none = root.path().join("no-such-dir");
    let loaded = startup::load(&config, &plugins, &root.path().join("audit.jsonl"), &none).unwrap();
    assert!(loaded.secrets.is_empty());
}

#[test]
fn env_delivery_without_a_secret_is_a_warning() {
    let root = tempfile::tempdir().unwrap();
    let install = "version = 1\nplugins.vikunja.secret_delivery = \"env\"\n";
    let loaded = load(root.path(), install, &policy_text(30)).unwrap();
    assert_eq!(
        loaded.warnings,
        [Warning::EnvDelivery {
            plugin: name("vikunja")
        }]
    );
}

#[test]
fn another_plugin_in_a_slot_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    write_manifest(
        &plugins,
        "decision/included/other-identity",
        r#"{"name":"other-identity","version":"1","kind":"decision","slot":"identity","hooks":["identity"]}"#,
    );
    let install = r#"
        version = 1
        plugins = { other-identity = {}, vikunja = {} }
        slots.identity = "other-identity"
    "#;
    let config = config_dir(root.path(), install, &policy_text(30));
    let secrets = secrets_dir(root.path());
    let error = startup::load(
        &config,
        &plugins,
        &root.path().join("audit.jsonl"),
        &secrets,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            StartError::NoCode {
                slot: Slot::Identity,
                ref plugin
            } if plugin == &name("other-identity")
        ),
        "{error}"
    );
}

#[test]
fn a_front_door_address_that_is_not_loopback_refuses_start() {
    let lan = "192.0.2.10:8300".parse().unwrap();
    assert!(matches!(
        startup::check_listen(lan),
        Err(StartError::NotLoopback(_))
    ));
    assert!(startup::check_listen("127.0.0.1:8300".parse().unwrap()).is_ok());
    assert!(startup::check_listen("[::1]:8300".parse().unwrap()).is_ok());
}

#[test]
fn an_unsafe_audit_file_refuses_start() {
    let root = tempfile::tempdir().unwrap();
    let plugins = plugin_tree(root.path());
    let config = config_dir(root.path(), INSTALL, &policy_text(30));
    let audit = root.path().join("audit.jsonl");
    std::fs::write(&audit, b"").unwrap();
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o644)).unwrap();
    let secrets = secrets_dir(root.path());
    let error = startup::load(&config, &plugins, &audit, &secrets).unwrap_err();
    assert!(matches!(error, StartError::Audit(_)), "{error}");
}
