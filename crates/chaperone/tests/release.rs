//! The files that the external release tool reads: `component.toml` and
//! the service unit it names (`docs/design.md` 8 and 12). The release tool
//! holds its own copy of the manifest text. A change to a field here thus
//! fails this test before it fails an install.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::path::{Path, PathBuf};

use chaperone_core::strict::{ByteCap, read_toml};
use serde::Deserialize;

/// The most bytes of `component.toml` that the test reads.
const MANIFEST_CAP: ByteCap = ByteCap::new(16 * 1024);

/// The install tree of the release tool.
const INSTALL_TO: &str = "/opt/components/chaperone";

/// The program that the unit starts and that the verify hook runs.
const PROGRAM: &str = "/opt/components/chaperone/bin/chaperone";

/// The site file of the host. The unit and the verify hook both read it.
const SITE_FILE: &str = "/etc/creche/site.env";

/// The key of the front door address in the site file.
const LISTEN_KEY: &str = "CHAPERONE_LISTEN";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Component {
    manifest_version: String,
    name: String,
    repo: String,
    path: String,
    kind: String,
    unit: String,
    runs_as: String,
    build: Vec<Vec<String>>,
    install: Install,
    verify: Verify,
    restore: Restore,
    release: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Install {
    to: String,
    prev: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Verify {
    command: Vec<String>,
    user: String,
    timeout_s: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Restore {
    mode: String,
    keep: u32,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn component() -> Component {
    let bytes = std::fs::read(repo_root().join("component.toml")).unwrap();
    read_toml(&bytes, MANIFEST_CAP).unwrap()
}

/// The text of the unit file that `component.toml` names.
fn unit_text() -> String {
    let unit = component().unit;
    std::fs::read_to_string(repo_root().join("systemd").join(unit)).unwrap()
}

/// The value of each line of `key=` in the unit text, in file order.
fn values<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let prefix = format!("{key}=");
    text.lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .collect()
}

#[test]
fn the_manifest_holds_the_fields_of_the_release_tool() {
    let component = component();
    assert_eq!(component.manifest_version, "0.19");
    assert_eq!(component.name, "chaperone");
    assert_eq!(component.repo, "chaperone");
    assert_eq!(component.path, ".");
    assert_eq!(component.kind, "binary");
    assert_eq!(component.unit, "creche-chaperone.service");
    assert_eq!(component.runs_as, "root");
    assert_eq!(
        component.build,
        [
            [
                "cargo",
                "install",
                "--locked",
                "--no-track",
                "--path",
                "crates/chaperone",
                "--bin",
                "chaperone"
            ],
            [
                "cargo",
                "install",
                "--locked",
                "--no-track",
                "--path",
                "crates/run-as",
                "--bin",
                "chaperone-as"
            ],
        ]
    );
    assert_eq!(component.install.to, INSTALL_TO);
    assert_eq!(component.install.prev, format!("{INSTALL_TO}.prev"));
    assert_eq!(
        component.verify.command,
        [
            PROGRAM,
            "verify",
            "--json",
            "--env-file",
            SITE_FILE,
            "--listen-key",
            LISTEN_KEY
        ]
    );
    assert_eq!(component.verify.user, "root");
    assert_eq!(component.verify.timeout_s, 60);
    assert_eq!(component.restore.mode, "automatic");
    assert_eq!(component.restore.keep, 3);
    assert!(component.release);
}

#[test]
fn the_release_workflow_runs_each_build_of_the_manifest() {
    let workflow =
        std::fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    for argv in component().build {
        let command = argv.join(" ");
        assert!(workflow.contains(&command), "{command}");
    }
}

#[test]
fn the_unit_starts_the_program_of_the_install_tree() {
    let text = unit_text();
    let starts = values(&text, "ExecStart");
    assert_eq!(starts.len(), 1, "{starts:?}");
    let argv: Vec<&str> = starts[0].split_whitespace().collect();
    assert_eq!(argv[..2], [PROGRAM, "serve"]);
    let listen = format!("${{{LISTEN_KEY}}}");
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["--listen", listen.as_str()]),
        "{argv:?}"
    );
    for flag in ["--secrets-dir", "--audit-file", "--admin-socket"] {
        assert!(argv.contains(&flag), "{flag}");
    }
    assert_eq!(values(&text, "EnvironmentFile"), [SITE_FILE]);
}

#[test]
fn the_unit_holds_only_the_two_capabilities_of_chaperone_as() {
    let text = unit_text();
    assert_eq!(values(&text, "User"), ["chaperone"]);
    assert_eq!(values(&text, "NoNewPrivileges"), ["yes"]);
    assert_eq!(
        values(&text, "CapabilityBoundingSet"),
        ["CAP_SETUID CAP_SETGID"]
    );
    assert_eq!(
        values(&text, "AmbientCapabilities"),
        ["CAP_SETUID CAP_SETGID"]
    );
}
