//! The files that the external release tool reads: `component.toml` and
//! the service unit it names (`docs/design.md` 8 and 12). The release tool
//! holds its own copy of the manifest text. A change to a field here thus
//! fails this test before it fails an install. The release workflow
//! builds and packs the same programs, one for each `plugin.toml` command.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chaperone_core::strict::{ByteCap, read_toml};
use chaperone_core::{Manifest, Runtime};
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

/// The package path and the program of each build, in the order of the
/// manifest. The order is the name order of the programs, which is the
/// order of the archive members.
const BUILDS: [(&str, &str); 7] = [
    ("crates/chaperone", "chaperone"),
    ("crates/run-as", "chaperone-as"),
    ("plugins/effect/included/attendance", "chaperone-attendance"),
    ("plugins/default/deny-all", "chaperone-deny-all"),
    (
        "plugins/effect/included/ha-approval",
        "chaperone-ha-approval",
    ),
    ("plugins/effect/included/ha-call", "chaperone-ha-call"),
    ("plugins/effect/included/release", "chaperone-release"),
];

/// The programs of the build that no `plugin.toml` names.
const HOST_PROGRAMS: [&str; 2] = ["chaperone", "chaperone-as"];

/// The directory of the programs in the archive.
const ARCHIVE_BIN: &str = "chaperone/bin";

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

/// The text of the release workflow.
fn workflow_text() -> String {
    std::fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap()
}

/// The argv of one build: one program of one package.
fn install(path: &str, program: &str) -> Vec<String> {
    [
        "cargo",
        "install",
        "--locked",
        "--no-track",
        "--path",
        path,
        "--bin",
        program,
    ]
    .map(String::from)
    .to_vec()
}

/// The program of each build of the manifest, in its order.
fn built_programs() -> Vec<String> {
    component()
        .build
        .iter()
        .map(|argv| {
            let at = argv.iter().position(|word| word == "--bin").unwrap();
            argv[at + 1].clone()
        })
        .collect()
}

/// Every `plugin.toml` under `dir`, outside `target` directories, sorted.
fn plugin_manifests(dir: &Path, found: &mut Vec<PathBuf>) {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "target") {
                plugin_manifests(&path, found);
            }
        } else if path.file_name().is_some_and(|name| name == "plugin.toml") {
            found.push(path);
        }
    }
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
    let builds: Vec<Vec<String>> = BUILDS
        .iter()
        .map(|(path, program)| install(path, program))
        .collect();
    assert_eq!(component.build, builds);
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
fn the_release_workflow_runs_the_builds_of_the_manifest_in_order() {
    let workflow = workflow_text();
    let runs: Vec<&str> = workflow
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("cargo install "))
        .collect();
    let builds: Vec<String> = component()
        .build
        .iter()
        .map(|argv| argv.join(" "))
        .collect();
    assert_eq!(runs, builds);
}

#[test]
fn the_archive_holds_each_program_of_the_build_in_name_order() {
    let workflow = workflow_text();
    let members: Vec<&str> = workflow
        .lines()
        .map(str::trim)
        .skip_while(|line| *line != "members=(")
        .skip(1)
        .take_while(|line| *line != ")")
        .collect();
    let programs = built_programs();
    let expected: Vec<String> = programs
        .iter()
        .map(|program| format!("{ARCHIVE_BIN}/{program}"))
        .collect();
    assert_eq!(members, expected);
    assert!(programs.is_sorted(), "{programs:?}");
}

#[test]
fn each_plugin_program_is_built_from_its_own_plugin() {
    let root = repo_root();
    let mut manifests = Vec::new();
    plugin_manifests(&root.join("plugins"), &mut manifests);
    assert!(!manifests.is_empty());

    let builds = component().build;
    let mut programs: BTreeSet<String> = HOST_PROGRAMS.map(String::from).into();
    for file in manifests {
        let manifest = Manifest::read(&std::fs::read(&file).unwrap()).unwrap();
        match manifest.runtime() {
            Runtime::Compiled => {}
            Runtime::Process { command } => {
                let program = &command[0];
                let dir = file.parent().unwrap().strip_prefix(&root).unwrap();
                let path = dir.to_str().unwrap();
                assert!(
                    builds.contains(&install(path, program)),
                    "{program} of {path}"
                );
                programs.insert(program.clone());
            }
        }
    }
    let built: BTreeSet<String> = built_programs().into_iter().collect();
    assert_eq!(built, programs);
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
fn the_unit_lets_the_group_read_the_audit() {
    let text = unit_text();
    let starts = values(&text, "ExecStart");
    let argv: Vec<&str> = starts[0].split_whitespace().collect();
    assert!(
        argv.windows(2).any(|pair| pair == ["--audit-mode", "0640"]),
        "{argv:?}"
    );
    assert_eq!(values(&text, "Group"), ["chaperone"]);
    assert_eq!(values(&text, "StateDirectoryMode"), ["0750"]);
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

#[test]
fn the_crate_holds_the_placeholder_version_that_the_release_stamps() {
    let manifest =
        std::fs::read_to_string(repo_root().join("crates/chaperone/Cargo.toml")).unwrap();
    assert!(manifest.lines().any(|line| line == "version = \"0.0.0\""));
    let workflow = workflow_text();
    assert!(workflow.contains("- name: Stamp the version"));
    assert!(workflow.contains("handover/bin/allocate-tags.sh --dry-run"));
}
