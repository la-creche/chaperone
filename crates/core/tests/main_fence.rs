//! A deny fence on a branch name, driven through the real decision with
//! each spelling of `main`. The fence compares strings exactly (section
//! 5.2, row 4). This file pins which spellings it denies. It also pins the
//! spellings it hands to the upstream.
//!
//! The fixture is a GitHub upstream whose write tools deny the branches
//! `main` and `master`. The comment on each row of passed spellings says
//! what github-mcp-server 1.12.0 does with that spelling.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::collections::BTreeMap;

use chaperone_core::{
    AppId, ArgName, ArgValue, Caller, Catalog, Decision, DenyReason, Found, Gates, InstallFile,
    Location, Manifest, PluginKey, PluginName, Policy, Reach, Request, Timestamp, ToolName, strict,
};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The five write tools with a fence on `branch`.
const FENCED_TOOLS: [&str; 5] = [
    "push_files",
    "create_or_update_file",
    "delete_file",
    "create_branch",
    "update_pull_request_branch",
];

fn put(catalog: &mut Catalog, location: Location, text: &str) {
    let manifest = Manifest::read(text.as_bytes()).unwrap();
    catalog.insert(
        PluginKey::from_manifest(&manifest),
        Found { location, manifest },
    );
}

fn catalog() -> Catalog {
    let mut catalog = Catalog::new();
    for (plugin, kind, slot) in [
        ("mcp-http", "adapter", "front_door"),
        ("bearer", "decision", "identity"),
        ("secret-files", "adapter", "secret_source"),
        ("audit-jsonl", "adapter", "audit_sink"),
        ("system-clock", "adapter", "clock"),
    ] {
        put(
            &mut catalog,
            Location::Default,
            &format!(
                r#"
                    name = "{plugin}"
                    version = "1"
                    kind = "{kind}"
                    slot = "{slot}"
                    hooks = ["{slot}"]
                "#
            ),
        );
    }
    put(
        &mut catalog,
        Location::Default,
        r#"
            name = "deny-all"
            version = "1"
            kind = "effect"
            slot = "approval_channel"
            hooks = ["approval"]
            command = ["deny-all"]
        "#,
    );
    put(
        &mut catalog,
        Location::Added,
        r#"
            name = "github"
            version = "1"
            kind = "effect"
            hooks = ["upstream"]
            command = ["github-mcp-server"]
        "#,
    );
    catalog
}

/// One app instance that holds the five tools. Each tool has a repository
/// allow and the branch deny.
fn policy() -> Policy {
    let fences = r#"arguments = { branch = { deny = ["main", "master"] }, owner = { allow = ["example-org"] }, repo = { allow = ["one", "two"] } }"#;
    let tools: String = FENCED_TOOLS
        .iter()
        .map(|tool| format!("{tool} = {{ {fences} }}\n"))
        .collect();
    let text = format!(
        r#"
        version = 1

        [apps.coder]
        token_sha256 = ["{DIGEST}"]
        limits = {{ calls_per_minute = 60, max_pending_gates = 10 }}

        [apps.coder.grants.github.tools]
        {tools}
        "#
    );
    let install = InstallFile::read(b"version = 1\nplugins = { github = {} }\n").unwrap();
    let setup = chaperone_core::resolve(&install, &catalog()).unwrap();
    Policy::load(text.as_bytes(), &setup, &[]).unwrap()
}

fn decide(policy: &Policy, tool: &str, branch: Option<&str>) -> Decision {
    let mut arguments = String::from(r#"{"owner": "example-org", "repo": "one""#);
    if let Some(branch) = branch {
        arguments.push_str(&format!(", \"branch\": {branch}"));
    }
    arguments.push('}');
    let value = strict::read_value(arguments.as_bytes(), strict::ByteCap::new(4096)).unwrap();
    let ArgValue::Object(arguments) = value else {
        panic!("not an object: {value:?}");
    };
    let empty = BTreeMap::new();
    chaperone_core::decide(
        Some(policy),
        &Request {
            caller: Some(&Caller {
                app: AppId::try_new("coder").unwrap(),
                reach: Reach::Full,
            }),
            upstream: &PluginName::try_new("github").unwrap(),
            tool: &ToolName::try_new(tool).unwrap(),
            arguments: &arguments,
            calls_this_minute: 0,
            calls_in_flight: 0,
            gates: Gates {
                pending: &empty,
                approved: &empty,
                denied: &empty,
            },
            now: Timestamp::from_unix_millis(1_000_000),
        },
    )
}

fn fenced() -> Decision {
    Decision::Deny(DenyReason::ArgumentFenced {
        argument: ArgName::try_new("branch").unwrap(),
    })
}

#[test]
fn the_fence_denies_the_exact_names() {
    let policy = policy();
    for tool in FENCED_TOOLS {
        for branch in [r#""main""#, r#""master""#] {
            assert_eq!(
                decide(&policy, tool, Some(branch)),
                fenced(),
                "{tool} {branch}"
            );
        }
    }
}

#[test]
fn the_fence_denies_a_branch_that_is_not_a_scalar() {
    let policy = policy();
    for tool in FENCED_TOOLS {
        for branch in [r#"["main"]"#, r#"{"name": "main"}"#] {
            assert_eq!(
                decide(&policy, tool, Some(branch)),
                fenced(),
                "{tool} {branch}"
            );
        }
    }
}

/// Each spelling here reaches the upstream. A spelling that names `main`
/// to GitHub is a bypass of the fence.
#[test]
fn the_fence_passes_every_other_spelling() {
    let policy = policy();
    let spellings = [
        // push_files and delete_file call GetRef("refs/heads/" + branch).
        // go-github resolves the `.` segment before the request, so the
        // GET is `git/ref/heads/main`, and UpdateRef then writes the
        // returned `refs/heads/main`. A bypass.
        r#""./main""#,
        r#""././main""#,
        // GitHub reads the Contents API `branch` of create_or_update_file.
        // Whether it resolves these to `main` is not tested.
        r#""refs/heads/main""#,
        r#""heads/main""#,
        r#""Main""#,
        r#""MAIN""#,
        r#""main ""#,
        r#"" main""#,
        r#""main\n""#,
        r#""main/.""#,
        r#""0123456789abcdef0123456789abcdef01234567""#,
        // go-github refuses a `..` segment (ErrPathForbidden), so the
        // upstream answers an error and writes nothing.
        r#""x/../main""#,
        // The upstream requires a string `branch`, so it refuses these.
        r#"null"#,
        r#"true"#,
        r#"1"#,
    ];
    for tool in FENCED_TOOLS {
        for branch in spellings {
            assert_eq!(
                decide(&policy, tool, Some(branch)),
                Decision::Allow,
                "{tool} {branch}"
            );
        }
    }
}

/// A deny fence passes a call that leaves the argument out. Every fenced
/// tool of github-mcp-server 1.12.0 requires `branch`, except
/// `update_pull_request_branch`, which has no `branch` argument at all:
/// the fence never sees the branch it writes.
#[test]
fn the_fence_passes_a_call_with_no_branch() {
    let policy = policy();
    for tool in FENCED_TOOLS {
        assert_eq!(decide(&policy, tool, None), Decision::Allow, "{tool}");
    }
}
