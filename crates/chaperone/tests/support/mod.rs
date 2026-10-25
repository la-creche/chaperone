//! Fixtures shared by the tests: a plugin tree, a configuration directory
//! and a policy for one app instance with a `vikunja` upstream.

#![allow(dead_code, reason = "each test file uses a part of the fixtures")]

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// A token in the form the bearer plugin accepts.
pub const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// An install file that enables the `vikunja` upstream.
pub const INSTALL: &str = r#"{"version":1,"plugins":{"vikunja":{}}}"#;

const VIKUNJA_MANIFEST: &str = r#"{"name":"vikunja","version":"1","kind":"effect","hooks":["upstream"],"command":["vikunja-mcp"]}"#;

/// The `plugins` directory of this repository.
pub fn repo_plugins() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins")
}

/// A plugin tree under `root`: the manifests of the repository's defaults,
/// plus a `vikunja` upstream in `effect/added`.
pub fn plugin_tree(root: &Path) -> PathBuf {
    let plugins = root.join("plugins");
    for entry in std::fs::read_dir(repo_plugins().join("default")).unwrap() {
        let source = entry.unwrap().path();
        if !source.is_dir() {
            continue;
        }
        let target = plugins.join("default").join(source.file_name().unwrap());
        std::fs::create_dir_all(&target).unwrap();
        std::fs::copy(source.join("plugin.json"), target.join("plugin.json")).unwrap();
    }
    write_manifest(&plugins, "effect/added/vikunja", VIKUNJA_MANIFEST);
    plugins
}

/// Write one `plugin.json` at `plugins/<relative>`.
pub fn write_manifest(plugins: &Path, relative: &str, manifest: &str) {
    let dir = plugins.join(relative);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.json"), manifest).unwrap();
}

/// The SHA-256 of `token` as hex, as the policy file holds it.
pub fn digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A policy with one app instance, `librechat`, that may list tasks and
/// needs an approval to create one. The other grants reach the test tools
/// of the fake upstream.
pub fn policy_text(calls_per_minute: u32) -> String {
    let digest = digest(TOKEN);
    format!(
        r#"{{"version":1,"apps":{{"librechat":{{
            "token_sha256":["{digest}"],
            "limits":{{"calls_per_minute":{calls_per_minute},"max_pending_gates":1}},
            "grants":{{"vikunja":{{"tools":{{
                "list_tasks":{{}},
                "create_task":{{"approval":"required"}},
                "picture":{{}},
                "big":{{}},
                "broken":{{}},
                "slow":{{}},
                "delete_task":{{"approval":"required"}},
                "wait_task":{{"approval":"required"}},
                "odd_task":{{"approval":"required"}}
            }}}}}}}}}}}}"#
    )
}

/// An approval channel in memory. It answers each gate by the tool it
/// holds. `create_task` is approved. `delete_task` is denied. `wait_task`
/// is approved after `wait`. `odd_task` gets text that is no answer.
#[derive(Debug)]
pub struct FakeApproval {
    pub wait: std::time::Duration,
}

impl chaperone::effect::Effect for FakeApproval {
    fn tools(&self) -> &[chaperone::effect::EffectTool] {
        &[]
    }

    fn call<'a>(
        &'a self,
        _tool: &'a chaperone_core::ToolName,
        arguments: std::collections::BTreeMap<String, chaperone_core::ArgValue>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<rmcp::model::CallToolResult, chaperone::effect::EffectFault>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let tool = match arguments.get("tool") {
                Some(chaperone_core::ArgValue::String(tool)) => tool.clone(),
                _ => String::new(),
            };
            let answer = |text: &str| {
                rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(
                    text.to_owned(),
                )])
            };
            Ok(if tool.ends_with("delete_task") {
                answer(r#"{"answer":"denied","reason":"not today"}"#)
            } else if tool.ends_with("wait_task") {
                tokio::time::sleep(self.wait).await;
                answer(r#"{"answer":"approved"}"#)
            } else if tool.ends_with("odd_task") {
                answer("yes")
            } else {
                answer(r#"{"answer":"approved"}"#)
            })
        })
    }
}

/// An approval channel over [`FakeApproval`] that answers at once.
pub fn fake_approval() -> chaperone::approval::ApprovalChannel {
    chaperone::approval::ApprovalChannel::new(Box::new(FakeApproval {
        wait: std::time::Duration::from_secs(1),
    }))
}

/// An empty secrets directory under `root`.
pub fn secrets_dir(root: &Path) -> PathBuf {
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    secrets
}

/// Write `value` as the secret `name` under `secrets`, mode 0600.
pub fn write_secret(secrets: &Path, name: &str, value: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = secrets.join(name);
    std::fs::write(&path, value).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A configuration directory under `root` with these two files.
pub fn config_dir(root: &Path, install: &str, policy: &str) -> PathBuf {
    let config = root.join("config");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("install.json"), install).unwrap();
    std::fs::write(config.join("policy.json"), policy).unwrap();
    config
}
