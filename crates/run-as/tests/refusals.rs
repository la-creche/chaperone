//! The refusals of `chaperone-as` that run without privilege
//! (`docs/design.md` 8). The name pattern refuses root and the caller by
//! name here. The unit tests of `resolve` refuse them by id.

#![allow(clippy::unwrap_used, reason = "a test fixture fails loudly")]

use std::process::Command;

use chaperone_core::CHILD_ENV_VAR;

#[test]
fn each_refusal_exits_125_with_one_stderr_line_and_no_stdout() {
    let id = Command::new("id").arg("-un").output().unwrap();
    let own = String::from_utf8(id.stdout).unwrap().trim().to_owned();
    let cases: [(&str, &[&str]); 5] = [
        ("no arguments", &[]),
        ("a relative command", &["mcp-ha", "bin/true"]),
        ("an unknown user", &["mcp-no-such-user-zz", "/bin/true"]),
        ("root", &["root", "/bin/true"]),
        ("the user of the caller", &[&own, "/bin/true"]),
    ];
    for (case, args) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_chaperone-as"))
            .args(args)
            .env_clear()
            .env(CHILD_ENV_VAR, "{}")
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(125), "{case}: {stderr}");
        assert!(output.stdout.is_empty(), "{case}");
        assert_eq!(stderr.lines().count(), 1, "{case}: {stderr}");
        assert!(
            stderr.starts_with("chaperone-as: refused: "),
            "{case}: {stderr}"
        );
    }
}
