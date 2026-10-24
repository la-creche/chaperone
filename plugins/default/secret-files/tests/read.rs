//! What the secret-files source reads, and what it refuses
//! (`docs/design.md` section 8).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use chaperone_core::{SecretError, SecretName, SecretSource};
use chaperone_plugin_secret_files::{FileSecrets, VALUE_CAP};

fn name(text: &str) -> SecretName {
    SecretName::try_new(text).unwrap()
}

/// Write `bytes` as the secret `name` with mode 0600.
fn put(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn a_good_file_reads_as_its_secret() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "vikunja_token", b"tok-123");
    let source = FileSecrets::new(dir.path().to_owned());
    let secret = source.read(&name("vikunja_token")).unwrap();
    assert_eq!(secret.name(), &name("vikunja_token"));
    #[expect(clippy::disallowed_methods, reason = "the test checks the value")]
    let value = secret.expose();
    assert_eq!(value, "tok-123");
}

#[test]
fn a_value_at_the_cap_reads_and_one_byte_more_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "at_cap", "a".repeat(VALUE_CAP).as_bytes());
    put(dir.path(), "over_cap", "a".repeat(VALUE_CAP + 1).as_bytes());
    let source = FileSecrets::new(dir.path().to_owned());
    assert!(source.read(&name("at_cap")).is_ok());
    assert!(matches!(
        source.read(&name("over_cap")),
        Err(SecretError::Invalid(_))
    ));
}

#[test]
fn a_missing_file_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let source = FileSecrets::new(dir.path().to_owned());
    assert!(matches!(
        source.read(&name("none")),
        Err(SecretError::Missing)
    ));
}

#[test]
fn a_missing_directory_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let source = FileSecrets::new(dir.path().join("none"));
    assert!(matches!(
        source.read(&name("token")),
        Err(SecretError::Missing)
    ));
}

#[test]
fn a_wider_mode_is_unsafe() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "token", b"tok");
    let path = dir.path().join("token");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let source = FileSecrets::new(dir.path().to_owned());
    assert!(matches!(
        source.read(&name("token")),
        Err(SecretError::Unsafe(_))
    ));
}

#[test]
fn a_symbolic_link_is_unsafe() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "real", b"tok");
    std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
    let source = FileSecrets::new(dir.path().to_owned());
    assert!(matches!(
        source.read(&name("link")),
        Err(SecretError::Unsafe(_))
    ));
}

#[test]
fn a_directory_is_unsafe() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("token")).unwrap();
    std::fs::set_permissions(
        dir.path().join("token"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let source = FileSecrets::new(dir.path().to_owned());
    assert!(matches!(
        source.read(&name("token")),
        Err(SecretError::Unsafe(_))
    ));
}

#[test]
fn an_empty_file_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "token", b"");
    let source = FileSecrets::new(dir.path().to_owned());
    assert!(matches!(
        source.read(&name("token")),
        Err(SecretError::Invalid(_))
    ));
}

#[test]
fn bytes_that_are_not_utf8_are_invalid() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "token", &[0xff, 0xfe, b'a']);
    let source = FileSecrets::new(dir.path().to_owned());
    assert!(matches!(
        source.read(&name("token")),
        Err(SecretError::Invalid(_))
    ));
}

#[test]
fn a_trailing_newline_or_a_control_character_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "newline", b"tok\n");
    put(dir.path(), "tab", b"to\tk");
    put(dir.path(), "space", b"tok ");
    let source = FileSecrets::new(dir.path().to_owned());
    for secret in ["newline", "tab", "space"] {
        assert!(
            matches!(source.read(&name(secret)), Err(SecretError::Invalid(_))),
            "{secret}"
        );
    }
}

#[test]
fn an_error_names_no_path_and_no_value() {
    let dir = tempfile::tempdir().unwrap();
    put(dir.path(), "token", b"SECRET-value\n");
    let source = FileSecrets::new(dir.path().to_owned());
    let error = source.read(&name("token")).unwrap_err();
    let shown = format!("{error} {error:?}");
    assert!(!shown.contains("SECRET"), "{shown}");
    assert!(!shown.contains(dir.path().to_str().unwrap()), "{shown}");
    let shown = format!("{source:?}");
    assert!(!shown.contains("SECRET"), "{shown}");
}
