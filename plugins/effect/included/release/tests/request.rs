//! The request file: its exact bytes, its name, and every refusal. A
//! refusal writes nothing and shows no argument value (G9).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Barrier;
use std::time::Duration;

use chaperone_plugin_release::{
    ArgumentError, Arguments, FileError, MAX_PENDING, Request, Requester, file,
};
use serde_json::json;

/// 1761400000.5 seconds after the Unix epoch.
const NOW: Duration = Duration::from_millis(1_761_400_000_500);

fn arguments(value: serde_json::Value) -> Result<Arguments, ArgumentError> {
    Arguments::parse(value.as_object().unwrap().clone())
}

fn request(value: serde_json::Value, entropy: [u8; 10]) -> Request {
    let requester = Requester::parse("agent-control").unwrap();
    Request::new(arguments(value).unwrap(), requester, NOW, entropy)
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn the_id_matches_the_ulid_of_the_executor() {
    let zero = request(json!({"components": {"chaperone": "latest"}}), [0; 10]);
    assert_eq!(zero.id().as_str(), "01K8DSY3ZM0000000000000000");
    let counted = request(
        json!({"components": {"chaperone": "latest"}}),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    );
    assert_eq!(counted.id().as_str(), "01K8DSY3ZM041061050R3GG28A");
}

#[test]
fn a_request_writes_one_file_with_the_exact_fields() {
    let dir = tempfile::tempdir().unwrap();
    let release = request(
        json!({"components": {"mcp-servers": "latest", "chaperone": "1.2.3"}}),
        [0; 10],
    );
    let path = file(dir.path(), &release).unwrap();
    assert_eq!(names(dir.path()), ["01K8DSY3ZM0000000000000000.json"]);
    assert_eq!(path, dir.path().join("01K8DSY3ZM0000000000000000.json"));
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        concat!(
            r#"{"id":"01K8DSY3ZM0000000000000000","kind":"release","#,
            r#""components":{"chaperone":"1.2.3","mcp-servers":"latest"},"#,
            r#""rollback_of":null,"requested_by":"agent-control","#,
            r#""requester_session":null,"ts":1761400000.5}"#
        )
    );

    let rollback = request(
        json!({
            "components": {"chaperone": "1.2.2"},
            "kind": "rollback",
            "rollback_of": "01K8DSY3ZM0000000000000000"
        }),
        [1; 10],
    );
    let text = std::fs::read_to_string(file(dir.path(), &rollback).unwrap()).unwrap();
    assert!(
        text.contains(r#""kind":"rollback","components":{"chaperone":"1.2.2"},"rollback_of":"01K8DSY3ZM0000000000000000""#),
        "{text}"
    );
}

#[test]
fn a_second_request_with_the_same_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let first = request(json!({"components": {"chaperone": "1.2.3"}}), [7; 10]);
    let path = file(dir.path(), &first).unwrap();
    let before = std::fs::read(&path).unwrap();

    let second = request(json!({"components": {"chaperone": "9.9.9"}}), [7; 10]);
    let error = file(dir.path(), &second).unwrap_err();
    assert!(matches!(error, FileError::Exists), "{error}");
    assert_eq!(names(dir.path()).len(), 1, "a temporary file stayed");
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn a_bad_argument_is_refused_with_no_value_in_the_error() {
    let marker = "zz-marker";
    let rollback = "01K8DSY3ZM0000000000000000";
    let nine: serde_json::Map<String, serde_json::Value> = (0..9)
        .map(|n| (format!("component-{n}"), json!("latest")))
        .collect();
    for (bad, expected) in [
        (json!({"components": {}}), ArgumentError::NoComponent),
        (json!({"components": nine}), ArgumentError::TooMany),
        (
            json!({"components": {"../zz-marker": "latest"}}),
            ArgumentError::ComponentName,
        ),
        (
            json!({"components": {"Zz-marker": "latest"}}),
            ArgumentError::ComponentName,
        ),
        (
            json!({"components": {"chaperone": "1.2"}}),
            ArgumentError::Version,
        ),
        (
            json!({"components": {"chaperone": "latest\n"}}),
            ArgumentError::Version,
        ),
        (
            json!({"components": {"chaperone": marker}}),
            ArgumentError::Version,
        ),
        (
            json!({"components": {"chaperone": 1}}),
            ArgumentError::Shape,
        ),
        (json!({"components": "chaperone"}), ArgumentError::Shape),
        (
            json!({"components": {"chaperone": "1.2.3"}, "path": marker}),
            ArgumentError::Shape,
        ),
        (
            json!({"components": {"chaperone": "1.2.3"}, "kind": marker}),
            ArgumentError::Kind,
        ),
        (
            json!({"components": {"chaperone": "1.2.3"}, "kind": "rollback", "rollback_of": marker}),
            ArgumentError::RollbackOf,
        ),
        (
            json!({"components": {"chaperone": "1.2.3"}, "kind": "rollback", "rollback_of": "Z0000000000000000000000000"}),
            ArgumentError::RollbackOf,
        ),
        (
            json!({"components": {"chaperone": "1.2.3"}, "rollback_of": rollback}),
            ArgumentError::ReleaseWithTarget,
        ),
        (
            json!({"components": {"chaperone": "1.2.3"}, "kind": "rollback"}),
            ArgumentError::RollbackWithoutTarget,
        ),
    ] {
        let error = arguments(bad.clone()).unwrap_err();
        assert_eq!(error, expected, "{bad}");
        assert!(!error.to_string().contains(marker), "{error}");
    }
}

#[test]
fn nothing_is_written_when_the_directory_refuses() {
    let root = tempfile::tempdir().unwrap();
    let release = request(json!({"components": {"chaperone": "1.2.3"}}), [0; 10]);

    let missing = root.path().join("missing");
    assert!(matches!(
        file(&missing, &release),
        Err(FileError::NoDirectory)
    ));
    assert!(!missing.exists());

    let real = root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(matches!(file(&link, &release), Err(FileError::NoDirectory)));
    assert!(names(&real).is_empty());

    for n in 0..8 {
        std::fs::write(real.join(format!("waiting-{n}.json")), b"{}").unwrap();
    }
    assert!(matches!(file(&real, &release), Err(FileError::Full)));
    assert_eq!(names(&real).len(), 8);
}

#[test]
fn a_burst_of_calls_never_files_more_than_the_cap() {
    const CALLS: usize = 32;
    const ROUNDS: u8 = 20;
    for round in 0..ROUNDS {
        let root = tempfile::tempdir().unwrap();
        let barrier = Barrier::new(CALLS);
        let filed = std::thread::scope(|scope| {
            let calls: Vec<_> = (0..CALLS)
                .map(|call| {
                    let barrier = &barrier;
                    let dir = root.path();
                    let mut entropy = [round; 10];
                    entropy[9] = u8::try_from(call).unwrap();
                    scope.spawn(move || {
                        let release =
                            request(json!({"components": {"chaperone": "1.2.3"}}), entropy);
                        barrier.wait();
                        file(dir, &release)
                    })
                })
                .collect();
            calls
                .into_iter()
                .map(|call| call.join().unwrap())
                .filter(Result::is_ok)
                .count()
        });
        let requests = names(root.path())
            .iter()
            .filter(|name| name.ends_with(".json"))
            .count();
        assert_eq!(filed, MAX_PENDING, "round {round}");
        assert_eq!(requests, MAX_PENDING, "round {round}");
    }
}
