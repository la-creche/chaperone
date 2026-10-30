//! The family fence through the real path: a loaded policy with an
//! `attendance` section, and the decision function. It covers what the
//! fence passes and what it denies. It also covers the two properties of
//! `plugins/decision/AGENTS.md`. The same input gives the same verdict. No
//! input makes it panic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::collections::BTreeMap;

use chaperone_core::{
    AppId, ArgValue, Caller, Catalog, Decision, DenyReason, Found, Gates, InstallFile, Location,
    Manifest, PluginKey, PluginName, Policy, PolicyError, Reach, Request, Timestamp, ToolName,
    decide, resolve,
};
use chaperone_plugin_attendance_fence::FamilyFence;
use proptest::prelude::*;

const SECTION: &str = r#"{ delegates = ["research"], enqueue_targets = ["builder", "research"] }"#;
const INSTALL: &str = r#"
version = 1
plugins.vikunja = {}
plugins.attendance = {}
"#;

fn put(catalog: &mut Catalog, location: Location, text: &str) {
    let manifest = Manifest::read(text.as_bytes()).unwrap();
    catalog.insert(
        PluginKey::from_manifest(&manifest),
        Found { location, manifest },
    );
}

/// The slot defaults, both halves of `attendance` and a `vikunja` upstream.
fn catalog() -> Catalog {
    let mut catalog = Catalog::new();
    for (name, kind, slot) in [
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
                    name = "{name}"
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
        Location::Included,
        r#"
            name = "attendance"
            version = "1"
            kind = "decision"
            hooks = ["fence"]
            pairs_with = "effect"
        "#,
    );
    put(
        &mut catalog,
        Location::Included,
        r#"
            name = "attendance"
            version = "1"
            kind = "effect"
            hooks = ["upstream"]
            pairs_with = "decision"
            command = ["chaperone-attendance"]
        "#,
    );
    put(
        &mut catalog,
        Location::Added,
        r#"
            name = "vikunja"
            version = "1"
            kind = "effect"
            hooks = ["upstream"]
            command = ["vikunja"]
        "#,
    );
    catalog
}

/// A policy with one app instance that may call every tool of both
/// upstreams, with the given `attendance` section.
fn load(section: Option<&str>) -> Result<Policy, PolicyError> {
    load_apps(&[("librechat", section)])
}

/// A policy with these app instances, each with its `attendance` section.
fn load_apps(apps: &[(&str, Option<&str>)]) -> Result<Policy, PolicyError> {
    let install = InstallFile::read(INSTALL.as_bytes()).unwrap();
    let setup = resolve(&install, &catalog()).unwrap();
    let mut text = "version = 1\n".to_owned();
    for (index, (app, section)) in apps.iter().enumerate() {
        let plugins = section.map_or(String::new(), |text| {
            format!("plugins.attendance = {text}\n")
        });
        text.push_str(&format!(
            r#"
            [apps.{app}]
            token_sha256 = ["{}"]
            limits = {{ calls_per_minute = 100, max_pending_gates = 1 }}
            grants.attendance.tools.invoke_agent = {{}}
            grants.attendance.tools.enqueue = {{}}
            grants.attendance.tools.job_status = {{}}
            grants.attendance.tools.other = {{}}
            grants.vikunja.tools.list_tasks = {{}}
            {plugins}"#,
            format!("{index:x}").repeat(64)
        ));
    }
    let fence = FamilyFence::new().unwrap();
    Policy::load(text.as_bytes(), &setup, &[&fence])
}

/// The app IDs and the rule of a cross-app refusal.
fn refused_pair(error: &PolicyError) -> (&str, &str, &str) {
    let PolicyError::CrossApp { plugin, error } = error else {
        panic!("not a cross-app refusal: {error}");
    };
    assert_eq!(plugin.as_str(), "attendance");
    (
        error.caller.as_str(),
        error.target.as_str(),
        error.rule.as_str(),
    )
}

/// The one app that `policy` refused, and its fault.
fn only_refusal(policy: &Policy) -> (&str, &PolicyError) {
    let refused: Vec<(&AppId, &PolicyError)> = policy.refused().collect();
    let [(app, error)] = refused.as_slice() else {
        panic!("not one refused app: {refused:?}");
    };
    (app.as_str(), error)
}

/// `policy`, after a check that it refused no app.
fn whole(policy: Policy) -> Policy {
    assert_eq!(policy.refused().count(), 0, "{policy:?}");
    policy
}

fn decision(
    policy: &Policy,
    upstream: &str,
    tool: &str,
    arguments: &BTreeMap<String, ArgValue>,
) -> Decision {
    let caller = Caller {
        app: AppId::try_new("librechat").unwrap(),
        reach: Reach::Full,
    };
    let none = BTreeMap::new();
    decide(
        Some(policy),
        &Request {
            caller: Some(&caller),
            upstream: &PluginName::try_new(upstream).unwrap(),
            tool: &ToolName::try_new(tool).unwrap(),
            arguments,
            calls_this_minute: 0,
            calls_in_flight: 0,
            gates: Gates {
                pending: &none,
                approved: &none,
                denied: &none,
            },
            now: Timestamp::from_unix_millis(0),
        },
    )
}

fn family(name: &str) -> BTreeMap<String, ArgValue> {
    BTreeMap::from([
        ("family".to_owned(), ArgValue::String(name.to_owned())),
        ("message".to_owned(), ArgValue::String("hello".to_owned())),
    ])
}

/// The decision of `tool` of the `attendance` upstream with `arguments`.
fn attend(policy: &Policy, tool: &str, arguments: &BTreeMap<String, ArgValue>) -> Decision {
    decision(policy, "attendance", tool, arguments)
}

fn is_not_granted(decision: &Decision) -> bool {
    matches!(
        decision,
        Decision::Deny(DenyReason::Fence { reason, .. })
            if reason.as_str().starts_with("tool_not_granted")
    )
}

#[test]
fn a_listed_family_passes_for_its_tool() {
    let policy = load(Some(SECTION)).unwrap();
    assert_eq!(
        attend(&policy, "invoke_agent", &family("research")),
        Decision::Allow
    );
    assert_eq!(
        attend(&policy, "enqueue", &family("builder")),
        Decision::Allow
    );
    assert_eq!(
        attend(&policy, "enqueue", &family("research")),
        Decision::Allow
    );
}

#[test]
fn a_family_not_on_the_list_of_its_tool_is_denied() {
    let policy = load(Some(SECTION)).unwrap();
    // `builder` is an enqueue target, not a delegate.
    let denied = attend(&policy, "invoke_agent", &family("builder"));
    assert!(is_not_granted(&denied), "{denied:?}");
    let denied = attend(&policy, "enqueue", &family("finance"));
    assert!(is_not_granted(&denied), "{denied:?}");
}

#[test]
fn an_app_without_a_section_reaches_no_family() {
    let policy = load(None).unwrap();
    for tool in ["invoke_agent", "enqueue"] {
        let denied = attend(&policy, tool, &family("research"));
        assert!(is_not_granted(&denied), "{tool}: {denied:?}");
    }
}

#[test]
fn an_empty_list_for_the_tool_reaches_no_family() {
    let policy = load(Some(r#"{ delegates = ["research"] }"#)).unwrap();
    let denied = attend(&policy, "enqueue", &family("research"));
    assert!(is_not_granted(&denied), "{denied:?}");
    assert_eq!(
        attend(&policy, "invoke_agent", &family("research")),
        Decision::Allow
    );
    let policy = load(Some("{ delegates = [], enqueue_targets = [] }")).unwrap();
    let denied = attend(&policy, "invoke_agent", &family("research"));
    assert!(is_not_granted(&denied), "{denied:?}");
}

#[test]
fn a_call_with_no_family_text_is_denied() {
    let policy = load(Some(SECTION)).unwrap();
    let denied = attend(&policy, "invoke_agent", &BTreeMap::new());
    assert!(is_not_granted(&denied), "{denied:?}");
    let number = BTreeMap::from([("family".to_owned(), ArgValue::Int(7))]);
    let denied = attend(&policy, "enqueue", &number);
    assert!(is_not_granted(&denied), "{denied:?}");
}

#[test]
fn job_status_and_another_upstream_pass_and_another_tool_is_denied() {
    for section in [Some(SECTION), None] {
        let policy = load(section).unwrap();
        assert_eq!(
            attend(&policy, "job_status", &BTreeMap::new()),
            Decision::Allow
        );
        assert_eq!(
            decision(&policy, "vikunja", "list_tasks", &family("x")),
            Decision::Allow
        );
        let denied = attend(&policy, "other", &family("research"));
        assert!(is_not_granted(&denied), "{denied:?}");
    }
}

#[test]
fn a_bad_section_refuses_its_app() {
    let too_many = |count: usize, field: &str| {
        let names: Vec<String> = (0..count).map(|index| format!("\"f{index:03}\"")).collect();
        format!("{{ {field} = [{}] }}", names.join(", "))
    };
    for bad in [
        r#"{ delegates = ["research"], extra = 1 }"#.to_owned(),
        r#"{ delegates = ["Research"] }"#.to_owned(),
        r#"{ delegates = ["r"] }"#.to_owned(),
        r#"{ enqueue_targets = ["9lives"] }"#.to_owned(),
        r#"{ delegates = "research" }"#.to_owned(),
        too_many(33, "delegates"),
        too_many(65, "enqueue_targets"),
        "[]".to_owned(),
    ] {
        let policy = load(Some(&bad)).unwrap();
        let (app, error) = only_refusal(&policy);
        assert_eq!(app, "librechat");
        assert!(
            matches!(error, PolicyError::Section { .. }),
            "{bad}: {error}"
        );
    }
    whole(load(Some(&too_many(32, "delegates"))).unwrap());
    whole(load(Some(&too_many(64, "enqueue_targets"))).unwrap());
}

#[test]
fn a_delegate_target_that_delegates_refuses_the_caller() {
    let policy = load_apps(&[
        ("alpha", Some(r#"{ delegates = ["beta"] }"#)),
        ("beta", Some(r#"{ delegates = ["gamma"] }"#)),
        ("gamma", None),
    ])
    .unwrap();
    let (app, error) = only_refusal(&policy);
    assert_eq!(app, "alpha");
    assert_eq!(policy.apps().count(), 2);
    let (caller, target, rule) = refused_pair(error);
    assert_eq!((caller, target), ("alpha", "beta"));
    assert!(rule.starts_with("one_hop"), "{rule}");
    let shown = error.to_string();
    assert!(shown.contains("alpha") && shown.contains("beta"), "{shown}");
}

#[test]
fn a_star_of_callers_around_one_target_loads() {
    whole(
        load_apps(&[
            ("alpha", Some(r#"{ delegates = ["hub"] }"#)),
            (
                "beta",
                Some(r#"{ delegates = ["hub"], enqueue_targets = ["alpha"] }"#),
            ),
            ("gamma", Some(r#"{ delegates = ["hub", "outside"] }"#)),
            ("hub", Some(r#"{ enqueue_targets = ["alpha"] }"#)),
        ])
        .unwrap(),
    );
}

#[test]
fn an_app_that_delegates_to_itself_is_refused() {
    let policy = load_apps(&[
        ("alpha", Some(r#"{ enqueue_targets = ["beta"] }"#)),
        ("beta", Some(r#"{ delegates = ["beta"] }"#)),
    ])
    .unwrap();
    let (app, error) = only_refusal(&policy);
    assert_eq!(app, "beta");
    assert!(policy.app(&AppId::try_new("alpha").unwrap()).is_some());
    let (caller, target, rule) = refused_pair(error);
    assert_eq!((caller, target), ("beta", "beta"));
    assert!(rule.contains("itself"), "{rule}");
}

#[test]
fn a_delegate_target_with_no_section_loads() {
    load_apps(&[
        ("alpha", Some(r#"{ delegates = ["beta"] }"#)),
        ("beta", None),
    ])
    .unwrap();
}

fn arg_value() -> impl Strategy<Value = ArgValue> {
    let leaf = prop_oneof![
        Just(ArgValue::Null),
        any::<bool>().prop_map(ArgValue::Bool),
        any::<i64>().prop_map(ArgValue::Int),
        "[a-z0-9-]{0,20}".prop_map(ArgValue::String),
        Just(ArgValue::String("research".into())),
    ];
    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(ArgValue::Array),
            prop::collection::btree_map("[a-z_]{1,8}", inner, 0..4).prop_map(ArgValue::Object),
        ]
    })
}

proptest! {
    #[test]
    fn the_same_input_gives_the_same_decision_and_never_panics(
        value in arg_value(),
        with_section in any::<bool>(),
        tool in prop_oneof![Just("invoke_agent"), Just("enqueue"), Just("job_status")],
    ) {
        let policy = load(with_section.then_some(SECTION)).unwrap();
        let arguments = BTreeMap::from([("family".to_owned(), value)]);
        let first = attend(&policy, tool, &arguments);
        let second = attend(&policy, tool, &arguments);
        prop_assert_eq!(&first, &second);
        prop_assert!(!matches!(first, Decision::Gate(_)));
        prop_assert_eq!(
            decision(&policy, "vikunja", "list_tasks", &arguments),
            Decision::Allow
        );
    }
}
