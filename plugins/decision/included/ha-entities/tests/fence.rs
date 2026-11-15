//! The domain fence through the real path: a loaded policy with an
//! `ha-entities` section, and the decision function. It covers what the
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
use chaperone_plugin_ha_entities_fence::{DomainFence, arguments};
use proptest::prelude::*;

const SECTION: &str = r#"{ upstreams = { ha-read = ["light", "sun"] } }"#;
const INSTALL: &str = r#"
version = 1
plugins.ha-entities = {}
plugins.ha-read = {}
plugins.vikunja = {}
"#;

fn put(catalog: &mut Catalog, location: Location, text: &str) {
    let manifest = Manifest::read(text.as_bytes()).unwrap();
    catalog.insert(
        PluginKey::from_manifest(&manifest),
        Found { location, manifest },
    );
}

/// The slot defaults, the fence, and the `ha-read` and `vikunja` upstreams.
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
            name = "ha-entities"
            version = "1"
            kind = "decision"
            hooks = ["fence"]
        "#,
    );
    for name in ["ha-read", "vikunja"] {
        put(
            &mut catalog,
            Location::Added,
            &format!(
                r#"
                    name = "{name}"
                    version = "1"
                    kind = "effect"
                    hooks = ["upstream"]
                    command = ["{name}"]
                "#
            ),
        );
    }
    catalog
}

/// A policy with one app instance that may call both upstreams, with the
/// given `ha-entities` section.
fn load(section: Option<&str>) -> Result<Policy, PolicyError> {
    let install = InstallFile::read(INSTALL.as_bytes()).unwrap();
    let setup = resolve(&install, &catalog()).unwrap();
    let plugins = section.map_or(String::new(), |text| {
        format!("plugins.ha-entities = {text}\n")
    });
    let text = format!(
        r#"
        version = 1

        [apps.principal]
        token_sha256 = ["{}"]
        limits = {{ calls_per_minute = 100, max_pending_gates = 1 }}
        grants.ha-read.tools.ha_get_state = {{}}
        grants.ha-read.tools.ha_search = {{}}
        grants.vikunja.tools.list_tasks = {{}}
        {plugins}"#,
        "0".repeat(64)
    );
    let fence = DomainFence::new().unwrap();
    Policy::load(text.as_bytes(), &setup, &[&fence])
}

fn decision(
    policy: &Policy,
    upstream: &str,
    tool: &str,
    arguments: &BTreeMap<String, ArgValue>,
) -> Decision {
    let caller = Caller {
        app: AppId::try_new("principal").unwrap(),
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

fn get_state(policy: &Policy, arguments: &BTreeMap<String, ArgValue>) -> Decision {
    decision(policy, "ha-read", "ha_get_state", arguments)
}

fn is_fenced(decision: &Decision) -> bool {
    matches!(decision, Decision::Deny(DenyReason::Fence { .. }))
}

fn entity_list(entities: &[&str]) -> BTreeMap<String, ArgValue> {
    let items = entities
        .iter()
        .map(|entity| ArgValue::String((*entity).to_owned()))
        .collect();
    BTreeMap::from([("entity_id".to_owned(), ArgValue::Array(items))])
}

#[test]
fn a_listed_domain_passes_and_an_unlisted_one_is_denied() {
    let policy = load(Some(SECTION)).unwrap();
    assert_eq!(get_state(&policy, &arguments("sun.sun")), Decision::Allow);
    assert_eq!(
        get_state(&policy, &arguments("light.hallway")),
        Decision::Allow
    );
    for hidden in ["automation.morning", "zone.home", "person.someone"] {
        let denied = get_state(&policy, &arguments(hidden));
        assert!(is_fenced(&denied), "{hidden}: {denied:?}");
    }
}

#[test]
fn a_list_passes_only_when_every_domain_is_listed() {
    let policy = load(Some(SECTION)).unwrap();
    assert_eq!(
        get_state(&policy, &entity_list(&["sun.sun", "light.hallway"])),
        Decision::Allow
    );
    assert!(is_fenced(&get_state(
        &policy,
        &entity_list(&["sun.sun", "script.cover"])
    )));
    assert!(is_fenced(&get_state(&policy, &entity_list(&[]))));
}

#[test]
fn an_entity_not_of_the_form_domain_dot_object_is_denied() {
    let policy = load(Some(SECTION)).unwrap();
    for text in [
        "sun",
        "sun.",
        ".sun",
        "Sun.sun",
        "sun.sun,automation.morning",
        r#"["sun.sun", "automation.morning"]"#,
        " sun.sun",
    ] {
        let denied = get_state(&policy, &arguments(text));
        assert!(is_fenced(&denied), "{text}: {denied:?}");
    }
    let long = format!("sun.{}", "a".repeat(252));
    assert!(is_fenced(&get_state(&policy, &arguments(&long))));
    let number = BTreeMap::from([("entity_id".to_owned(), ArgValue::Int(7))]);
    assert!(is_fenced(&get_state(&policy, &number)));
}

#[test]
fn a_call_without_an_entity_passes() {
    let policy = load(Some(SECTION)).unwrap();
    let query = BTreeMap::from([("query".to_owned(), ArgValue::String("pico".into()))]);
    assert_eq!(
        decision(&policy, "ha-read", "ha_search", &query),
        Decision::Allow
    );
}

#[test]
fn an_unlisted_upstream_passes_untouched() {
    for section in [Some(SECTION), None] {
        let policy = load(section).unwrap();
        assert_eq!(
            decision(
                &policy,
                "vikunja",
                "list_tasks",
                &arguments("automation.morning")
            ),
            Decision::Allow
        );
    }
}

#[test]
fn an_app_without_a_section_passes_untouched() {
    let policy = load(None).unwrap();
    assert_eq!(
        get_state(&policy, &arguments("automation.morning")),
        Decision::Allow
    );
}

#[test]
fn an_empty_domain_list_denies_every_entity() {
    let policy = load(Some(r"{ upstreams = { ha-read = [] } }")).unwrap();
    assert!(is_fenced(&get_state(&policy, &arguments("sun.sun"))));
}

#[test]
fn a_bad_section_refuses_its_app() {
    for bad in [
        r"{ upstreams = {} }",
        r#"{ upstreams = { ha-read = ["Light"] } }"#,
        r#"{ upstreams = { ha-read = ["light.kitchen"] } }"#,
        r#"{ upstreams = { ha-read = [""] } }"#,
        r#"{ upstreams = { ha__read = ["light"] } }"#,
        r#"{ upstreams = { ha-read = "light" } }"#,
        r#"{ upstreams = { ha-read = ["light"] }, extra = 1 }"#,
        "[]",
    ] {
        let policy = load(Some(bad)).unwrap();
        let refused: Vec<(&AppId, &PolicyError)> = policy.refused().collect();
        let [(app, error)] = refused.as_slice() else {
            panic!("{bad}: not one refused app: {refused:?}");
        };
        assert_eq!(app.as_str(), "principal");
        assert!(
            matches!(error, PolicyError::Section { .. }),
            "{bad}: {error}"
        );
    }
}

fn arg_value() -> impl Strategy<Value = ArgValue> {
    let leaf = prop_oneof![
        Just(ArgValue::Null),
        any::<bool>().prop_map(ArgValue::Bool),
        any::<i64>().prop_map(ArgValue::Int),
        "[a-z._ ,\\[\\]\"]{0,20}".prop_map(ArgValue::String),
        Just(ArgValue::String("sun.sun".into())),
        Just(ArgValue::String("automation.morning".into())),
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
    ) {
        let policy = load(with_section.then_some(SECTION)).unwrap();
        let arguments = BTreeMap::from([("entity_id".to_owned(), value)]);
        let first = get_state(&policy, &arguments);
        let second = get_state(&policy, &arguments);
        prop_assert_eq!(&first, &second);
        prop_assert!(!matches!(first, Decision::Gate(_)));
        prop_assert_eq!(
            decision(&policy, "vikunja", "list_tasks", &arguments),
            Decision::Allow
        );
    }
}
