//! The entity fence through the real path: a loaded policy with an
//! `ha-call` section, and the decision function. It covers what the fence
//! passes and what it denies. It also covers the two properties of
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
use chaperone_plugin_ha_call_fence::{EntityFence, arguments};
use proptest::prelude::*;

const SECTION: &str = r#"{"entities":["light.kitchen","switch.fan_1"]}"#;
const INSTALL: &str =
    r#"{"version":1,"plugins":{"ha-call":{"secrets":{"HA_TOKEN":"ha_token"}},"vikunja":{}}}"#;

fn put(catalog: &mut Catalog, location: Location, text: &str) {
    let manifest = Manifest::read(text.as_bytes()).unwrap();
    catalog.insert(
        PluginKey::from_manifest(&manifest),
        Found { location, manifest },
    );
}

/// The slot defaults, both halves of `ha-call` and a `vikunja` upstream.
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
                r#"{{"name":"{name}","version":"1","kind":"{kind}","slot":"{slot}","hooks":["{slot}"]}}"#
            ),
        );
    }
    put(
        &mut catalog,
        Location::Default,
        r#"{"name":"deny-all","version":"1","kind":"effect","slot":"approval_channel",
            "hooks":["approval"],"command":["deny-all"]}"#,
    );
    put(
        &mut catalog,
        Location::Included,
        r#"{"name":"ha-call","version":"1","kind":"decision","hooks":["fence"],"pairs_with":"effect"}"#,
    );
    put(
        &mut catalog,
        Location::Included,
        r#"{"name":"ha-call","version":"1","kind":"effect","hooks":["upstream"],
            "secrets":["HA_TOKEN"],"pairs_with":"decision","command":["chaperone-ha-call"]}"#,
    );
    put(
        &mut catalog,
        Location::Added,
        r#"{"name":"vikunja","version":"1","kind":"effect","hooks":["upstream"],"command":["vikunja"]}"#,
    );
    catalog
}

/// A policy with one app instance that may call both upstreams, with the
/// given `ha-call` section.
fn load(section: Option<&str>) -> Result<Policy, PolicyError> {
    let install = InstallFile::read(INSTALL.as_bytes()).unwrap();
    let setup = resolve(&install, &catalog()).unwrap();
    let plugins = section.map_or(String::new(), |text| {
        format!(r#","plugins":{{"ha-call":{text}}}"#)
    });
    let text = format!(
        r#"{{"version":1,"apps":{{"librechat":{{
            "token_sha256":["{}"],
            "limits":{{"calls_per_minute":100,"max_pending_gates":1}},
            "grants":{{
                "ha-call":{{"tools":{{"call_service":{{}}}}}},
                "vikunja":{{"tools":{{"list_tasks":{{}}}}}}
            }}{plugins}
        }}}}}}"#,
        "0".repeat(64)
    );
    let fence = EntityFence::new().unwrap();
    Policy::load(text.as_bytes(), &setup, &[&fence])
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
            gates: Gates {
                pending: &none,
                approved: &none,
                denied: &none,
            },
            now: Timestamp::from_unix_millis(0),
        },
    )
}

fn is_fenced(decision: &Decision) -> bool {
    matches!(decision, Decision::Deny(DenyReason::Fence { .. }))
}

#[test]
fn a_listed_entity_passes_and_an_unlisted_one_is_denied() {
    let policy = load(Some(SECTION)).unwrap();
    assert_eq!(
        decision(
            &policy,
            "ha-call",
            "call_service",
            &arguments("light.kitchen")
        ),
        Decision::Allow
    );
    let denied = decision(
        &policy,
        "ha-call",
        "call_service",
        &arguments("light.bedroom"),
    );
    assert!(is_fenced(&denied), "{denied:?}");
}

#[test]
fn a_list_passes_only_when_every_entity_is_listed() {
    let policy = load(Some(SECTION)).unwrap();
    let listed = BTreeMap::from([(
        "entity_id".to_owned(),
        ArgValue::Array(vec![
            ArgValue::String("light.kitchen".into()),
            ArgValue::String("switch.fan_1".into()),
        ]),
    )]);
    assert_eq!(
        decision(&policy, "ha-call", "call_service", &listed),
        Decision::Allow
    );
    let mixed = BTreeMap::from([(
        "entity_id".to_owned(),
        ArgValue::Array(vec![
            ArgValue::String("light.kitchen".into()),
            ArgValue::String("light.bedroom".into()),
        ]),
    )]);
    assert!(is_fenced(&decision(
        &policy,
        "ha-call",
        "call_service",
        &mixed
    )));
    let empty = BTreeMap::from([("entity_id".to_owned(), ArgValue::Array(vec![]))]);
    assert!(is_fenced(&decision(
        &policy,
        "ha-call",
        "call_service",
        &empty
    )));
}

#[test]
fn no_entity_and_a_non_text_entity_are_denied() {
    let policy = load(Some(SECTION)).unwrap();
    assert!(is_fenced(&decision(
        &policy,
        "ha-call",
        "call_service",
        &BTreeMap::new()
    )));
    let number = BTreeMap::from([("entity_id".to_owned(), ArgValue::Int(7))]);
    assert!(is_fenced(&decision(
        &policy,
        "ha-call",
        "call_service",
        &number
    )));
}

#[test]
fn another_upstream_passes_untouched() {
    for section in [Some(SECTION), None] {
        let policy = load(section).unwrap();
        assert_eq!(
            decision(&policy, "vikunja", "list_tasks", &BTreeMap::new()),
            Decision::Allow
        );
    }
}

#[test]
fn an_app_without_a_section_may_act_on_no_entity() {
    let policy = load(None).unwrap();
    assert!(is_fenced(&decision(
        &policy,
        "ha-call",
        "call_service",
        &arguments("light.kitchen")
    )));
}

#[test]
fn a_bad_section_does_not_load() {
    for bad in [
        r#"{"entities":["kitchen"]}"#,
        r#"{"entities":["Light.Kitchen"]}"#,
        r#"{"entities":["light.kitchen"],"extra":1}"#,
        r#"{"entities":"light.kitchen"}"#,
        r#"[]"#,
    ] {
        let error = load(Some(bad)).unwrap_err();
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
        "[a-z._ ]{0,20}".prop_map(ArgValue::String),
        Just(ArgValue::String("light.kitchen".into())),
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
        let first = decision(&policy, "ha-call", "call_service", &arguments);
        let second = decision(&policy, "ha-call", "call_service", &arguments);
        prop_assert_eq!(&first, &second);
        prop_assert!(!matches!(first, Decision::Gate(_)));
        prop_assert_eq!(
            decision(&policy, "vikunja", "list_tasks", &arguments),
            Decision::Allow
        );
    }
}
