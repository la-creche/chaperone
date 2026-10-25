//! Tests of the decision through the public API: each row of
//! `docs/design.md` 5.2, and the properties G1, G2, G4 and G7.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::collections::{BTreeMap, BTreeSet};

use chaperone_core::{
    AppId, ArgValue, AuditApp, AuditTool, Caller, Catalog, Decision, DenyReason, Fence,
    FenceReason, FenceVerdict, Found, GateId, Gates, InstallFile, Location, Manifest, PluginKey,
    PluginName, Policy, PolicyError, PreparedFence, RawSection, Reach, Request, SectionError,
    Timestamp, TokenDigest, ToolCall, ToolName, strict, with_digest,
};
use proptest::prelude::*;
use serde::Deserialize;

// ---------------------------------------------------------------- fixtures

fn name(text: &str) -> PluginName {
    PluginName::try_new(text).unwrap()
}

fn tool(text: &str) -> ToolName {
    ToolName::try_new(text).unwrap()
}

fn app_id(text: &str) -> AppId {
    AppId::try_new(text).unwrap()
}

fn put(catalog: &mut Catalog, location: Location, text: &str) {
    let manifest = Manifest::read(text.as_bytes()).unwrap();
    catalog.insert(
        PluginKey::from_manifest(&manifest),
        Found { location, manifest },
    );
}

/// The defaults, the `ha-call` pair, a `vikunja` upstream and one extra
/// fence, `zz-extra`, used by the G7 property and the fault test.
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
        Location::Included,
        r#"
            name = "ha-call"
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
            name = "ha-call"
            version = "1"
            kind = "effect"
            hooks = ["upstream"]
            pairs_with = "decision"
            command = ["ha-call"]
        "#,
    );
    put(
        &mut catalog,
        Location::Included,
        r#"
            name = "zz-extra"
            version = "1"
            kind = "decision"
            hooks = ["fence"]
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

const INSTALL: &str = "version = 1\nplugins = { ha-call = {}, vikunja = {} }\n";
const INSTALL_EXTRA: &str =
    "version = 1\nplugins = { ha-call = {}, vikunja = {}, zz-extra = {} }\n";

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn policy_text(extra_section: &str) -> String {
    format!(
        r#"
        version = 1

        [apps.librechat]
        note = "the test app"
        token_sha256 = ["{DIGEST}"]
        limits = {{ calls_per_minute = 3, max_pending_gates = 2 }}

        [apps.librechat.grants.vikunja.tools]
        list_tasks = {{}}
        create_task = {{ approval = "required" }}
        update_task = {{ arguments = {{ project = {{ allow = [1, 2] }} }} }}
        delete_task = {{ arguments = {{ project = {{ deny = [1] }} }} }}

        [apps.librechat.grants.ha-call.tools]
        ha_call = {{}}

        [apps.librechat.plugins]
        ha-call = {{ allow = ["light.kitchen"], gate = ["lock.front"] }}
        {extra_section}
        "#
    )
}

/// The decision half of `ha-call`: an entity allow-list, plus entities that
/// need an approval.
#[derive(Debug)]
struct EntityFence(PluginName);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntitySection {
    allow: BTreeSet<String>,
    #[serde(default)]
    gate: BTreeSet<String>,
}

#[derive(Debug)]
struct PreparedEntities(Option<EntitySection>);

impl Fence for EntityFence {
    fn name(&self) -> &PluginName {
        &self.0
    }

    fn prepare(
        &self,
        section: Option<RawSection<'_>>,
    ) -> Result<Box<dyn PreparedFence>, SectionError> {
        let section = section
            .map(|raw| raw.parse::<EntitySection>())
            .transpose()?;
        Ok(Box::new(PreparedEntities(section)))
    }
}

impl PreparedFence for PreparedEntities {
    fn check(&self, call: &ToolCall<'_>) -> FenceVerdict {
        if call.upstream.as_str() != "ha-call" {
            return FenceVerdict::Pass;
        }
        let Some(section) = &self.0 else {
            return FenceVerdict::Deny(FenceReason::new("no entity allow-list"));
        };
        let entity = match call.arguments.get("entity_id") {
            Some(ArgValue::String(entity)) => entity,
            _ => return FenceVerdict::Deny(FenceReason::new("entity_id is missing")),
        };
        if section.gate.contains(entity) {
            FenceVerdict::Gate
        } else if section.allow.contains(entity) {
            FenceVerdict::Pass
        } else {
            FenceVerdict::Deny(FenceReason::new("entity not allowed"))
        }
    }
}

/// The extra fence. Its verdict is fixed, depends on argument `n`, or is a
/// panic.
#[derive(Debug, Clone, Copy)]
enum Behavior {
    Pass,
    Deny,
    Gate,
    ByArgument,
    /// The fence panics: a plugin fault.
    Fault,
}

#[derive(Debug)]
struct ExtraFence(PluginName, Behavior);

#[derive(Debug)]
struct PreparedExtra(Behavior);

impl Fence for ExtraFence {
    fn name(&self) -> &PluginName {
        &self.0
    }

    fn prepare(
        &self,
        _section: Option<RawSection<'_>>,
    ) -> Result<Box<dyn PreparedFence>, SectionError> {
        Ok(Box::new(PreparedExtra(self.1)))
    }
}

impl PreparedFence for PreparedExtra {
    fn check(&self, call: &ToolCall<'_>) -> FenceVerdict {
        let deny = || FenceVerdict::Deny(FenceReason::new("extra"));
        match self.0 {
            Behavior::Pass => FenceVerdict::Pass,
            Behavior::Deny => deny(),
            Behavior::Gate => FenceVerdict::Gate,
            Behavior::Fault => panic!("plugin fault"),
            Behavior::ByArgument => match call.arguments.get("n") {
                Some(ArgValue::Int(n)) if n % 3 == 0 => deny(),
                Some(ArgValue::Int(n)) if n % 3 == 1 => FenceVerdict::Gate,
                _ => FenceVerdict::Pass,
            },
        }
    }
}

fn load(install: &str, policy: &str, fences: &[&dyn Fence]) -> Result<Policy, PolicyError> {
    let install = InstallFile::read(install.as_bytes()).unwrap();
    let setup = chaperone_core::resolve(&install, &catalog()).unwrap();
    Policy::load(policy.as_bytes(), &setup, fences)
}

fn base_policy() -> Policy {
    let entities = EntityFence(name("ha-call"));
    load(INSTALL, &policy_text(""), &[&entities]).unwrap()
}

fn extended_policy(behavior: Behavior) -> Policy {
    let entities = EntityFence(name("ha-call"));
    let extra = ExtraFence(name("zz-extra"), behavior);
    load(INSTALL_EXTRA, &policy_text(""), &[&entities, &extra]).unwrap()
}

fn caller() -> Caller {
    Caller {
        app: app_id("librechat"),
        reach: Reach::Full,
    }
}

#[test]
fn an_audit_tool_keeps_only_a_configured_name() {
    let policy = base_policy();
    assert_eq!(
        AuditTool::lookup("vikunja__list_tasks", Some(&policy)).as_str(),
        "vikunja__list_tasks"
    );
    assert_eq!(
        AuditTool::lookup("vikunja__not_granted", Some(&policy)).as_str(),
        AuditTool::UNKNOWN
    );
}

#[test]
fn an_audit_app_keeps_only_a_configured_id() {
    let policy = base_policy();
    assert_eq!(
        AuditApp::lookup(Some(&app_id("librechat")), Some(&policy)).as_ref(),
        Some(&app_id("librechat"))
    );
    assert_eq!(
        AuditApp::lookup(Some(&app_id("token-looking-text")), Some(&policy)).as_ref(),
        None
    );
}

fn args(text: &str) -> BTreeMap<String, ArgValue> {
    let value = strict::read_value(text.as_bytes(), strict::ByteCap::new(4096)).unwrap();
    let ArgValue::Object(members) = value else {
        panic!("not an object: {value:?}");
    };
    members
}

/// The gate state of one test.
#[derive(Debug, Default, Clone)]
struct GateBook {
    pending: BTreeMap<GateId, Timestamp>,
    approved: BTreeMap<GateId, Timestamp>,
    denied: BTreeMap<GateId, Timestamp>,
}

impl GateBook {
    fn view(&self) -> Gates<'_> {
        Gates {
            pending: &self.pending,
            approved: &self.approved,
            denied: &self.denied,
        }
    }
}

const NOW: Timestamp = Timestamp::from_unix_millis(1_000_000);
const LATER: Timestamp = Timestamp::from_unix_millis(2_000_000);

#[derive(Debug)]
struct Case {
    caller: Option<Caller>,
    upstream: PluginName,
    tool: ToolName,
    arguments: BTreeMap<String, ArgValue>,
    calls: u32,
    gates: GateBook,
}

impl Case {
    fn new(upstream: &str, tool_name: &str, arguments: &str) -> Self {
        Self {
            caller: Some(caller()),
            upstream: name(upstream),
            tool: tool(tool_name),
            arguments: args(arguments),
            calls: 0,
            gates: GateBook::default(),
        }
    }

    fn gate_id(&self) -> GateId {
        GateId::from_call(&ToolCall {
            app: &app_id("librechat"),
            upstream: &self.upstream,
            tool: &self.tool,
            arguments: &self.arguments,
            now: NOW,
        })
    }

    fn decide(&self, policy: Option<&Policy>) -> Decision {
        chaperone_core::decide(
            policy,
            &Request {
                caller: self.caller.as_ref(),
                upstream: &self.upstream,
                tool: &self.tool,
                arguments: &self.arguments,
                calls_this_minute: self.calls,
                gates: self.gates.view(),
                now: NOW,
            },
        )
    }
}

fn deny(reason: DenyReason) -> Decision {
    Decision::Deny(reason)
}

// -------------------------------------------------------------- the rows

#[test]
fn row_0_no_policy_denies() {
    let case = Case::new("vikunja", "list_tasks", "{}");
    assert_eq!(case.decide(None), deny(DenyReason::PolicyNotLoaded));
}

#[test]
fn row_1_no_caller_or_unknown_app_denies() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "list_tasks", "{}");
    case.caller = None;
    assert_eq!(
        case.decide(Some(&policy)),
        deny(DenyReason::UnknownCredential)
    );

    case.caller = Some(Caller {
        app: app_id("stranger"),
        reach: Reach::Full,
    });
    assert_eq!(
        case.decide(Some(&policy)),
        deny(DenyReason::UnknownCredential)
    );
}

#[test]
fn row_2_the_rate_limit_denies() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "list_tasks", "{}");
    case.calls = 2;
    assert_eq!(case.decide(Some(&policy)), Decision::Allow);
    case.calls = 3;
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::RateLimited));
}

#[test]
fn row_3_a_tool_without_a_grant_denies() {
    let policy = base_policy();
    let case = Case::new("vikunja", "drop_database", "{}");
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::ToolNotGranted));
}

#[test]
fn row_3_a_narrowed_reach_denies_a_granted_tool() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "list_tasks", "{}");
    case.caller = Some(Caller {
        app: app_id("librechat"),
        reach: Reach::Only(BTreeMap::from([(
            name("vikunja"),
            BTreeSet::from([tool("update_task")]),
        )])),
    });
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::ToolNotGranted));
}

#[test]
fn row_4_an_allow_fence_needs_a_listed_value() {
    let policy = base_policy();
    let fenced = || {
        deny(DenyReason::ArgumentFenced {
            argument: chaperone_core::ArgName::try_new("project").unwrap(),
        })
    };
    assert_eq!(
        Case::new("vikunja", "update_task", r#"{"project": 2}"#).decide(Some(&policy)),
        Decision::Allow
    );
    assert_eq!(
        Case::new("vikunja", "update_task", r#"{"project": 3}"#).decide(Some(&policy)),
        fenced()
    );
    assert_eq!(
        Case::new("vikunja", "update_task", r#"{"project": "2"}"#).decide(Some(&policy)),
        fenced()
    );
    assert_eq!(
        Case::new("vikunja", "update_task", "{}").decide(Some(&policy)),
        fenced()
    );
}

#[test]
fn row_4_a_deny_fence_refuses_a_listed_value_and_a_non_scalar() {
    let policy = base_policy();
    let fenced = || {
        deny(DenyReason::ArgumentFenced {
            argument: chaperone_core::ArgName::try_new("project").unwrap(),
        })
    };
    assert_eq!(
        Case::new("vikunja", "delete_task", r#"{"project": 1}"#).decide(Some(&policy)),
        fenced()
    );
    assert_eq!(
        Case::new("vikunja", "delete_task", r#"{"project": [1]}"#).decide(Some(&policy)),
        fenced()
    );
    assert_eq!(
        Case::new("vikunja", "delete_task", r#"{"project": 5}"#).decide(Some(&policy)),
        Decision::Allow
    );
    assert_eq!(
        Case::new("vikunja", "delete_task", "{}").decide(Some(&policy)),
        Decision::Allow
    );
}

#[test]
fn row_5_a_fence_plugin_denies() {
    let policy = base_policy();
    let case = Case::new("ha-call", "ha_call", r#"{"entity_id": "switch.heater"}"#);
    assert_eq!(
        case.decide(Some(&policy)),
        deny(DenyReason::Fence {
            plugin: name("ha-call"),
            reason: FenceReason::new("entity not allowed"),
        })
    );
    let allowed = Case::new("ha-call", "ha_call", r#"{"entity_id": "light.kitchen"}"#);
    assert_eq!(allowed.decide(Some(&policy)), Decision::Allow);
}

#[test]
fn row_5_a_fence_plugin_fault_is_a_deny() {
    let policy = extended_policy(Behavior::Fault);
    let case = Case::new("vikunja", "list_tasks", "{}");
    assert_eq!(
        case.decide(Some(&policy)),
        deny(DenyReason::FenceFault {
            plugin: name("zz-extra"),
        })
    );
}

#[test]
fn row_6_a_gated_call_waits_then_runs_after_approval() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "create_task", r#"{"title": "milk"}"#);
    let id = case.gate_id();
    assert_eq!(case.decide(Some(&policy)), Decision::Gate(id));

    case.gates.pending.insert(id, LATER);
    assert_eq!(case.decide(Some(&policy)), Decision::Gate(id));

    case.gates.pending.clear();
    case.gates.approved.insert(id, LATER);
    assert_eq!(case.decide(Some(&policy)), Decision::Allow);
}

#[test]
fn row_6_a_fence_can_ask_for_a_gate() {
    let policy = base_policy();
    let case = Case::new("ha-call", "ha_call", r#"{"entity_id": "lock.front"}"#);
    assert_eq!(case.decide(Some(&policy)), Decision::Gate(case.gate_id()));
}

#[test]
fn row_6_an_expired_approval_does_not_count() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "create_task", r#"{"title": "milk"}"#);
    let id = case.gate_id();
    case.gates.approved.insert(id, NOW);
    assert_eq!(case.decide(Some(&policy)), Decision::Gate(id));
}

#[test]
fn row_6_a_denied_gate_denies_until_it_expires() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "create_task", r#"{"title": "milk"}"#);
    let id = case.gate_id();
    case.gates.denied.insert(id, LATER);
    case.gates.approved.insert(id, LATER);
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::ApprovalDenied));
}

#[test]
fn row_6_the_pending_cap_denies_a_new_gate() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "create_task", r#"{"title": "milk"}"#);
    let other_a = Case::new("vikunja", "create_task", r#"{"title": "a"}"#).gate_id();
    let other_b = Case::new("vikunja", "create_task", r#"{"title": "b"}"#).gate_id();
    case.gates
        .pending
        .extend([(other_a, LATER), (other_b, LATER)]);
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::GateCap));
}

#[test]
fn row_6_an_expired_pending_gate_does_not_count() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "create_task", r#"{"title": "milk"}"#);
    let id = case.gate_id();
    let other_a = Case::new("vikunja", "create_task", r#"{"title": "a"}"#).gate_id();
    let other_b = Case::new("vikunja", "create_task", r#"{"title": "b"}"#).gate_id();
    case.gates
        .pending
        .extend([(id, NOW), (other_a, NOW), (other_b, NOW)]);
    assert_eq!(case.decide(Some(&policy)), Decision::Gate(id));
    case.gates.pending.insert(other_a, LATER);
    case.gates.pending.insert(other_b, LATER);
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::GateCap));
}

#[test]
fn the_gate_id_ignores_argument_order_and_white_space() {
    let one = Case::new("vikunja", "create_task", r#"{"a": 1, "b": [true]}"#);
    let two = Case::new("vikunja", "create_task", r#"{ "b":[ true ], "a":1 }"#);
    assert_eq!(one.gate_id(), two.gate_id());
    let three = Case::new("vikunja", "create_task", r#"{"a": 2, "b": [true]}"#);
    assert_ne!(one.gate_id(), three.gate_id());
}

// ---------------------------------------------------------- policy loads

fn load_error(policy: &str) -> PolicyError {
    let entities = EntityFence(name("ha-call"));
    load(INSTALL, policy, &[&entities]).unwrap_err()
}

#[test]
fn a_policy_without_the_fence_code_does_not_load() {
    assert_eq!(
        load(INSTALL, &policy_text(""), &[]).unwrap_err(),
        PolicyError::MissingFence(name("ha-call"))
    );
}

#[test]
fn two_fences_of_one_name_do_not_load_in_either_order() {
    let entities = EntityFence(name("ha-call"));
    let twin = ExtraFence(name("ha-call"), Behavior::Pass);
    let expected = PolicyError::DuplicateFence(name("ha-call"));
    assert_eq!(
        load(INSTALL, &policy_text(""), &[&entities, &twin]).unwrap_err(),
        expected
    );
    assert_eq!(
        load(INSTALL, &policy_text(""), &[&twin, &entities]).unwrap_err(),
        expected
    );
}

#[test]
fn a_policy_with_a_bad_plugin_section_does_not_load() {
    let text = policy_text("").replace(r#"gate = ["lock.front"]"#, "gates = []");
    assert!(matches!(load_error(&text), PolicyError::Section { .. }));
}

#[test]
fn a_policy_with_a_section_for_an_inactive_plugin_does_not_load() {
    let text = policy_text("zz-extra = {}");
    assert!(matches!(
        load_error(&text),
        PolicyError::UnknownSection { .. }
    ));
}

#[test]
fn a_policy_that_grants_an_inactive_upstream_does_not_load() {
    let text = policy_text("").replace("grants.vikunja.tools", "grants.nope.tools");
    assert!(matches!(
        load_error(&text),
        PolicyError::UnknownUpstream { .. }
    ));
}

#[test]
fn a_policy_with_three_digests_does_not_load() {
    let text = policy_text("").replace(
        &format!(r#"["{DIGEST}"]"#),
        &format!(
            r#"["{DIGEST}", "{}", "{}"]"#,
            "b".repeat(64),
            "c".repeat(64)
        ),
    );
    assert!(matches!(load_error(&text), PolicyError::DigestCount { .. }));
}

#[test]
fn a_policy_with_an_upper_case_digest_does_not_load() {
    let text = policy_text("").replace(DIGEST, &"A".repeat(64));
    assert!(matches!(load_error(&text), PolicyError::Read(_)));
}

#[test]
fn a_policy_with_an_empty_argument_list_does_not_load() {
    let text = policy_text("").replace("{ allow = [1, 2] }", "{ allow = [] }");
    assert!(matches!(load_error(&text), PolicyError::EmptyFence { .. }));
}

#[test]
fn two_apps_cannot_share_a_digest() {
    let text = policy_text("").replacen(
        "[apps.librechat]\n",
        &format!(
            "[apps.other]\ntoken_sha256 = [\"{DIGEST}\"]\n\
             limits = {{ calls_per_minute = 1, max_pending_gates = 0 }}\n\n[apps.librechat]\n"
        ),
        1,
    );
    assert!(matches!(
        load_error(&text),
        PolicyError::SharedDigest { .. }
    ));
}

#[test]
fn refuses_a_json_policy_file() {
    let text = format!(
        r#"{{"version":1,"apps":{{"librechat":{{"token_sha256":["{DIGEST}"],
            "limits":{{"calls_per_minute":1,"max_pending_gates":0}}}}}}}}"#
    );
    assert!(matches!(
        load_error(&text),
        PolicyError::Read(strict::StrictError::Syntax { line: 1, .. })
    ));
}

#[test]
fn refuses_a_schema_field() {
    let text = format!(
        "\"$schema\" = \"urn:chaperone:policy:1\"\n{}",
        policy_text("")
    );
    assert!(matches!(
        load_error(&text),
        PolicyError::Read(strict::StrictError::Shape { .. })
    ));
}

#[test]
fn reads_comments_in_a_policy_file() {
    let text = policy_text("# The extra fence is not active.").replace(
        "version = 1",
        "# The grants of each app instance.\nversion = 1 # The file shape.",
    );
    let entities = EntityFence(name("ha-call"));
    assert!(load(INSTALL, &text, &[&entities]).is_ok());
}

#[test]
fn reads_a_quoted_tool_name() {
    let text = policy_text("").replace("list_tasks = {}", r#""tasks.list" = {}"#);
    let entities = EntityFence(name("ha-call"));
    let policy = load(INSTALL, &text, &[&entities]).unwrap();
    let app = policy.app(&app_id("librechat")).unwrap();
    assert!(app.grant(&name("vikunja"), &tool("tasks.list")).is_some());
    assert!(app.grant(&name("vikunja"), &tool("list_tasks")).is_none());
}

#[test]
fn a_new_digest_keeps_the_rest_of_the_text() {
    let text = policy_text("").replace(
        &format!(r#"["{DIGEST}"]"#),
        &format!("[\n    \"{DIGEST}\", # The first token.\n]"),
    );
    let after = with_digest(
        text.as_bytes(),
        &app_id("librechat"),
        TokenDigest::from_bytes([0xbb; 32]),
    )
    .unwrap();
    let after = String::from_utf8(after).unwrap();
    assert_eq!(
        after,
        text.replace(
            &format!(r#""{DIGEST}","#),
            &format!(r#""{DIGEST}", "{}","#, "b".repeat(64))
        )
    );
    let entities = EntityFence(name("ha-call"));
    let policy = load(INSTALL, &after, &[&entities]).unwrap();
    assert_eq!(policy.app(&app_id("librechat")).unwrap().digests().len(), 2);
}

// ------------------------------------------------------------ properties

fn arb_case() -> impl Strategy<Value = Case> {
    let call = prop_oneof![
        Just(("vikunja", "list_tasks")),
        Just(("vikunja", "create_task")),
        Just(("vikunja", "update_task")),
        Just(("vikunja", "delete_task")),
        Just(("vikunja", "not_granted")),
        Just(("ha-call", "ha_call")),
    ];
    let entity = prop_oneof![
        Just("light.kitchen"),
        Just("lock.front"),
        Just("switch.heater")
    ];
    (
        call,
        entity,
        -5_i64..5,
        0_i64..4,
        0_u32..5,
        any::<(bool, bool, bool)>(),
        0_usize..3,
        any::<bool>(),
    )
        .prop_map(
            |((upstream, tool_name), entity, n, project, calls, flags, others, narrow)| {
                let text =
                    format!(r#"{{"entity_id": "{entity}", "n": {n}, "project": {project}}}"#);
                let mut case = Case::new(upstream, tool_name, &text);
                case.calls = calls;
                let id = case.gate_id();
                let (pending, approved, denied) = flags;
                if pending {
                    case.gates.pending.insert(id, LATER);
                }
                if approved {
                    case.gates.approved.insert(id, LATER);
                }
                if denied {
                    case.gates.denied.insert(id, LATER);
                }
                for index in 0..others {
                    let other =
                        Case::new("vikunja", "create_task", &format!(r#"{{"i": {index}}}"#));
                    case.gates.pending.insert(other.gate_id(), LATER);
                }
                if narrow {
                    case.caller = Some(Caller {
                        app: app_id("librechat"),
                        reach: Reach::Only(BTreeMap::from([(
                            name("vikunja"),
                            BTreeSet::from([tool("list_tasks")]),
                        )])),
                    });
                }
                case
            },
        )
}

fn arb_behavior() -> impl Strategy<Value = Behavior> {
    prop_oneof![
        Just(Behavior::Pass),
        Just(Behavior::Deny),
        Just(Behavior::Gate),
        Just(Behavior::ByArgument),
        Just(Behavior::Fault),
    ]
}

proptest! {
    /// G1: the same input gives the same decision.
    #[test]
    fn g1_the_decision_is_deterministic(case in arb_case()) {
        let policy = base_policy();
        prop_assert_eq!(case.decide(Some(&policy)), case.decide(Some(&policy)));
    }

    /// G7: adding a fence never turns a deny or a gate into an allow, and
    /// never turns a deny into anything else.
    #[test]
    fn g7_a_new_fence_only_narrows(case in arb_case(), behavior in arb_behavior()) {
        let base = case.decide(Some(&base_policy()));
        let extended = case.decide(Some(&extended_policy(behavior)));
        match base {
            Decision::Allow => {}
            Decision::Gate(_) => prop_assert_ne!(extended, Decision::Allow),
            Decision::Deny(_) => prop_assert!(matches!(extended, Decision::Deny(_))),
        }
    }

    /// G4: a narrowed reach never allows what the full reach does not.
    #[test]
    fn g4_a_narrowed_reach_only_narrows(mut case in arb_case()) {
        let policy = base_policy();
        case.caller = Some(caller());
        let full = case.decide(Some(&policy));
        case.caller = Some(Caller {
            app: app_id("librechat"),
            reach: Reach::Only(BTreeMap::from([(name("vikunja"), BTreeSet::from([tool("list_tasks")]))])),
        });
        let narrow = case.decide(Some(&policy));
        if full != Decision::Allow {
            prop_assert_ne!(narrow, Decision::Allow);
        }
    }

    /// G2: a strict prefix of a valid policy does not load, or it grants
    /// nothing beyond the whole file.
    // DESIGN-QUESTION: docs/design.md 6. TOML has no closing delimiter, so a
    // policy file cut at the end of a line can still load. This test takes
    // the reading that such a cut may only narrow, which holds for this
    // fixture. A tool grant written as a table, with its arguments in a later
    // table, can lose its fence to a cut. A required end marker in the file
    // would close that gap, and it would change the file shape.
    #[test]
    fn g2_a_cut_policy_only_narrows(cut in 0_usize..1000) {
        let text = policy_text("");
        let end = cut.min(text.len() - 1);
        prop_assume!(text.is_char_boundary(end));
        let entities = EntityFence(name("ha-call"));
        let whole = load(INSTALL, &text, &[&entities]).unwrap();
        let Ok(prefix) = load(INSTALL, &text[..end], &[&entities]) else {
            return Ok(());
        };
        for (id, app) in prefix.apps() {
            let full = whole.app(id).unwrap();
            prop_assert_eq!(app.limits(), full.limits());
            for (upstream, tool) in app.granted() {
                let grant = app.grant(upstream, tool).unwrap();
                let original = full.grant(upstream, tool);
                prop_assert!(original.is_some(), "{upstream} {tool}");
                let original = original.unwrap();
                prop_assert_eq!(grant.approval(), original.approval());
                prop_assert_eq!(grant.arguments(), original.arguments());
            }
        }
    }

    /// No input makes a reader panic.
    #[test]
    fn readers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = InstallFile::read(&bytes);
        let _ = Manifest::read(&bytes);
        let entities = EntityFence(name("ha-call"));
        let _ = load(INSTALL, &String::from_utf8_lossy(&bytes), &[&entities]);
    }
}
