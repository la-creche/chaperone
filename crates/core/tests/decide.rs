//! Tests of the decision through the public API: each row of
//! `docs/design.md` 5.2, and the properties G1, G2, G4 and G7.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

use std::collections::{BTreeMap, BTreeSet};

use chaperone_core::{
    AppId, ArgValue, AuditApp, AuditTool, Caller, Catalog, CrossAppError, Decision, DenyReason,
    Fence, FenceCode, FenceReason, FenceVerdict, Found, GateId, Gates, InstallFile, Location,
    Manifest, PluginKey, PluginName, Policy, PolicyError, PreparedFence, RawSection, Reach,
    Request, SectionError, Timestamp, TokenDigest, ToolCall, ToolName, UpstreamBound, strict,
    with_digest,
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
    type Prepared = PreparedEntities;

    fn name(&self) -> &PluginName {
        &self.0
    }

    fn prepare(&self, section: Option<RawSection<'_>>) -> Result<Self::Prepared, SectionError> {
        let section = section
            .map(|raw| raw.parse::<EntitySection>())
            .transpose()?;
        Ok(PreparedEntities(section))
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
    type Prepared = PreparedExtra;

    fn name(&self) -> &PluginName {
        &self.0
    }

    fn prepare(&self, _section: Option<RawSection<'_>>) -> Result<Self::Prepared, SectionError> {
        Ok(PreparedExtra(self.1))
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

fn load(install: &str, policy: &str, fences: &[&dyn FenceCode]) -> Result<Policy, PolicyError> {
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
    in_flight: u32,
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
            in_flight: 0,
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
                calls_in_flight: self.in_flight,
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
fn row_6_a_full_in_flight_limit_denies() {
    let policy = limited(&inflight_policy("2"));
    let mut case = Case::new("vikunja", "list_tasks", "{}");
    case.in_flight = 1;
    assert_eq!(case.decide(Some(&policy)), Decision::Allow);
    case.in_flight = 2;
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::RateLimited));

    // The limit comes before the gate, so a full limit opens no gate.
    let gated = Case {
        in_flight: 2,
        ..Case::new("vikunja", "create_task", "{}")
    };
    assert_eq!(gated.decide(Some(&policy)), deny(DenyReason::RateLimited));

    // A call that an earlier row denies keeps the reason of that row.
    let ungranted = Case {
        in_flight: 2,
        ..Case::new("vikunja", "drop_database", "{}")
    };
    assert_eq!(
        ungranted.decide(Some(&policy)),
        deny(DenyReason::ToolNotGranted)
    );
}

#[test]
fn row_6_the_limit_counts_only_its_own_upstream() {
    let policy = limited(&inflight_policy("1"));
    let mut case = Case::new("ha-call", "ha_call", r#"{"entity_id": "light.kitchen"}"#);
    case.in_flight = 5;
    assert_eq!(case.decide(Some(&policy)), Decision::Allow);

    let mut unlimited = Case::new("vikunja", "list_tasks", "{}");
    unlimited.in_flight = 100;
    assert_eq!(unlimited.decide(Some(&base_policy())), Decision::Allow);
}

#[test]
fn row_6_an_identical_call_of_a_live_gate_skips_the_limit() {
    let policy = limited(&inflight_policy("1"));
    let mut case = Case::new("vikunja", "create_task", r#"{"title": "milk"}"#);
    case.in_flight = 1;
    let id = case.gate_id();

    // The run of an approved gate holds the only slot. An identical call
    // reads its gate: it waits, collects the result or is denied.
    case.gates.pending.insert(id, LATER);
    assert_eq!(case.decide(Some(&policy)), Decision::Gate(id));
    case.gates.pending.clear();
    case.gates.approved.insert(id, LATER);
    assert_eq!(case.decide(Some(&policy)), Decision::Allow);
    case.gates.approved.clear();
    case.gates.denied.insert(id, LATER);
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::ApprovalDenied));

    // An expired gate does not count, so the limit denies.
    case.gates.denied.insert(id, NOW);
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::RateLimited));
}

#[test]
fn row_6_only_a_gated_call_of_its_own_gate_skips_the_limit() {
    let policy = limited(&inflight_policy("1"));

    // The live gate of another call does not lift the limit.
    let mut other = Case::new("vikunja", "create_task", r#"{"title": "milk"}"#);
    other.in_flight = 1;
    let bread = Case::new("vikunja", "create_task", r#"{"title": "bread"}"#).gate_id();
    other.gates.pending.insert(bread, LATER);
    assert_eq!(other.decide(Some(&policy)), deny(DenyReason::RateLimited));

    // A call that no row gates runs, so a gate with its ID does not lift
    // the limit.
    let mut ungated = Case::new("vikunja", "list_tasks", "{}");
    ungated.in_flight = 1;
    let id = ungated.gate_id();
    ungated.gates.approved.insert(id, LATER);
    assert_eq!(ungated.decide(Some(&policy)), deny(DenyReason::RateLimited));
}

#[test]
fn row_7_a_gated_call_waits_then_runs_after_approval() {
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
fn row_7_a_fence_can_ask_for_a_gate() {
    let policy = base_policy();
    let case = Case::new("ha-call", "ha_call", r#"{"entity_id": "lock.front"}"#);
    assert_eq!(case.decide(Some(&policy)), Decision::Gate(case.gate_id()));
}

#[test]
fn row_7_an_expired_approval_does_not_count() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "create_task", r#"{"title": "milk"}"#);
    let id = case.gate_id();
    case.gates.approved.insert(id, NOW);
    assert_eq!(case.decide(Some(&policy)), Decision::Gate(id));
}

#[test]
fn row_7_a_denied_gate_denies_until_it_expires() {
    let policy = base_policy();
    let mut case = Case::new("vikunja", "create_task", r#"{"title": "milk"}"#);
    let id = case.gate_id();
    case.gates.denied.insert(id, LATER);
    case.gates.approved.insert(id, LATER);
    assert_eq!(case.decide(Some(&policy)), deny(DenyReason::ApprovalDenied));
}

#[test]
fn row_7_the_pending_cap_denies_a_new_gate() {
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
fn row_7_an_expired_pending_gate_does_not_count() {
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

/// The fault of the app `librechat`, which the load of `policy` refuses.
/// The file itself loads.
fn refusal(policy: &str) -> PolicyError {
    let entities = EntityFence(name("ha-call"));
    let loaded = load(INSTALL, policy, &[&entities]).unwrap();
    let librechat = app_id("librechat");
    assert!(loaded.app(&librechat).is_none());
    let refused: BTreeMap<&AppId, &PolicyError> = loaded.refused().collect();
    refused.get(&librechat).copied().unwrap().clone()
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
fn a_bad_plugin_section_refuses_its_app() {
    let text = policy_text("").replace(r#"gate = ["lock.front"]"#, "gates = []");
    assert!(matches!(refusal(&text), PolicyError::Section { .. }));
}

#[test]
fn a_section_for_an_inactive_plugin_refuses_its_app() {
    let text = policy_text("zz-extra = {}");
    assert!(matches!(refusal(&text), PolicyError::UnknownSection { .. }));
}

#[test]
fn a_grant_of_an_inactive_upstream_refuses_its_app() {
    let text = policy_text("").replace("grants.vikunja.tools", "grants.nope.tools");
    assert!(matches!(
        refusal(&text),
        PolicyError::UnknownUpstream { .. }
    ));
}

#[test]
fn three_digests_refuse_their_app() {
    let text = policy_text("").replace(
        &format!(r#"["{DIGEST}"]"#),
        &format!(
            r#"["{DIGEST}", "{}", "{}"]"#,
            "b".repeat(64),
            "c".repeat(64)
        ),
    );
    assert!(matches!(refusal(&text), PolicyError::DigestCount { .. }));
}

#[test]
fn an_upper_case_digest_refuses_its_app() {
    let text = policy_text("").replace(DIGEST, &"A".repeat(64));
    assert!(matches!(refusal(&text), PolicyError::AppShape { .. }));
}

#[test]
fn an_empty_argument_list_refuses_its_app() {
    let text = policy_text("").replace("{ allow = [1, 2] }", "{ allow = [] }");
    assert!(matches!(refusal(&text), PolicyError::EmptyFence { .. }));
}

/// The fixture policy with a second app, `other`, before `librechat`.
/// `other` holds the token digest `digest` and grants nothing.
fn with_other_app(policy: &str, digest: &str) -> String {
    policy.replacen(
        "[apps.librechat]\n",
        &format!(
            "[apps.other]\ntoken_sha256 = [\"{digest}\"]\n\
             limits = {{ calls_per_minute = 1, max_pending_gates = 0 }}\n\n[apps.librechat]\n"
        ),
        1,
    )
}

#[test]
fn two_apps_that_share_a_digest_are_both_refused() {
    let entities = EntityFence(name("ha-call"));
    let loaded = load(
        INSTALL,
        &with_other_app(&policy_text(""), DIGEST),
        &[&entities],
    )
    .unwrap();
    let refused: Vec<&AppId> = loaded.refused().map(|(app, _)| app).collect();
    assert_eq!(refused, [&app_id("librechat"), &app_id("other")]);
    assert!(
        loaded
            .refused()
            .all(|(_, error)| matches!(error, PolicyError::SharedDigest { .. }))
    );
    assert_eq!(loaded.apps().count(), 0);
}

#[test]
fn a_refused_app_leaves_the_other_apps_loaded() {
    let bad = policy_text("").replace("grants.vikunja.tools", "grants.nope.tools");
    let entities = EntityFence(name("ha-call"));
    let loaded = load(
        INSTALL,
        &with_other_app(&bad, &"b".repeat(64)),
        &[&entities],
    )
    .unwrap();
    assert!(loaded.app(&app_id("other")).is_some());
    assert!(loaded.app(&app_id("librechat")).is_none());
    assert!(matches!(refusal(&bad), PolicyError::UnknownUpstream { .. }));
}

#[test]
fn each_call_of_a_refused_app_is_denied() {
    let bad = policy_text("").replace("grants.vikunja.tools", "grants.nope.tools");
    let entities = EntityFence(name("ha-call"));
    let loaded = load(INSTALL, &bad, &[&entities]).unwrap();
    let case = Case::new("ha-call", "ha_call", r#"{"entity_id": "light.kitchen"}"#);
    assert_eq!(
        case.decide(Some(&loaded)),
        deny(DenyReason::UnknownCredential)
    );
}

/// A fence whose section lists apps that its app must not share the
/// policy with: a rule across apps, for the tests of [`Policy::load`].
#[derive(Debug)]
struct BlockFence(PluginName);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockSection {
    blocks: BTreeSet<String>,
}

#[derive(Debug)]
struct PreparedBlocks(BTreeSet<String>);

impl Fence for BlockFence {
    type Prepared = PreparedBlocks;

    fn name(&self) -> &PluginName {
        &self.0
    }

    fn prepare(&self, section: Option<RawSection<'_>>) -> Result<Self::Prepared, SectionError> {
        let section = section.map(|raw| raw.parse::<BlockSection>()).transpose()?;
        Ok(PreparedBlocks(
            section.map(|one| one.blocks).unwrap_or_default(),
        ))
    }

    fn check_sections(
        &self,
        sections: &BTreeMap<&AppId, &Self::Prepared>,
    ) -> Result<(), CrossAppError> {
        for (caller, prepared) in sections {
            for target in sections.keys() {
                if prepared.0.contains(target.as_str()) {
                    return Err(CrossAppError {
                        caller: (*caller).clone(),
                        target: (*target).clone(),
                        rule: FenceReason::new("blocked"),
                    });
                }
            }
        }
        Ok(())
    }
}

impl PreparedFence for PreparedBlocks {
    fn check(&self, _call: &ToolCall<'_>) -> FenceVerdict {
        FenceVerdict::Pass
    }
}

#[test]
fn a_rule_across_apps_refuses_its_caller_alone() {
    let text = with_other_app(
        &policy_text(r#"zz-extra = { blocks = ["other"] }"#),
        &"b".repeat(64),
    );
    let entities = EntityFence(name("ha-call"));
    let blocks = BlockFence(name("zz-extra"));
    let loaded = load(INSTALL_EXTRA, &text, &[&entities, &blocks]).unwrap();
    assert!(loaded.app(&app_id("other")).is_some());
    let refused: Vec<(&AppId, &PolicyError)> = loaded.refused().collect();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].0, &app_id("librechat"));
    assert!(matches!(refused[0].1, PolicyError::CrossApp { .. }));
}

/// The fixture policy with `timeout_s = <value>` on the `vikunja` grant.
fn bounded_policy(value: &str) -> String {
    policy_text("").replace(
        "[apps.librechat.grants.vikunja.tools]",
        &format!("[apps.librechat.grants.vikunja]\ntimeout_s = {value}\n\n[apps.librechat.grants.vikunja.tools]"),
    )
}

#[test]
fn an_upstream_grant_without_a_bound_takes_30_seconds() {
    let app = base_policy();
    let app = app.app(&app_id("librechat")).unwrap();
    assert_eq!(
        app.upstream_bound(&name("vikunja")),
        Some(UpstreamBound::DEFAULT)
    );
    assert_eq!(UpstreamBound::DEFAULT.seconds(), 30);
    assert_eq!(app.upstream_bound(&name("nope")), None);
}

#[test]
fn an_upstream_grant_sets_its_own_bound() {
    let entities = EntityFence(name("ha-call"));
    for seconds in [1, 120] {
        let policy = load(INSTALL, &bounded_policy(&seconds.to_string()), &[&entities]).unwrap();
        let app = policy.app(&app_id("librechat")).unwrap();
        let bound = app.upstream_bound(&name("vikunja")).unwrap();
        assert_eq!(bound.seconds(), seconds);
    }
}

#[test]
fn a_bound_outside_1_to_120_seconds_refuses_its_app() {
    for value in ["0", "121", "-1"] {
        let error = refusal(&bounded_policy(value));
        assert_eq!(
            error,
            PolicyError::UpstreamBound {
                app: app_id("librechat"),
                upstream: name("vikunja"),
            }
        );
        assert!(error.to_string().contains("1 to 120"), "{error}");
    }
}

#[test]
fn a_bound_that_is_not_an_integer_refuses_its_app() {
    for value in ["1.5", r#""30""#, "true"] {
        assert!(matches!(
            refusal(&bounded_policy(value)),
            PolicyError::AppShape { .. }
        ));
    }
}

/// The fixture policy with `max_inflight = <value>` on the `vikunja` grant.
fn inflight_policy(value: &str) -> String {
    policy_text("").replace(
        "[apps.librechat.grants.vikunja.tools]",
        &format!("[apps.librechat.grants.vikunja]\nmax_inflight = {value}\n\n[apps.librechat.grants.vikunja.tools]"),
    )
}

/// Load `policy` with the `ha-call` fence.
fn limited(policy: &str) -> Policy {
    let entities = EntityFence(name("ha-call"));
    load(INSTALL, policy, &[&entities]).unwrap()
}

#[test]
fn an_upstream_grant_without_max_inflight_has_no_limit() {
    let policy = base_policy();
    let app = policy.app(&app_id("librechat")).unwrap();
    assert_eq!(app.inflight_limit(&name("vikunja")), None);
}

#[test]
fn an_upstream_grant_sets_its_own_in_flight_limit() {
    for count in [1, 8] {
        let policy = limited(&inflight_policy(&count.to_string()));
        let app = policy.app(&app_id("librechat")).unwrap();
        let limit = app.inflight_limit(&name("vikunja")).unwrap();
        assert_eq!(limit.get(), count);
        assert_eq!(app.inflight_limit(&name("ha-call")), None);
    }
}

#[test]
fn an_in_flight_limit_outside_1_to_8_refuses_its_app() {
    for value in ["0", "9", "-1"] {
        let error = refusal(&inflight_policy(value));
        assert_eq!(
            error,
            PolicyError::InflightLimit {
                app: app_id("librechat"),
                upstream: name("vikunja"),
            }
        );
        assert!(error.to_string().contains("1 to 8"), "{error}");
    }
}

#[test]
fn an_in_flight_limit_that_is_not_an_integer_refuses_its_app() {
    for value in ["1.5", r#""2""#, "true"] {
        assert!(matches!(
            refusal(&inflight_policy(value)),
            PolicyError::AppShape { .. }
        ));
    }
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
