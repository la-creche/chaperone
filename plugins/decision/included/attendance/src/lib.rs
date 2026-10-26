//! The decision half of `attendance` (`docs/design.md` section 12): the
//! families each app instance may reach. Each app instance lists them in
//! its `attendance` section of the policy file. `delegates` fences
//! `invoke_agent` and `enqueue_targets` fences `enqueue`. A call passes
//! only when its `family` argument is on the list for its tool.
//! `job_status` passes untouched, and so does a call to any other upstream.
//!
//! An app instance with no section, or with an empty list for the tool,
//! reaches no family (G2). Each deny reason starts with `tool_not_granted`.
//!
//! The family of an app instance is its app ID. Delegation stays one hop
//! deep. An app instance on any `delegates` list delegates to no family,
//! and no app instance delegates to itself. A policy that breaks either
//! rule does not load.

use std::collections::{BTreeMap, BTreeSet};

use chaperone_core::{
    AppId, ArgValue, CrossAppError, Fence, FenceReason, FenceVerdict, PluginName, PreparedFence,
    RawSection, SectionError, ToolCall,
};
use serde::Deserialize;

/// The argument that names the target family.
const FAMILY_ARG: &str = "family";

/// The most families in `delegates`.
pub const MAX_DELEGATES: usize = 32;

/// The most families in `enqueue_targets`.
pub const MAX_ENQUEUE_TARGETS: usize = 64;

const INVOKE_AGENT: &str = "invoke_agent";
const ENQUEUE: &str = "enqueue";
const JOB_STATUS: &str = "job_status";

const NO_SECOND_HOP: &str =
    "one_hop: an app instance that another app instance delegates to must not delegate";
const NO_SELF_HOP: &str = "one_hop: an app instance must not delegate to itself";

/// A family name: `a-z`, then 1 to 30 of `a-z`, `0-9` and `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
struct Family(String);

impl TryFrom<String> for Family {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if is_family(&text) {
            Ok(Self(text))
        } else {
            Err("a family name is a-z, then 1 to 30 of a-z, 0-9 and -".to_owned())
        }
    }
}

/// Whether `text` is `a-z`, then 1 to 30 of `a-z`, `0-9` and `-`.
fn is_family(text: &str) -> bool {
    let Some((first, rest)) = text.as_bytes().split_first() else {
        return false;
    };
    (1..=30).contains(&rest.len())
        && first.is_ascii_lowercase()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// A key of the `attendance` section. Any other key refuses the section.
/// The section is read as a map of these keys, so a TOML array in place
/// of a table is refused too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum List {
    /// The families `invoke_agent` may ask.
    Delegates,
    /// The families `enqueue` may start a session in.
    EnqueueTargets,
}

/// The `attendance` section of one app instance in the policy file. A
/// missing list is empty.
#[derive(Debug)]
struct Section {
    delegates: BTreeSet<Family>,
    enqueue_targets: BTreeSet<Family>,
}

/// The fence, as the registry builds it.
#[derive(Debug)]
pub struct FamilyFence {
    name: PluginName,
}

impl FamilyFence {
    /// # Errors
    ///
    /// Returns the [`chaperone_core::NameError`] of the plugin name. It
    /// cannot fail for the name in `plugin.toml`.
    pub fn new() -> Result<Self, chaperone_core::NameError> {
        Ok(Self {
            name: PluginName::try_new("attendance")?,
        })
    }
}

/// The fence of one app instance. An app instance with no section has two
/// empty lists.
#[derive(Debug)]
pub struct PreparedFamilyFence {
    upstream: PluginName,
    section: Section,
}

impl Fence for FamilyFence {
    type Prepared = PreparedFamilyFence;

    fn name(&self) -> &PluginName {
        &self.name
    }

    fn prepare(&self, section: Option<RawSection<'_>>) -> Result<Self::Prepared, SectionError> {
        let section = match section {
            None => Section {
                delegates: BTreeSet::new(),
                enqueue_targets: BTreeSet::new(),
            },
            Some(section) => {
                let mut lists: BTreeMap<List, BTreeSet<Family>> = section.parse()?;
                Section {
                    delegates: lists.remove(&List::Delegates).unwrap_or_default(),
                    enqueue_targets: lists.remove(&List::EnqueueTargets).unwrap_or_default(),
                }
            }
        };
        if section.delegates.len() > MAX_DELEGATES {
            return Err(SectionError(format!(
                "delegates lists more than {MAX_DELEGATES} families"
            )));
        }
        if section.enqueue_targets.len() > MAX_ENQUEUE_TARGETS {
            return Err(SectionError(format!(
                "enqueue_targets lists more than {MAX_ENQUEUE_TARGETS} families"
            )));
        }
        Ok(PreparedFamilyFence {
            upstream: self.name.clone(),
            section,
        })
    }

    fn check_sections(
        &self,
        sections: &BTreeMap<&AppId, &Self::Prepared>,
    ) -> Result<(), CrossAppError> {
        let by_family: BTreeMap<&str, (&AppId, &Self::Prepared)> = sections
            .iter()
            .map(|(id, prepared)| (id.as_str(), (*id, *prepared)))
            .collect();
        for (caller, prepared) in sections {
            for family in &prepared.section.delegates {
                let Some((target, reached)) = by_family.get(family.0.as_str()) else {
                    continue;
                };
                let rule = if target == caller {
                    NO_SELF_HOP
                } else if !reached.section.delegates.is_empty() {
                    NO_SECOND_HOP
                } else {
                    continue;
                };
                return Err(CrossAppError {
                    caller: (*caller).clone(),
                    target: (*target).clone(),
                    rule: FenceReason::new(rule),
                });
            }
        }
        Ok(())
    }
}

impl PreparedFence for PreparedFamilyFence {
    fn check(&self, call: &ToolCall<'_>) -> FenceVerdict {
        if *call.upstream != self.upstream {
            return FenceVerdict::Pass;
        }
        let listed = match call.tool.as_str() {
            INVOKE_AGENT => &self.section.delegates,
            ENQUEUE => &self.section.enqueue_targets,
            JOB_STATUS => return FenceVerdict::Pass,
            // DESIGN-QUESTION: docs/design.md 12 names three tools. The
            // reading: a fourth tool of this upstream is denied. A change
            // adds its fence here.
            _ => {
                return FenceVerdict::Deny(FenceReason::new(
                    "tool_not_granted: the attendance fence knows no such tool",
                ));
            }
        };
        if listed.is_empty() {
            return FenceVerdict::Deny(FenceReason::new(
                "tool_not_granted: the app instance lists no family for this tool",
            ));
        }
        let named = match call.arguments.get(FAMILY_ARG) {
            Some(ArgValue::String(family)) => family,
            Some(
                ArgValue::Null
                | ArgValue::Bool(_)
                | ArgValue::Int(_)
                | ArgValue::UInt(_)
                | ArgValue::Float(_)
                | ArgValue::Array(_)
                | ArgValue::Object(_),
            )
            | None => {
                return FenceVerdict::Deny(FenceReason::new(
                    "tool_not_granted: the call names no family as a string",
                ));
            }
        };
        if listed.contains(&Family(named.clone())) {
            return FenceVerdict::Pass;
        }
        FenceVerdict::Deny(FenceReason::new(
            "tool_not_granted: the family is not on the app instance's list for this tool",
        ))
    }
}
