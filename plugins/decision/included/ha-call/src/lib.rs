//! The decision half of `ha-call` (`docs/design.md` section 12): an entity
//! allow-list for Home Assistant calls. Each app instance lists the
//! entities it may act on in its `ha-call` section of the policy file. A
//! call to the `ha-call` upstream passes only when every entity it names
//! is on that list. A call to any other upstream passes untouched.
//!
//! The fence denies a call with no `entity_id`, because a service call
//! without a target can act on every entity of its domain. An app instance
//! with no section may act on nothing (G2).

use std::collections::{BTreeMap, BTreeSet};

use chaperone_core::{
    ArgValue, Fence, FenceReason, FenceVerdict, PluginName, PreparedFence, RawSection,
    SectionError, ToolCall,
};
use serde::Deserialize;

/// The argument that names the entities a call acts on.
const ENTITY_ARG: &str = "entity_id";

/// The longest entity ID the section accepts, in bytes.
const ENTITY_MAX: usize = 255;

/// The `ha-call` section of one app instance in the policy file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    /// The entities the app instance may act on, as `domain.object_id`.
    entities: BTreeSet<String>,
}

/// Whether `text` has the form of an entity ID: `domain.object_id`, each
/// part of `a-z`, `0-9` and `_`.
fn is_entity_id(text: &str) -> bool {
    let Some((domain, object)) = text.split_once('.') else {
        return false;
    };
    let is_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    };
    text.len() <= ENTITY_MAX && is_part(domain) && is_part(object)
}

/// The fence, as the registry builds it.
#[derive(Debug)]
pub struct EntityFence {
    name: PluginName,
}

impl EntityFence {
    /// # Errors
    ///
    /// Returns the [`chaperone_core::NameError`] of the plugin name. It
    /// cannot fail for the name in `plugin.json`.
    pub fn new() -> Result<Self, chaperone_core::NameError> {
        Ok(Self {
            name: PluginName::try_new("ha-call")?,
        })
    }
}

/// The fence of one app instance.
#[derive(Debug)]
struct PreparedEntityFence {
    upstream: PluginName,
    /// The allow-list, or `None` for an app instance with no section.
    entities: Option<BTreeSet<String>>,
}

impl Fence for EntityFence {
    fn name(&self) -> &PluginName {
        &self.name
    }

    fn prepare(
        &self,
        section: Option<RawSection<'_>>,
    ) -> Result<Box<dyn PreparedFence>, SectionError> {
        let entities = match section {
            None => None,
            Some(section) => {
                let parsed: Section = section.parse()?;
                if let Some(bad) = parsed.entities.iter().find(|text| !is_entity_id(text)) {
                    return Err(SectionError(format!(
                        "the entity {bad:?} is not domain.object_id of a-z, 0-9 and _"
                    )));
                }
                Some(parsed.entities)
            }
        };
        Ok(Box::new(PreparedEntityFence {
            upstream: self.name.clone(),
            entities,
        }))
    }
}

impl PreparedFence for PreparedEntityFence {
    fn check(&self, call: &ToolCall<'_>) -> FenceVerdict {
        if *call.upstream != self.upstream {
            return FenceVerdict::Pass;
        }
        let Some(entities) = &self.entities else {
            return FenceVerdict::Deny(FenceReason::new(
                "the app instance has no ha-call section, so it may act on no entity",
            ));
        };
        let Some(named) = call.arguments.get(ENTITY_ARG) else {
            return FenceVerdict::Deny(FenceReason::new(
                "the call names no entity_id, and a call without a target acts on every entity",
            ));
        };
        if every_entity_listed(named, entities) {
            return FenceVerdict::Pass;
        }
        FenceVerdict::Deny(FenceReason::new(
            "the call names an entity that is not on the app instance's allow-list",
        ))
    }
}

/// Whether `named` is one listed entity, or a non-empty list of them.
fn every_entity_listed(named: &ArgValue, entities: &BTreeSet<String>) -> bool {
    match named {
        ArgValue::String(entity) => entities.contains(entity),
        ArgValue::Array(items) => {
            !items.is_empty()
                && items.iter().all(|item| match item {
                    ArgValue::String(entity) => entities.contains(entity),
                    ArgValue::Null
                    | ArgValue::Bool(_)
                    | ArgValue::Int(_)
                    | ArgValue::UInt(_)
                    | ArgValue::Float(_)
                    | ArgValue::Array(_)
                    | ArgValue::Object(_) => false,
                })
        }
        ArgValue::Null
        | ArgValue::Bool(_)
        | ArgValue::Int(_)
        | ArgValue::UInt(_)
        | ArgValue::Float(_)
        | ArgValue::Object(_) => false,
    }
}

/// The arguments of a call, for tests and callers that build them by hand.
#[must_use]
pub fn arguments(entity: &str) -> BTreeMap<String, ArgValue> {
    BTreeMap::from([(ENTITY_ARG.to_owned(), ArgValue::String(entity.to_owned()))])
}
