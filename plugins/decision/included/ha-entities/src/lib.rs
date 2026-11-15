//! A fence on the entity domains that a call to a Home Assistant upstream
//! may name (`docs/design.md` section 12). Each app instance maps an
//! upstream to the domains it may read in its `ha-entities` section of the
//! policy file. A call to a listed upstream that carries `entity_id` passes
//! only when every entity it names is `domain.object_id` of a listed
//! domain.
//!
//! Home Assistant answers a read of an entity that the user of the token
//! may not read with a 401. Its IP ban counts each 401 as a failed login,
//! so a few such reads ban the host of chaperone. The fence denies those
//! calls before they reach Home Assistant.
//!
//! A call without `entity_id` passes untouched. So does a call to an
//! upstream that the section does not list, and every call of an app
//! instance with no section.

use std::collections::{BTreeMap, BTreeSet};

use chaperone_core::{
    ArgValue, Fence, FenceReason, FenceVerdict, PluginName, PreparedFence, RawSection,
    SectionError, ToolCall,
};
use serde::Deserialize;

/// The argument that names the entities a call reads or acts on.
const ENTITY_ARG: &str = "entity_id";

/// The longest entity ID the fence passes, in bytes.
const ENTITY_MAX: usize = 255;

/// The `ha-entities` section of one app instance in the policy file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    /// The domains each upstream may name, by upstream.
    upstreams: BTreeMap<PluginName, BTreeSet<String>>,
}

/// Whether `text` is one part of an entity ID: `a-z`, `0-9` and `_`.
fn is_part(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// The domain of `text`, when `text` has the form `domain.object_id`.
fn domain_of(text: &str) -> Option<&str> {
    let (domain, object) = text.split_once('.')?;
    (text.len() <= ENTITY_MAX && is_part(domain) && is_part(object)).then_some(domain)
}

/// The fence, as the registry builds it.
#[derive(Debug)]
pub struct DomainFence {
    name: PluginName,
}

impl DomainFence {
    /// # Errors
    ///
    /// Returns the [`chaperone_core::NameError`] of the plugin name. It
    /// cannot fail for the name in `plugin.toml`.
    pub fn new() -> Result<Self, chaperone_core::NameError> {
        Ok(Self {
            name: PluginName::try_new("ha-entities")?,
        })
    }
}

/// The fence of one app instance.
#[derive(Debug)]
pub struct PreparedDomainFence {
    /// The domains of each fenced upstream. Empty for an app instance with
    /// no section.
    upstreams: BTreeMap<PluginName, BTreeSet<String>>,
}

impl Fence for DomainFence {
    type Prepared = PreparedDomainFence;

    fn name(&self) -> &PluginName {
        &self.name
    }

    fn prepare(&self, section: Option<RawSection<'_>>) -> Result<Self::Prepared, SectionError> {
        let Some(section) = section else {
            return Ok(PreparedDomainFence {
                upstreams: BTreeMap::new(),
            });
        };
        let parsed: Section = section.parse()?;
        if parsed.upstreams.is_empty() {
            return Err(SectionError(
                "the section lists no upstream, so it fences nothing".to_owned(),
            ));
        }
        let bad = parsed
            .upstreams
            .values()
            .flatten()
            .find(|text| !is_part(text));
        if let Some(bad) = bad {
            return Err(SectionError(format!(
                "the domain {bad:?} is not one or more of a-z, 0-9 and _"
            )));
        }
        Ok(PreparedDomainFence {
            upstreams: parsed.upstreams,
        })
    }
}

impl PreparedFence for PreparedDomainFence {
    fn check(&self, call: &ToolCall<'_>) -> FenceVerdict {
        let Some(domains) = self.upstreams.get(call.upstream) else {
            return FenceVerdict::Pass;
        };
        let Some(named) = call.arguments.get(ENTITY_ARG) else {
            return FenceVerdict::Pass;
        };
        if every_domain_listed(named, domains) {
            return FenceVerdict::Pass;
        }
        FenceVerdict::Deny(FenceReason::new(
            "the call names an entity outside the domains the app instance may read",
        ))
    }
}

/// Whether `named` is one entity of a listed domain, or a non-empty list of
/// them.
fn every_domain_listed(named: &ArgValue, domains: &BTreeSet<String>) -> bool {
    match named {
        ArgValue::String(entity) => is_listed(entity, domains),
        ArgValue::Array(items) => {
            !items.is_empty()
                && items.iter().all(|item| match item {
                    ArgValue::String(entity) => is_listed(entity, domains),
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

/// Whether `entity` is `domain.object_id` of a listed domain.
fn is_listed(entity: &str, domains: &BTreeSet<String>) -> bool {
    domain_of(entity).is_some_and(|domain| domains.contains(domain))
}

/// The arguments of a call, for tests and callers that build them by hand.
#[must_use]
pub fn arguments(entity: &str) -> BTreeMap<String, ArgValue> {
    BTreeMap::from([(ENTITY_ARG.to_owned(), ArgValue::String(entity.to_owned()))])
}
