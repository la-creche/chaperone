//! The contract between the registry and the plugin tree: every slot plugin
//! that ships with chaperone has a row, every row names a plugin that
//! ships, and each row builds what its slot needs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::collections::BTreeSet;

use chaperone::catalog;
use chaperone::registry::{Build, ENTRIES, find};
use chaperone_core::{PluginName, Slot};
use support::repo_plugins;

#[test]
fn every_shipped_slot_plugin_has_one_row() {
    let catalog = catalog::discover(&repo_plugins()).unwrap();
    for found in catalog.values() {
        let Some(slot) = found.manifest.slot() else {
            continue;
        };
        let name = found.manifest.name();
        let rows = ENTRIES
            .iter()
            .filter(|entry| entry.slot == slot && entry.name == name.as_str())
            .count();
        assert_eq!(rows, 1, "{name} in the slot {slot} needs one registry row");
        assert!(find(slot, name).is_some());
    }
}

#[test]
fn every_row_names_a_shipped_plugin_in_its_slot() {
    let catalog = catalog::discover(&repo_plugins()).unwrap();
    for entry in ENTRIES {
        let name = PluginName::try_new(entry.name).unwrap();
        let found = catalog
            .values()
            .find(|found| found.manifest.name() == &name)
            .unwrap_or_else(|| panic!("{name} has a registry row and no plugin.json"));
        assert_eq!(
            found.manifest.slot(),
            Some(entry.slot),
            "{name} does not claim the slot {}",
            entry.slot
        );
    }
}

#[test]
fn every_slot_has_a_row_and_no_slot_has_two_names_alike() {
    let mut seen = BTreeSet::new();
    for entry in ENTRIES {
        assert!(
            seen.insert((entry.slot, entry.name)),
            "{} appears twice for the slot {}",
            entry.name,
            entry.slot
        );
    }
    for slot in Slot::ALL {
        assert!(
            ENTRIES.iter().any(|entry| entry.slot == slot),
            "the slot {slot} has no row"
        );
    }
}

#[test]
fn each_row_builds_what_its_slot_needs() {
    for entry in ENTRIES {
        let fits = match (entry.slot, entry.build) {
            (Slot::Identity, Build::Identity(_))
            | (Slot::AuditSink, Build::AuditSink(_))
            | (Slot::FrontDoor, Build::FrontDoor)
            | (Slot::SecretSource | Slot::ApprovalChannel, Build::Later) => true,
            (
                Slot::Identity
                | Slot::AuditSink
                | Slot::FrontDoor
                | Slot::SecretSource
                | Slot::ApprovalChannel,
                Build::Identity(_) | Build::AuditSink(_) | Build::FrontDoor | Build::Later,
            ) => false,
        };
        assert!(
            fits,
            "{} builds the wrong thing for {}",
            entry.name, entry.slot
        );
    }
}

#[test]
fn a_name_outside_the_table_has_no_row() {
    let other = PluginName::try_new("other-identity").unwrap();
    assert!(find(Slot::Identity, &other).is_none());
    let bearer = PluginName::try_new("bearer").unwrap();
    assert!(find(Slot::AuditSink, &bearer).is_none());
}
