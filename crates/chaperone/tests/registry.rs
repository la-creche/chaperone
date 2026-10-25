//! The contract between the registry and the plugin tree. Every slot plugin
//! that ships with chaperone has a row. Every row names a plugin that
//! ships. Each row builds what its slot needs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly on a bad fixture"
)]

mod support;

use std::collections::BTreeSet;

use chaperone::catalog;
use chaperone::registry::{Build, ENTRIES, FENCES, find, find_fence};
use chaperone_core::{Hook, PluginKind, PluginName, Slot};
use support::repo_plugins;

#[test]
fn every_shipped_slot_plugin_has_one_row() {
    let catalog = catalog::discover(&repo_plugins()).unwrap();
    for found in catalog.values() {
        let Some(slot) = found.manifest.slot() else {
            continue;
        };
        // An effect plugin runs as a process. The host needs no row for it.
        if slot.hook().kind() == PluginKind::Effect {
            continue;
        }
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
        if slot.hook().kind() == PluginKind::Effect {
            continue;
        }
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
            | (Slot::Clock, Build::Clock(_))
            | (Slot::SecretSource, Build::SecretSource(_)) => true,
            (
                Slot::Identity
                | Slot::AuditSink
                | Slot::FrontDoor
                | Slot::SecretSource
                | Slot::ApprovalChannel
                | Slot::Clock,
                Build::Identity(_)
                | Build::AuditSink(_)
                | Build::Clock(_)
                | Build::SecretSource(_)
                | Build::FrontDoor,
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

#[test]
fn every_shipped_fence_has_one_row_and_every_row_a_fence() {
    let catalog = catalog::discover(&repo_plugins()).unwrap();
    let shipped: BTreeSet<&str> = catalog
        .values()
        .filter(|found| found.manifest.kind() == PluginKind::Decision)
        .filter(|found| found.manifest.serves(Hook::Fence))
        .map(|found| found.manifest.name().as_str())
        .collect();
    let rows: BTreeSet<&str> = FENCES.iter().map(|entry| entry.name).collect();
    assert_eq!(shipped, rows);
    assert_eq!(rows.len(), FENCES.len(), "a fence appears twice");
    for entry in FENCES {
        let name = PluginName::try_new(entry.name).unwrap();
        assert!(find_fence(&name).is_some());
        assert_eq!((entry.build)().unwrap().name(), &name);
    }
}
