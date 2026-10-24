//! The purity check of `crates/core` (G3). The clippy lists in
//! `crates/core/clippy.toml` ban single items. This test bans whole
//! modules and types by name, over every source file of the crate. A
//! comment or a doc comment counts too, so a banned name does not even
//! appear in the text.

#![allow(clippy::unwrap_used, reason = "a test fails loudly")]

/// Each source file of the crate, outside its `#[cfg(test)]` module.
const SOURCES: &[(&str, &str)] = &[
    ("audit", include_str!("../src/audit.rs")),
    ("clock", include_str!("../src/clock.rs")),
    ("decide", include_str!("../src/decide.rs")),
    ("exposed", include_str!("../src/exposed.rs")),
    ("gateway", include_str!("../src/gateway.rs")),
    ("hook", include_str!("../src/hook.rs")),
    ("ids", include_str!("../src/ids.rs")),
    ("install", include_str!("../src/install.rs")),
    ("lib", include_str!("../src/lib.rs")),
    ("plugin", include_str!("../src/plugin.rs")),
    ("policy", include_str!("../src/policy.rs")),
    ("secret", include_str!("../src/secret.rs")),
    ("strict", include_str!("../src/strict.rs")),
    ("time", include_str!("../src/time.rs")),
    ("value", include_str!("../src/value.rs")),
];

/// A name that no source file of the crate may contain.
const BANNED: &[&str] = &[
    // I/O, the clock and the environment (G3).
    "std::fs",
    "std::net",
    "std::env",
    "std::process",
    "std::thread",
    "std::os::",
    "SystemTime",
    "Instant",
    "tokio",
    // Randomness, and the collections that hash with a random seed.
    "rand::",
    "getrandom",
    "HashMap",
    "HashSet",
    "RandomState",
    // Global and hidden state.
    "static mut",
    "thread_local",
    "OnceLock",
    "OnceCell",
    "LazyLock",
    "LazyCell",
    "RefCell",
    "Cell<",
    "Mutex",
    "RwLock",
    "Atomic",
];

const TEST_MODULE: &str = "#[cfg(test)]";

/// The part of a file before its test module.
fn non_test(text: &str) -> &str {
    text.split(TEST_MODULE).next().unwrap()
}

#[test]
fn every_module_of_the_crate_is_scanned() {
    let (_, lib) = SOURCES.iter().find(|(name, _)| *name == "lib").unwrap();
    for line in lib.lines() {
        let Some(declared) = line
            .strip_prefix("pub mod ")
            .or_else(|| line.strip_prefix("mod "))
        else {
            continue;
        };
        let module = declared.trim_end_matches(';');
        assert!(
            SOURCES.iter().any(|(name, _)| *name == module),
            "add src/{module}.rs to SOURCES in tests/purity.rs"
        );
    }
}

#[test]
fn no_source_names_a_banned_module_or_type() {
    for (name, text) in SOURCES {
        for banned in BANNED {
            assert!(
                !non_test(text).contains(banned),
                "src/{name}.rs names {banned}, which G3 bans in core"
            );
        }
    }
}
