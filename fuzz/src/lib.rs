//! Shared fixtures of the fuzz targets.

use chaperone_core::{Catalog, Found, InstallFile, Location, Manifest, PluginKey, Setup};

fn put(catalog: &mut Catalog, location: Location, text: &str) {
    let Ok(manifest) = Manifest::read(text.as_bytes()) else {
        return;
    };
    catalog.insert(
        PluginKey::from_manifest(&manifest),
        Found { location, manifest },
    );
}

/// The default plugins and one upstream, `vikunja`. No fence.
pub fn setup() -> Option<Setup> {
    let mut catalog = Catalog::new();
    for (plugin, kind, slot) in [
        ("mcp-http", "adapter", "front_door"),
        ("bearer", "decision", "identity"),
        ("secret-files", "adapter", "secret_source"),
        ("audit-jsonl", "adapter", "audit_sink"),
    ] {
        put(
            &mut catalog,
            Location::Default,
            &format!(
                r#"{{"name":"{plugin}","version":"1","kind":"{kind}","slot":"{slot}","hooks":["{slot}"]}}"#
            ),
        );
    }
    put(
        &mut catalog,
        Location::Default,
        r#"{"name":"deny-all","version":"1","kind":"effect","slot":"approval_channel","hooks":["approval"],"command":["deny-all"]}"#,
    );
    put(
        &mut catalog,
        Location::Added,
        r#"{"name":"vikunja","version":"1","kind":"effect","hooks":["upstream"],"command":["vikunja"]}"#,
    );
    let install = InstallFile::read(br#"{"version":1,"plugins":{"vikunja":{}}}"#).ok()?;
    chaperone_core::resolve(&install, &catalog).ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_seed_policy_loads() {
        let setup = super::setup().unwrap();
        let seed = std::fs::read("corpus/policy_load/seed1.json").unwrap();
        chaperone_core::Policy::load(&seed, &setup, &[]).unwrap();
    }
}
