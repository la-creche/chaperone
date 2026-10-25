//! The JSON Schema of each configuration file, from its Rust types
//! (`docs/design.md` 6). The types are the source of truth. The schema is
//! what the editor and `chaperone schema` show.

use crate::install::install_schema;
use crate::plugin::manifest_schema;
use crate::policy::policy_schema;

/// The schema of each configuration file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigSchemas {
    #[serde(rename = "install.json")]
    pub install: schemars::Schema,
    #[serde(rename = "policy.json")]
    pub policy: schemars::Schema,
    #[serde(rename = "plugin.json")]
    pub plugin: schemars::Schema,
}

/// The schema of each configuration file, from the types that read it.
#[must_use]
pub fn config_schemas() -> ConfigSchemas {
    ConfigSchemas {
        install: install_schema(),
        policy: policy_schema(),
        plugin: manifest_schema(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_schema_is_an_object_that_names_its_properties() {
        let schemas = config_schemas();
        for (name, schema) in [
            ("install", &schemas.install),
            ("policy", &schemas.policy),
            ("plugin", &schemas.plugin),
        ] {
            let value = schema.as_value();
            assert_eq!(value["type"], "object", "{name}");
            assert!(value["properties"].is_object(), "{name}");
            assert_eq!(value["additionalProperties"], false, "{name}");
        }
        let policy = schemas.policy.as_value();
        assert!(policy["properties"]["apps"].is_object());
        assert!(policy["properties"]["$schema"].is_object());
    }
}
