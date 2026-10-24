//! The MCP wire model that chaperone checks upstream results against: the
//! official JSON Schema of each protocol version, copied without change
//! into `crates/core/schemas/mcp/` (see the README there). A result is
//! valid only when it is a `CallToolResult` of the version that the
//! upstream negotiated.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::Value;

/// An MCP protocol version that chaperone can check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolVersion {
    V2025_06_18,
    V2025_11_25,
    V2026_07_28,
}

impl ProtocolVersion {
    /// Every version, oldest first.
    pub const ALL: [Self; 3] = [Self::V2025_06_18, Self::V2025_11_25, Self::V2026_07_28];

    /// The version as the protocol writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2025_06_18 => "2025-06-18",
            Self::V2025_11_25 => "2025-11-25",
            Self::V2026_07_28 => "2026-07-28",
        }
    }

    /// The version that `text` names, if chaperone knows it.
    #[must_use]
    pub fn from_wire(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|version| version.as_str() == text)
    }

    fn schema_text(self) -> &'static str {
        match self {
            Self::V2025_06_18 => include_str!("../schemas/mcp/2025-06-18.json"),
            Self::V2025_11_25 => include_str!("../schemas/mcp/2025-11-25.json"),
            Self::V2026_07_28 => include_str!("../schemas/mcp/2026-07-28.json"),
        }
    }

    /// The key that holds the definitions. Draft 7 uses `definitions`,
    /// draft 2020-12 uses `$defs`.
    const fn definitions_key(self) -> &'static str {
        match self {
            Self::V2025_06_18 => "definitions",
            Self::V2025_11_25 | Self::V2026_07_28 => "$defs",
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the copied schemas do not compile. chaperone refuses to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the MCP {version} schema does not compile")]
pub struct SchemaError {
    version: ProtocolVersion,
}

impl SchemaError {
    /// The version whose schema does not compile.
    #[must_use]
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }
}

/// Why a value is not a `CallToolResult` of its version. Only this module
/// builds one. It holds a version and a place in the copied schema, never
/// a key or a value of the input (G9).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{fault} of the MCP {version} CallToolResult")]
pub struct ResultError {
    version: ProtocolVersion,
    fault: ResultFault,
}

/// What a result broke.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResultFault {
    /// A rule of the official schema, at this JSON pointer into the copy.
    Schema(String),
    /// A top-level field that the version's schema does not define.
    UnknownField,
}

impl fmt::Display for ResultFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(path) => write!(f, "schema: the value breaks {path}"),
            Self::UnknownField => f.write_str("unknown_field: a top-level field is not defined"),
        }
    }
}

impl ResultError {
    /// The version whose schema the value broke.
    #[must_use]
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// The JSON pointer into the copied schema. `None` means a top-level
    /// field that the schema does not define.
    #[must_use]
    pub fn schema_path(&self) -> Option<&str> {
        match &self.fault {
            ResultFault::Schema(path) => Some(path),
            ResultFault::UnknownField => None,
        }
    }
}

/// The check of one version: the official schema, and the top-level fields
/// that its `CallToolResult` defines.
struct Checker {
    version: ProtocolVersion,
    validator: jsonschema::Validator,
    fields: BTreeSet<String>,
}

/// The compiled `CallToolResult` check of every version. The caller builds
/// it once at start and passes it in. Core keeps no global (G3).
pub struct ResultSchemas {
    checkers: Vec<Checker>,
}

impl fmt::Debug for ResultSchemas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let versions: Vec<ProtocolVersion> = self
            .checkers
            .iter()
            .map(|checker| checker.version)
            .collect();
        f.debug_struct("ResultSchemas")
            .field("versions", &versions)
            .finish()
    }
}

impl ResultSchemas {
    /// Compile the check of every version.
    ///
    /// # Errors
    ///
    /// Returns a [`SchemaError`] when a copied schema does not compile.
    pub fn compile() -> Result<Self, SchemaError> {
        let mut checkers = Vec::new();
        for version in ProtocolVersion::ALL {
            let failed = || SchemaError { version };
            let mut schema: Value =
                serde_json::from_str(version.schema_text()).map_err(|_| failed())?;
            let definitions = version.definitions_key();
            let fields: BTreeSet<String> = schema
                .get(definitions)
                .and_then(|defs| defs.get("CallToolResult"))
                .and_then(|result| result.get("properties"))
                .and_then(Value::as_object)
                .ok_or_else(failed)?
                .keys()
                .cloned()
                .collect();
            let Value::Object(root) = &mut schema else {
                return Err(failed());
            };
            root.insert(
                "$ref".to_owned(),
                Value::String(format!("#/{definitions}/CallToolResult")),
            );
            let validator = jsonschema::validator_for(&schema).map_err(|_| failed())?;
            checkers.push(Checker {
                version,
                validator,
                fields,
            });
        }
        Ok(Self { checkers })
    }

    /// Check that `value` is a `CallToolResult` of `version`.
    ///
    /// The official schema leaves `additionalProperties` open. chaperone
    /// also refuses a top-level field that the version's `CallToolResult`
    /// does not define, as the strict-wire rule of `AGENTS.md` asks. Nested
    /// shapes follow the official schema (`docs/design.md` 7.7).
    ///
    /// # Errors
    ///
    /// Returns a [`ResultError`] that names the first rule broken.
    pub fn check(&self, version: ProtocolVersion, value: &Value) -> Result<(), ResultError> {
        let Some(checker) = self
            .checkers
            .iter()
            .find(|checker| checker.version == version)
        else {
            return Err(ResultError {
                version,
                fault: ResultFault::Schema(String::new()),
            });
        };
        checker
            .validator
            .validate(value)
            .map_err(|error| ResultError {
                version,
                fault: ResultFault::Schema(error.schema_path().to_string()),
            })?;
        let unknown = value
            .as_object()
            .is_some_and(|members| members.keys().any(|key| !checker.fields.contains(key)));
        if unknown {
            return Err(ResultError {
                version,
                fault: ResultFault::UnknownField,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_version_allows_exactly_its_schema_fields() {
        let schemas = ResultSchemas::compile().unwrap();
        let fields = |version: ProtocolVersion| -> Vec<String> {
            let checker = schemas
                .checkers
                .iter()
                .find(|checker| checker.version == version)
                .unwrap();
            checker.fields.iter().cloned().collect()
        };
        assert_eq!(
            fields(ProtocolVersion::V2025_06_18),
            ["_meta", "content", "isError", "structuredContent"]
        );
        assert_eq!(
            fields(ProtocolVersion::V2026_07_28),
            [
                "_meta",
                "content",
                "isError",
                "resultType",
                "structuredContent"
            ]
        );
    }

    #[test]
    fn an_unknown_top_level_field_is_refused_in_every_version() {
        let schemas = ResultSchemas::compile().unwrap();
        for version in ProtocolVersion::ALL {
            let value = serde_json::json!({
                "content": [],
                "resultType": "complete",
                "unexpected": true,
            });
            let error = schemas.check(version, &value).unwrap_err();
            // 2025 versions also lack resultType, which is itself unknown there.
            assert_eq!(error.schema_path(), None, "{version}");
        }
    }
}
