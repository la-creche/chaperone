//! The MCP wire model that chaperone checks upstream results against: the
//! official JSON Schema of each protocol version, copied without change
//! into `crates/core/schemas/mcp/` (see the README there). A result is
//! valid only when it is a `CallToolResult` of the version that the
//! upstream negotiated.

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

    /// The pointer to `CallToolResult` inside the schema. Draft 7 keeps
    /// definitions under `definitions`, draft 2020-12 under `$defs`.
    const fn result_pointer(self) -> &'static str {
        match self {
            Self::V2025_06_18 => "#/definitions/CallToolResult",
            Self::V2025_11_25 | Self::V2026_07_28 => "#/$defs/CallToolResult",
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the copied schemas do not compile. chaperone refuses to start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the MCP {version} schema does not compile")]
pub struct SchemaError {
    pub version: ProtocolVersion,
}

/// Why a value is not a `CallToolResult` of its version. It names only a
/// place in the schema, never a place or a value in the input (G9).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("schema: the value breaks {schema_path} of the MCP {version} CallToolResult")]
pub struct ResultError {
    pub version: ProtocolVersion,
    /// A JSON pointer into the copied schema, which is trusted text.
    pub schema_path: String,
}

/// The compiled `CallToolResult` check of every version. The caller builds
/// it once at start and passes it in. Core keeps no global (G3).
pub struct ResultSchemas {
    validators: Vec<(ProtocolVersion, jsonschema::Validator)>,
}

impl fmt::Debug for ResultSchemas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let versions: Vec<ProtocolVersion> = self
            .validators
            .iter()
            .map(|(version, _)| *version)
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
        let mut validators = Vec::new();
        for version in ProtocolVersion::ALL {
            let failed = || SchemaError { version };
            let mut schema: Value =
                serde_json::from_str(version.schema_text()).map_err(|_| failed())?;
            let Value::Object(root) = &mut schema else {
                return Err(failed());
            };
            root.insert(
                "$ref".to_owned(),
                Value::String(version.result_pointer().to_owned()),
            );
            let validator = jsonschema::validator_for(&schema).map_err(|_| failed())?;
            validators.push((version, validator));
        }
        Ok(Self { validators })
    }

    /// Check that `value` is a `CallToolResult` of `version`.
    ///
    /// # Errors
    ///
    /// Returns a [`ResultError`] that names the first schema rule broken.
    pub fn check(&self, version: ProtocolVersion, value: &Value) -> Result<(), ResultError> {
        let Some((_, validator)) = self.validators.iter().find(|(known, _)| *known == version)
        else {
            return Err(ResultError {
                version,
                schema_path: String::new(),
            });
        };
        validator.validate(value).map_err(|error| ResultError {
            version,
            schema_path: error.schema_path().to_string(),
        })
    }
}
