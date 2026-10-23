//! The `Secret` type (G9). It has no `Display` and no `Serialize`. Its
//! `Debug` prints only the name. The value is wiped when the `Secret` drops.
//! [`Secret::expose`] is the one way to read the value, and clippy flags
//! each call to it outside this crate.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};

use crate::ids::SecretName;

/// A credential that chaperone holds for a plugin.
pub struct Secret {
    name: SecretName,
    value: SecretString,
}

impl Secret {
    /// Wrap `value` under `name`.
    #[must_use]
    pub fn new(name: SecretName, value: String) -> Self {
        Self {
            name,
            value: SecretString::from(value),
        }
    }

    /// The name of the secret. A log line may show it.
    #[must_use]
    pub fn name(&self) -> &SecretName {
        &self.name
    }

    /// The value of the secret. Each caller outside this crate needs an
    /// `#[expect(clippy::disallowed_methods, reason = "...")]`.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.value.expose_secret()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({})", self.name)
    }
}

/// The bearer token an app sends with a call. Like a [`Secret`], it has no
/// `Display` and no `Serialize`, and its `Debug` hides the value.
pub struct Bearer(SecretString);

impl Bearer {
    /// Wrap the token text from a request.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self(SecretString::from(token))
    }

    /// The token text. An identity plugin hashes it and drops it.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bearer(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(Secret: fmt::Display, serde::Serialize, Clone);
    assert_not_impl_any!(Bearer: fmt::Display, serde::Serialize, Clone);

    #[test]
    fn debug_shows_the_name_and_not_the_value() {
        let secret = Secret::new(SecretName::new("ha_token").unwrap(), "hunter2".into());
        let shown = format!("{secret:?}");
        assert_eq!(shown, "Secret(ha_token)");
        assert!(!shown.contains("hunter2"));
    }

    #[test]
    fn bearer_debug_hides_the_token() {
        assert_eq!(format!("{:?}", Bearer::new("tok".into())), "Bearer(..)");
    }

    #[test]
    fn expose_returns_the_value() {
        let secret = Secret::new(SecretName::new("ha_token").unwrap(), "hunter2".into());
        assert_eq!(secret.expose(), "hunter2");
    }
}
