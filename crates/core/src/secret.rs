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

/// Why a secret source could not return a secret. Each one refuses start
/// (G2). The error names a cause, never a path or a value (G9). The
/// caller logs the secret's name next to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    /// No secret of that name exists.
    #[error("the secret does not exist")]
    Missing,
    /// The secret's storage breaks a safety rule of the source, such as a
    /// file mode or an owner.
    #[error("the secret's storage is not safe: {0}")]
    Unsafe(&'static str),
    /// The secret is empty, too large or not UTF-8.
    #[error("the secret's value is not valid: {0}")]
    Invalid(&'static str),
    /// The operating system refused a read.
    #[error("the secret could not be read ({0:?})")]
    Io(std::io::ErrorKind),
}

/// The secret-source hook. It fills the secret source slot
/// (`docs/design.md` 7.2). chaperone reads each bound secret through it at
/// start.
pub trait SecretSource: Send + Sync + fmt::Debug {
    /// The secret `name`.
    ///
    /// # Errors
    ///
    /// Returns a [`SecretError`] when the secret is missing, unsafe,
    /// invalid or unreadable.
    fn read(&self, name: &SecretName) -> Result<Secret, SecretError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(Secret: fmt::Display, serde::Serialize, Clone);
    assert_not_impl_any!(Bearer: fmt::Display, serde::Serialize, Clone);

    #[test]
    fn a_secret_error_holds_no_text() {
        // Each variant holds a fixed cause or an error kind, never a value.
        let shown = format!(
            "{} {} {} {}",
            SecretError::Missing,
            SecretError::Unsafe("mode"),
            SecretError::Invalid("empty"),
            SecretError::Io(std::io::ErrorKind::PermissionDenied),
        );
        assert!(shown.contains("not safe: mode"), "{shown}");
    }

    #[test]
    fn debug_shows_the_name_and_not_the_value() {
        let secret = Secret::new(SecretName::try_new("ha_token").unwrap(), "hunter2".into());
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
        let secret = Secret::new(SecretName::try_new("ha_token").unwrap(), "hunter2".into());
        assert_eq!(secret.expose(), "hunter2");
    }
}
