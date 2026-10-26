//! The env file of `chaperone verify --env-file` (`docs/design.md` 10).
//! It gives the front door address, as the service unit reads it. The
//! reader is strict, so its result is never a guess. No value of the file
//! appears in an error, because the file can hold secrets (G9).

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

use chaperone_core::strict::ByteCap;

use crate::files::{self, ReadError};

/// The largest env file `chaperone verify` reads.
pub const ENV_FILE_CAP: ByteCap = ByteCap::new(64 * 1024);

/// The key of the front door address when `--listen-key` is not given.
pub const DEFAULT_LISTEN_KEY: &str = "CHAPERONE_LISTEN";

/// A key of an env file: `A-Z`, then any of `A-Z`, `0-9` and `_`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EnvKey(String);

/// Why a text is not an env file key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a key is A-Z, then any of A-Z, 0-9 and _")]
pub struct KeyError;

impl FromStr for EnvKey {
    type Err = KeyError;

    fn from_str(text: &str) -> Result<Self, KeyError> {
        let Some((first, rest)) = text.as_bytes().split_first() else {
            return Err(KeyError);
        };
        let valid = first.is_ascii_uppercase()
            && rest
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_');
        if !valid {
            return Err(KeyError);
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for EnvKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why the env file gives no front door address. Each one fails the
/// check. A line is named by its number only.
#[derive(Debug, thiserror::Error)]
pub enum EnvFileError {
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error("the env file is not UTF-8")]
    NotUtf8,
    #[error("line {line} of the env file is not KEY=VALUE, a # comment or empty")]
    BadLine { line: usize },
    #[error("line {line} of the env file repeats the key of line {first}")]
    DuplicateKey { line: usize, first: usize },
    #[error("the env file has no key {0}")]
    MissingKey(EnvKey),
    #[error("the value of {0} in the env file is not a host:port socket address")]
    NotAddress(EnvKey),
}

/// The front door address that `key` holds in the env file at `path`.
///
/// # Errors
///
/// Returns an [`EnvFileError`] when the file does not read, breaks a rule
/// of [`listen_address`], or is over [`ENV_FILE_CAP`].
pub fn read_listen(path: &Path, key: &EnvKey) -> Result<SocketAddr, EnvFileError> {
    let bytes = files::read_capped(path, ENV_FILE_CAP)?;
    listen_address(&bytes, key)
}

/// The front door address that `key` holds in `bytes`. Each line is
/// `KEY=VALUE`, a comment that starts with `#`, or empty. The value is the
/// text after the first `=`, as it is. A key appears once.
///
/// # Errors
///
/// Returns an [`EnvFileError`] for the first line that breaks a rule, a
/// missing key, or a value that is not a socket address.
pub fn listen_address(bytes: &[u8], key: &EnvKey) -> Result<SocketAddr, EnvFileError> {
    let text = std::str::from_utf8(bytes).map_err(|_| EnvFileError::NotUtf8)?;
    // The line of each key seen. Only the value of `key` is kept.
    let mut seen: BTreeMap<EnvKey, usize> = BTreeMap::new();
    let mut value = None;
    for (index, line) in text.split('\n').enumerate() {
        let number = index.saturating_add(1);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = || EnvFileError::BadLine { line: number };
        let (name, text) = line.split_once('=').ok_or_else(bad)?;
        let name: EnvKey = name.parse().map_err(|_| bad())?;
        if let Some(first) = seen.get(&name) {
            return Err(EnvFileError::DuplicateKey {
                line: number,
                first: *first,
            });
        }
        if name == *key {
            value = Some(text);
        }
        seen.insert(name, number);
    }
    let value = value.ok_or_else(|| EnvFileError::MissingKey(key.clone()))?;
    value
        .parse()
        .map_err(|_| EnvFileError::NotAddress(key.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(text: &str) -> EnvKey {
        text.parse().unwrap()
    }

    fn listen(text: &str) -> Result<SocketAddr, EnvFileError> {
        listen_address(text.as_bytes(), &key(DEFAULT_LISTEN_KEY))
    }

    #[test]
    fn reads_the_address_among_comments_empty_lines_and_other_keys() {
        let text = "# The site file.\n\nOTHER_TOKEN=a=b c\nCHAPERONE_LISTEN=192.0.2.10:8300\n";
        assert_eq!(listen(text).unwrap(), "192.0.2.10:8300".parse().unwrap());
        let text = "CHAPERONE_LISTEN=[::1]:8300";
        assert_eq!(listen(text).unwrap(), "[::1]:8300".parse().unwrap());
    }

    #[test]
    fn reads_another_key_when_asked() {
        let text = "PEP_BIND=127.0.0.1:9000\n";
        let address = listen_address(text.as_bytes(), &key("PEP_BIND")).unwrap();
        assert_eq!(address, "127.0.0.1:9000".parse().unwrap());
    }

    #[test]
    fn refuses_a_line_that_is_no_assignment_no_comment_and_not_empty() {
        for (text, line) in [
            ("export CHAPERONE_LISTEN=127.0.0.1:8300\n", 1),
            ("A=1\n \nCHAPERONE_LISTEN=127.0.0.1:8300\n", 2),
            ("A=1\n  # an indented comment\n", 2),
            ("lower=1\n", 1),
            ("1A=1\n", 1),
            ("A-B=1\n", 1),
            ("A =1\n", 1),
            ("=1\n", 1),
            ("JUST_A_KEY\n", 1),
        ] {
            let error = listen(text).unwrap_err();
            assert!(
                matches!(error, EnvFileError::BadLine { line: found } if found == line),
                "{text:?}: {error}"
            );
        }
    }

    #[test]
    fn refuses_a_duplicate_key() {
        let error = listen("A=1\nB=2\nA=3\n").unwrap_err();
        assert!(
            matches!(error, EnvFileError::DuplicateKey { line: 3, first: 1 }),
            "{error}"
        );
    }

    #[test]
    fn refuses_a_missing_key() {
        let error = listen("PEP_BIND=127.0.0.1:8300\n").unwrap_err();
        assert!(matches!(error, EnvFileError::MissingKey(_)), "{error}");
        assert_eq!(
            error.to_string(),
            "the env file has no key CHAPERONE_LISTEN"
        );
    }

    #[test]
    fn refuses_a_value_that_is_no_socket_address_and_never_shows_it() {
        for value in [
            "localhost:8300",
            "127.0.0.1",
            "",
            " 127.0.0.1:8300",
            "127.0.0.1:8300\r",
        ] {
            let text = format!("CHAPERONE_LISTEN={value}\n");
            let error = listen(&text).unwrap_err();
            assert!(
                matches!(error, EnvFileError::NotAddress(_)),
                "{value:?}: {error}"
            );
            if !value.trim().is_empty() {
                assert!(!error.to_string().contains(value.trim()), "{error}");
            }
        }
    }

    #[test]
    fn an_error_never_shows_a_value_of_the_file() {
        for text in [
            "SECRET=hunter2-value\nSECRET=hunter2-value\n",
            "SECRET=hunter2-value\nnot a line\n",
            "SECRET=hunter2-value\n",
        ] {
            let error = listen(text).unwrap_err().to_string();
            assert!(!error.contains("hunter2"), "{error}");
        }
    }

    #[test]
    fn refuses_text_that_is_not_utf8() {
        let error = listen_address(b"A=\xff\n", &key("A")).unwrap_err();
        assert!(matches!(error, EnvFileError::NotUtf8), "{error}");
    }

    #[test]
    fn refuses_a_file_over_64_kib() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.env");
        let line = "CHAPERONE_LISTEN=127.0.0.1:8300\n";
        let filler = "#".repeat(ENV_FILE_CAP.bytes() - line.len());
        std::fs::write(&path, format!("{line}{filler}")).unwrap();
        let read = read_listen(&path, &key(DEFAULT_LISTEN_KEY)).unwrap();
        assert_eq!(read, "127.0.0.1:8300".parse().unwrap());

        std::fs::write(&path, format!("{line}{filler}#")).unwrap();
        let error = read_listen(&path, &key(DEFAULT_LISTEN_KEY)).unwrap_err();
        assert!(
            matches!(error, EnvFileError::Read(ReadError::TooLarge { .. })),
            "{error}"
        );
    }

    #[test]
    fn a_key_is_upper_case_then_digits_and_underscores() {
        for text in ["A", "CHAPERONE_LISTEN", "A1_B2"] {
            assert!(text.parse::<EnvKey>().is_ok(), "{text}");
        }
        for text in ["", "a", "_A", "1A", "A-B", "A B", "Ä"] {
            assert_eq!(text.parse::<EnvKey>(), Err(KeyError), "{text}");
        }
    }
}
