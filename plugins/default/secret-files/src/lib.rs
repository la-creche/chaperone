//! The default secret source. One secret is one file in the secrets
//! directory, named after the secret (`docs/design.md` section 8).
//!
//! The source opens the file without following a final symbolic link. It
//! then checks the opened file: a regular file, mode 0600, owned by the
//! user that runs chaperone. It reads at most [`VALUE_CAP`] bytes. The
//! value must be one line of UTF-8 with no control character and no white
//! space at either end. A file written with a trailing newline thus
//! refuses loudly instead of failing an upstream login quietly.
//!
//! Every error is a [`SecretError`]: a fixed cause, never a path or a value
//! (G9).

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use chaperone_core::{Secret, SecretError, SecretName, SecretSource};

/// The longest secret value, in bytes.
// DESIGN-QUESTION: docs/design.md 8 names no size and no shape for a
// secret value. One line of at most 4096 bytes holds every token of
// version 1. A multi-line value, such as a PEM key, needs a design change.
pub const VALUE_CAP: usize = 4096;

const FILE_MODE: u32 = 0o600;
const MODE_BITS: u32 = 0o777;

/// The secret source over one directory.
#[derive(Debug)]
pub struct FileSecrets {
    dir: PathBuf,
}

impl FileSecrets {
    /// A source over `dir`. The directory is checked on each read, so a
    /// setup with no bound secret never touches it.
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl SecretSource for FileSecrets {
    fn read(&self, name: &SecretName) -> Result<Secret, SecretError> {
        let file = open_no_follow(&self.dir.join(name.as_str()))?;
        check_file(&file)?;
        let value = read_value(file)?;
        Ok(Secret::new(name.clone(), value))
    }
}

/// Open the file for reading without following a final symbolic link.
fn open_no_follow(path: &std::path::Path) -> Result<File, SecretError> {
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path);
    match opened {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(SecretError::Missing),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            Err(SecretError::Unsafe("a symbolic link"))
        }
        Err(error) => Err(SecretError::Io(error.kind())),
    }
}

/// Check the opened file, not the path. A file swapped in after the open
/// is checked too.
fn check_file(file: &File) -> Result<(), SecretError> {
    let metadata = file
        .metadata()
        .map_err(|error| SecretError::Io(error.kind()))?;
    if !metadata.file_type().is_file() {
        return Err(SecretError::Unsafe("not a regular file"));
    }
    if metadata.permissions().mode() & MODE_BITS != FILE_MODE {
        return Err(SecretError::Unsafe("mode is not 0600"));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(SecretError::Unsafe("owner is not the chaperone user"));
    }
    Ok(())
}

/// Read at most [`VALUE_CAP`] bytes and check the shape of the value.
fn read_value(file: File) -> Result<String, SecretError> {
    let limit = u64::try_from(VALUE_CAP)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| SecretError::Io(error.kind()))?;
    if bytes.is_empty() {
        return Err(SecretError::Invalid("empty"));
    }
    if bytes.len() > VALUE_CAP {
        return Err(SecretError::Invalid("over 4096 bytes"));
    }
    let value = String::from_utf8(bytes).map_err(|_| SecretError::Invalid("not UTF-8"))?;
    if value.chars().any(char::is_control) {
        return Err(SecretError::Invalid("holds a control character"));
    }
    if value.trim() != value {
        return Err(SecretError::Invalid("starts or ends with white space"));
    }
    Ok(value)
}
