//! The `release` upstream (`docs/design.md` section 12). Each call of its
//! one tool, `request`, writes one request file into the `requests/`
//! directory of the release spool. The file has the shape that the release
//! executor reads. The executor resolves the components and asks the
//! operator. This plugin approves nothing and starts nothing.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The most components that one request names.
pub const MAX_COMPONENTS: usize = 8;

/// The most request files that can wait in the directory. The executor
/// keeps its own cap. This one refuses a call before the write.
pub const MAX_PENDING: usize = 8;

/// The largest request file, in bytes.
pub const MAX_REQUEST_BYTES: usize = 4096;

const REQUEST_SUFFIX: &str = ".json";
const REQUEST_FILE_MODE: u32 = 0o600;
const LATEST: &str = "latest";

/// Upper-case Crockford base32: no I, L, O or U.
const ULID_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ULID_CHARS: usize = 26;
const TIME_BITS: u32 = 48;
const RANDOM_BITS: u32 = 80;

/// Whether `text` is `a-z`, then 1 to 30 of `a-z`, `0-9` and `-`.
fn is_name(text: &str) -> bool {
    let Some((first, rest)) = text.as_bytes().split_first() else {
        return false;
    };
    (1..=30).contains(&rest.len())
        && first.is_ascii_lowercase()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Whether `text` is three runs of digits joined by dots.
fn is_version(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_ulid(text: &str) -> bool {
    text.len() == ULID_CHARS && text.bytes().all(|byte| ULID_ALPHABET.contains(&byte))
}

/// A request ID: 26 characters of upper-case Crockford base32.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
    /// The ID of 48 bits of milliseconds since the Unix epoch, then 80 bits
    /// of `entropy`. A later request sorts after an earlier one.
    #[must_use]
    pub fn new(now: Duration, entropy: [u8; 10]) -> Self {
        let millis = now.as_millis() & ((1 << TIME_BITS) - 1);
        let random = entropy
            .iter()
            .fold(0_u128, |value, byte| (value << 8) | u128::from(*byte));
        let value = (millis << RANDOM_BITS) | random;
        let text = (0..ULID_CHARS)
            .rev()
            .map(|place| char::from(ULID_ALPHABET[((value >> (place * 5)) & 0x1f) as usize]))
            .collect();
        Self(text)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name that a request states as its requester. The executor treats it
/// as a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requester(String);

impl Requester {
    /// The requester `text`, or nothing when it is not a name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        is_name(text).then(|| Self(text.to_owned()))
    }
}

/// A component name: `a-z`, then 1 to 30 of `a-z`, `0-9` and `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Component(String);

/// The version a request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    Latest,
    /// `x.y.z`, digits only.
    Exact(String),
}

impl Version {
    fn as_str(&self) -> &str {
        match self {
            Self::Latest => LATEST,
            Self::Exact(text) => text,
        }
    }
}

/// What the executor does with the components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Release,
    /// Reverse the release of this earlier request.
    Rollback(RequestId),
}

/// The checked arguments of one `request` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    components: BTreeMap<Component, Version>,
    action: Action,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArguments {
    components: BTreeMap<String, String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    rollback_of: Option<String>,
}

/// Why the arguments are not a request. Each text is fixed, so it never
/// shows an argument value (G9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ArgumentError {
    #[error(
        "the arguments take components, and optional kind and rollback_of, each with string values"
    )]
    Shape,
    #[error("components names no component")]
    NoComponent,
    #[error("components names more than {MAX_COMPONENTS} components")]
    TooMany,
    #[error("a component name is not a-z, then 1 to 30 of a-z, 0-9 and -")]
    ComponentName,
    #[error("a version in components is not latest or x.y.z")]
    Version,
    #[error("kind is not release or rollback")]
    Kind,
    #[error("rollback_of is not a request ID of 26 base32 characters")]
    RollbackOf,
    #[error("kind release takes no rollback_of")]
    ReleaseWithTarget,
    #[error("kind rollback needs a rollback_of")]
    RollbackWithoutTarget,
}

impl Arguments {
    /// Check the arguments of a call.
    ///
    /// # Errors
    ///
    /// Returns the first [`ArgumentError`] found.
    pub fn parse(
        arguments: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, ArgumentError> {
        let raw: RawArguments = serde_json::from_value(serde_json::Value::Object(arguments))
            .map_err(|_| ArgumentError::Shape)?;
        if raw.components.is_empty() {
            return Err(ArgumentError::NoComponent);
        }
        if raw.components.len() > MAX_COMPONENTS {
            return Err(ArgumentError::TooMany);
        }
        let mut components = BTreeMap::new();
        for (name, version) in raw.components {
            if !is_name(&name) {
                return Err(ArgumentError::ComponentName);
            }
            let version = if version == LATEST {
                Version::Latest
            } else if is_version(&version) {
                Version::Exact(version)
            } else {
                return Err(ArgumentError::Version);
            };
            components.insert(Component(name), version);
        }
        let target = match raw.rollback_of {
            None => None,
            Some(text) if is_ulid(&text) => Some(RequestId(text)),
            Some(_) => return Err(ArgumentError::RollbackOf),
        };
        let action = match (raw.kind.as_deref().unwrap_or("release"), target) {
            ("release", None) => Action::Release,
            ("release", Some(_)) => return Err(ArgumentError::ReleaseWithTarget),
            ("rollback", Some(target)) => Action::Rollback(target),
            ("rollback", None) => return Err(ArgumentError::RollbackWithoutTarget),
            (_, _) => return Err(ArgumentError::Kind),
        };
        Ok(Self { components, action })
    }
}

/// One request, ready to write.
#[derive(Debug, Clone)]
pub struct Request {
    id: RequestId,
    arguments: Arguments,
    requester: Requester,
    now: Duration,
}

/// The request file, field by field, in the order the executor writes it.
#[derive(Serialize)]
struct Body<'a> {
    id: &'a str,
    kind: &'a str,
    components: BTreeMap<&'a str, &'a str>,
    rollback_of: Option<&'a str>,
    requested_by: &'a str,
    requester_session: Option<&'a str>,
    ts: f64,
}

/// Why no request file was written.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("the requests directory is missing or is not a directory")]
    NoDirectory,
    #[error("the requests directory already holds {MAX_PENDING} requests")]
    Full,
    #[error("a request with this ID already exists")]
    Exists,
    #[error("the request is larger than {MAX_REQUEST_BYTES} bytes")]
    TooLarge,
    #[error("the request file cannot be written: {0}")]
    Io(#[from] io::Error),
}

impl Request {
    /// A request at `now`, the time since the Unix epoch, with an ID from
    /// `now` and `entropy`.
    #[must_use]
    pub fn new(
        arguments: Arguments,
        requester: Requester,
        now: Duration,
        entropy: [u8; 10],
    ) -> Self {
        Self {
            id: RequestId::new(now, entropy),
            arguments,
            requester,
            now,
        }
    }

    #[must_use]
    pub fn id(&self) -> &RequestId {
        &self.id
    }

    fn body(&self) -> Result<Vec<u8>, FileError> {
        let (kind, rollback_of) = match &self.arguments.action {
            Action::Release => ("release", None),
            Action::Rollback(target) => ("rollback", Some(target.as_str())),
        };
        // DESIGN-QUESTION: docs/design.md 7.7 sends an upstream no app ID and
        // no session. The reading: requested_by is the install argument and
        // requester_session is null. A change passes the app ID in each call.
        // DESIGN-QUESTION: AGENTS.md "Time" wants RFC 3339. The executor
        // reads ts as seconds since the Unix epoch, so ts is a number. A
        // change needs the executor to read RFC 3339.
        let body = Body {
            id: self.id.as_str(),
            kind,
            components: self
                .arguments
                .components
                .iter()
                .map(|(name, version)| (name.0.as_str(), version.as_str()))
                .collect(),
            rollback_of,
            requested_by: &self.requester.0,
            requester_session: None,
            ts: self.now.as_secs_f64(),
        };
        let bytes = serde_json::to_vec(&body).map_err(io::Error::from)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(FileError::TooLarge);
        }
        Ok(bytes)
    }
}

/// Write `request` into `dir` as `<ID>.json` with mode 0600, and return its
/// path. The body goes to `.<ID>.json.tmp` first, then a hard link gives it
/// its name. A reader sees a whole file or none. A link never replaces a
/// file that exists, where a rename would.
///
/// # Errors
///
/// Returns a [`FileError`]. No request file exists after an error.
pub fn file(dir: &Path, request: &Request) -> Result<PathBuf, FileError> {
    let body = request.body()?;
    let is_dir = fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir());
    if !is_dir {
        return Err(FileError::NoDirectory);
    }
    let mut pending = 0;
    for entry in fs::read_dir(dir)? {
        if entry?
            .file_name()
            .to_string_lossy()
            .ends_with(REQUEST_SUFFIX)
        {
            pending += 1;
        }
    }
    if pending >= MAX_PENDING {
        return Err(FileError::Full);
    }

    let name = format!("{}{REQUEST_SUFFIX}", request.id.as_str());
    let target = dir.join(&name);
    let temporary = dir.join(format!(".{name}.tmp"));
    remove_if_present(&temporary)?;
    let linked = write_new(&temporary, &body).and_then(|()| {
        fs::hard_link(&temporary, &target).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                FileError::Exists
            } else {
                FileError::Io(error)
            }
        })
    });
    let removed = remove_if_present(&temporary);
    linked?;
    removed?;
    Ok(target)
}

fn write_new(path: &Path, body: &[u8]) -> Result<(), FileError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(REQUEST_FILE_MODE)
        .open(path)?;
    // The umask of the process must not change the mode.
    file.set_permissions(Permissions::from_mode(REQUEST_FILE_MODE))?;
    file.write_all(body)?;
    file.sync_all()?;
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<(), FileError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(FileError::Io(error)),
    }
}
