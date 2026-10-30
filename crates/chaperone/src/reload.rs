//! The policy the call path decides with. chaperone reloads the policy file
//! when the file changes (`docs/design.md` 6). Before each call it compares
//! the file's device, inode, size and modification time with the loaded
//! file. A change re-reads the file through the strict reader. While no
//! valid policy is loaded, each call re-reads the file.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chaperone_core::{POLICY_FILE_CAP, Policy, Setup};

use crate::files::{self, ReadError};
use crate::startup::{self, POLICY_FILE, StartError};

/// The facts of a file that change when the file is written or replaced.
/// A read of the file's metadata, not a clock read (G3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    modified_secs: i64,
    modified_nanos: i64,
}

impl Stamp {
    /// The stamp of the file at `path` now.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError::Io`] when the metadata cannot be read.
    pub fn of(path: &Path) -> Result<Self, ReadError> {
        let metadata = std::fs::metadata(path).map_err(|error| ReadError::Io {
            path: path.to_owned(),
            error,
        })?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_secs: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
        })
    }
}

/// The policy file and the policy last read from it.
#[derive(Debug)]
pub struct PolicyFile {
    path: PathBuf,
    setup: Setup,
    state: Mutex<Watched>,
}

/// The stamp of the last read, or `None` when the metadata could not be
/// read. The policy of that read, or `None` when the read was refused.
#[derive(Debug)]
struct Watched {
    stamp: Option<Stamp>,
    policy: Option<Arc<Policy>>,
}

impl PolicyFile {
    /// Watch `policy.toml` in `config_dir`. `policy` was read from the file
    /// when it had `stamp`.
    #[must_use]
    pub fn new(config_dir: &Path, setup: Setup, policy: Policy, stamp: Stamp) -> Self {
        Self {
            path: config_dir.join(POLICY_FILE),
            setup,
            state: Mutex::new(Watched {
                stamp: Some(stamp),
                policy: Some(Arc::new(policy)),
            }),
        }
    }

    /// The policy to decide one call with, reloaded first when the file
    /// changed or when no valid policy is loaded. `None` means no valid
    /// policy is loaded, and the call is denied (G2).
    pub fn current(&self) -> Option<Arc<Policy>> {
        let mut state = self.state.lock().ok()?;
        let stamp = Stamp::of(&self.path).ok();
        // A mode change keeps the stamp, so a refused read is tried again.
        if stamp == state.stamp && state.policy.is_some() {
            return state.policy.clone();
        }
        state.stamp = stamp;
        state.policy = match self.read() {
            Ok(policy) => {
                tracing::info!(file = %self.path.display(), "reloaded the policy file");
                for (app, error) in policy.refused() {
                    tracing::warn!(
                        %app,
                        %error,
                        "the app is refused, and each of its calls is denied"
                    );
                }
                Some(Arc::new(policy))
            }
            // A refused file denies every call until a valid file lands
            // (section 6 of `docs/design.md`).
            Err(error) => {
                tracing::error!(
                    file = %self.path.display(),
                    %error,
                    "the policy file is refused, so every call is denied"
                );
                None
            }
        };
        state.policy.clone()
    }

    fn read(&self) -> Result<Policy, StartError> {
        let bytes = files::read_capped(&self.path, POLICY_FILE_CAP)?;
        startup::policy_from(&bytes, &self.setup)
    }
}

/// Where the call path takes its policy from.
#[derive(Debug)]
pub enum PolicySource {
    /// A policy that does not change while chaperone runs.
    Fixed(Arc<Policy>),
    /// The policy file, reloaded when it changes.
    File(Box<PolicyFile>),
}

impl PolicySource {
    /// The policy for one call, or `None` when no valid policy is loaded.
    pub fn current(&self) -> Option<Arc<Policy>> {
        match self {
            Self::Fixed(policy) => Some(Arc::clone(policy)),
            Self::File(file) => file.current(),
        }
    }
}

impl From<Policy> for PolicySource {
    fn from(policy: Policy) -> Self {
        Self::Fixed(Arc::new(policy))
    }
}

impl From<PolicyFile> for PolicySource {
    fn from(file: PolicyFile) -> Self {
        Self::File(Box::new(file))
    }
}
