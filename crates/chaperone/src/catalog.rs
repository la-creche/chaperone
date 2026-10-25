//! Find every plugin on disk. A plugin found here does nothing until
//! `install.toml` enables it (G10). The result is a sorted map, so the
//! directory order changes nothing.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use chaperone_core::{
    Catalog, Found, Location, Manifest, ManifestError, PLUGIN_FILE_CAP, PluginKey, PluginKind,
    PluginName,
};

use crate::files::{self, ReadError};

/// The file that describes one plugin.
pub const MANIFEST_FILE: &str = "plugin.toml";

/// Why the plugin tree is not valid. Each one refuses start (G2).
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("cannot list {}: {error}", path.display())]
    List {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error("{} is not a valid manifest: {error}", path.display())]
    Manifest { path: PathBuf, error: ManifestError },
    #[error("{} names the plugin {name}, and its directory has another name", path.display())]
    NameMismatch { path: PathBuf, name: PluginName },
    #[error("{} declares the kind {found:?}, and sits in the {expected:?} directory", path.display())]
    KindMismatch {
        path: PathBuf,
        expected: PluginKind,
        found: PluginKind,
    },
    #[error("two directories hold a {kind:?} plugin named {name}")]
    Duplicate { kind: PluginKind, name: PluginName },
}

const KIND_DIRS: [(&str, PluginKind); 3] = [
    ("adapter", PluginKind::Adapter),
    ("decision", PluginKind::Decision),
    ("effect", PluginKind::Effect),
];

const LOCATION_DIRS: [(&str, Location); 2] =
    [("included", Location::Included), ("added", Location::Added)];

/// Read every `plugin.toml` under `root`: `default/*`, then
/// `<kind>/included/*` and `<kind>/added/*`.
///
/// # Errors
///
/// Returns the first [`CatalogError`] found.
pub fn discover(root: &Path) -> Result<Catalog, CatalogError> {
    let mut catalog = Catalog::new();
    for dir in plugin_dirs(&root.join("default"))? {
        add(&mut catalog, &dir, Location::Default, None)?;
    }
    for (kind_dir, kind) in KIND_DIRS {
        for (location_dir, location) in LOCATION_DIRS {
            let parent = root.join(kind_dir).join(location_dir);
            for dir in plugin_dirs(&parent)? {
                add(&mut catalog, &dir, location, Some(kind))?;
            }
        }
    }
    Ok(catalog)
}

/// The subdirectories of `parent`, sorted. A missing `parent` has none.
fn plugin_dirs(parent: &Path) -> Result<Vec<PathBuf>, CatalogError> {
    let list = |error| CatalogError::List {
        path: parent.to_owned(),
        error,
    };
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(list(error)),
    };
    let mut dirs = Vec::new();
    for entry in entries {
        let path = entry.map_err(list)?.path();
        if path.is_dir() {
            dirs.push(path);
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// Read the manifest in `dir` and add it. `expected` is the kind of the
/// kind directory, or `None` under `default/`.
fn add(
    catalog: &mut Catalog,
    dir: &Path,
    location: Location,
    expected: Option<PluginKind>,
) -> Result<(), CatalogError> {
    let path = dir.join(MANIFEST_FILE);
    let bytes = files::read_capped(&path, PLUGIN_FILE_CAP)?;
    let manifest = Manifest::read(&bytes).map_err(|error| CatalogError::Manifest {
        path: path.clone(),
        error,
    })?;

    let dir_name = dir.file_name().and_then(|name| name.to_str());
    if dir_name != Some(manifest.name().as_str()) {
        return Err(CatalogError::NameMismatch {
            path,
            name: manifest.name().clone(),
        });
    }
    if let Some(expected) = expected
        && manifest.kind() != expected
    {
        return Err(CatalogError::KindMismatch {
            path,
            expected,
            found: manifest.kind(),
        });
    }

    let key = PluginKey::from_manifest(&manifest);
    if catalog.contains_key(&key) {
        return Err(CatalogError::Duplicate {
            kind: key.kind,
            name: key.name,
        });
    }
    catalog.insert(key, Found { location, manifest });
    Ok(())
}
