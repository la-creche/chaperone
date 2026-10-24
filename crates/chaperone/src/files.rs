//! Read a configuration file with a size cap, so a large file never fills
//! memory. The strict reader checks the cap again on the bytes.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chaperone_core::strict::ByteCap;

/// Why a configuration file could not be read. Each one refuses start (G2).
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("cannot read {}: {error}", path.display())]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("{} is larger than {cap} bytes", path.display())]
    TooLarge { path: PathBuf, cap: usize },
}

/// Read `path` into memory, up to `cap` bytes. One byte more refuses the
/// file.
pub(crate) fn read_capped(path: &Path, cap: ByteCap) -> Result<Vec<u8>, ReadError> {
    let io = |error| ReadError::Io {
        path: path.to_owned(),
        error,
    };
    let limit = u64::try_from(cap.bytes())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(io)?
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() > cap.bytes() {
        return Err(ReadError::TooLarge {
            path: path.to_owned(),
            cap: cap.bytes(),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_up_to_the_cap_and_refuses_one_byte_more() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.json");
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(read_capped(&path, ByteCap::new(4)).unwrap(), b"1234");
        assert!(matches!(
            read_capped(&path, ByteCap::new(3)),
            Err(ReadError::TooLarge { cap: 3, .. })
        ));
    }

    #[test]
    fn a_missing_file_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = read_capped(&dir.path().join("none.json"), ByteCap::new(4)).unwrap_err();
        assert!(matches!(error, ReadError::Io { .. }), "{error}");
    }
}
