//! ULIDs: 26 characters of upper-case Crockford base32, from 48 bits of
//! milliseconds since the Unix epoch and 80 random bits. A later ID sorts
//! after an earlier one. [`Ulid::new`] is pure. [`Ulid::mint`] reads the
//! clock and the OS random source, so this crate is not part of
//! `crates/core` (G3).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Upper-case Crockford base32: no I, L, O or U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CHARS: usize = 26;
const TIME_BITS: u32 = 48;
const RANDOM_BITS: u32 = 80;

/// One ULID, as its 26 characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ulid(String);

/// Why no ULID was minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MintError {
    #[error("the clock of the host is before 1970")]
    Clock,
    #[error("the OS random source failed")]
    Random,
}

impl Ulid {
    /// The ID of 48 bits of milliseconds since the Unix epoch, then 80 bits
    /// of `entropy`. `now` is the time since the Unix epoch.
    #[must_use]
    pub fn new(now: Duration, entropy: [u8; 10]) -> Self {
        let millis = now.as_millis() & ((1 << TIME_BITS) - 1);
        let random = entropy
            .iter()
            .fold(0_u128, |value, byte| (value << 8) | u128::from(*byte));
        let value = (millis << RANDOM_BITS) | random;
        let text = (0..CHARS)
            .rev()
            .map(|place| char::from(ALPHABET[((value >> (place * 5)) & 0x1f) as usize]))
            .collect();
        Self(text)
    }

    /// A new ID from the OS clock and the OS random source.
    ///
    /// # Errors
    ///
    /// Returns a [`MintError`] when the clock is before 1970 or the random
    /// source fails.
    pub fn mint() -> Result<Self, MintError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MintError::Clock)?;
        let mut entropy = [0_u8; 10];
        getrandom::fill(&mut entropy).map_err(|_| MintError::Random)?;
        Ok(Self::new(now, entropy))
    }

    /// `text` as an ID, or nothing when it is not 26 characters of the
    /// alphabet.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let valid = text.len() == CHARS && text.bytes().all(|byte| ALPHABET.contains(&byte));
        valid.then(|| Self(text.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
