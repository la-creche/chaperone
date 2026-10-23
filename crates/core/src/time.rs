//! A point in time, as the caller passes it to the decision (G3). Core never
//! reads a clock.

use std::time::Duration;

/// Milliseconds since the Unix epoch, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The time `millis` milliseconds after the Unix epoch.
    #[must_use]
    pub const fn from_unix_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn unix_millis(self) -> i64 {
        self.0
    }

    /// The time `duration` later, or `None` on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let millis = i64::try_from(duration.as_millis()).ok()?;
        self.0.checked_add(millis).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_add_adds_and_refuses_overflow() {
        let start = Timestamp::from_unix_millis(1_000);
        assert_eq!(
            start.checked_add(Duration::from_secs(60)),
            Some(Timestamp::from_unix_millis(61_000))
        );
        assert_eq!(
            Timestamp::from_unix_millis(i64::MAX).checked_add(Duration::from_millis(1)),
            None
        );
    }
}
