//! The default clock plugin. It reads the OS clock and nothing else. Core
//! takes the time as an argument (G3), so the program reads it here and
//! passes it on.

use std::time::{SystemTime, UNIX_EPOCH};

use chaperone_core::{Clock, Timestamp};

/// The OS clock. A time before the Unix epoch reads as the epoch, and a
/// time past the range of a [`Timestamp`] reads as its maximum.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
            });
        Timestamp::from_unix_millis(millis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_reads_a_time_after_2025() {
        const START_OF_2025: i64 = 1_735_689_600_000;
        assert!(SystemClock.now().unix_millis() > START_OF_2025);
    }
}
