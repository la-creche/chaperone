//! The clock hook. It fills the clock slot. The program reads the time
//! through it and passes the time to the decision as an argument (G3).
//! Core only states the contract.

use std::fmt;

use crate::time::Timestamp;

/// A source of the current time.
pub trait Clock: Send + Sync + fmt::Debug {
    fn now(&self) -> Timestamp;
}
