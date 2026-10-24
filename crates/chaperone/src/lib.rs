//! The chaperone program. It reads the configuration, finds the plugins,
//! resolves the slots, counts calls and writes the audit. It decides
//! nothing: it calls `chaperone_core` to decide. `crates/chaperone/AGENTS.md`
//! has the rules.
//!
//! This crate holds the parts of the program that serve no connection. The
//! front door of build step 3.2 serves them over MCP.

pub mod catalog;
mod files;
pub mod gateway;
pub mod registry;
pub mod startup;

pub use files::ReadError;
