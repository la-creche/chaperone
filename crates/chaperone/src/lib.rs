//! The chaperone program. It reads the configuration, finds the plugins,
//! resolves the slots, counts calls and writes the audit. It decides
//! nothing: it calls `chaperone_core` to decide. `crates/chaperone/AGENTS.md`
//! has the rules.
//!
//! This crate holds the parts of the program that serve no connection. The
//! `mcp-http` front door plugin serves them over MCP.

pub mod catalog;
pub mod clock;
mod files;
pub mod gateway;
pub mod registry;
pub mod startup;

pub use files::ReadError;
