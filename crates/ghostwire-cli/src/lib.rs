/// CLI tools for GhostWire
///
/// This crate provides the unified CLI interface (gwctl) for:
/// - Server management and configuration
/// - Node registration and control
/// - User and key management
/// - Network monitoring and debugging

pub mod commands;
pub mod config;
pub mod client;

pub use commands::*;