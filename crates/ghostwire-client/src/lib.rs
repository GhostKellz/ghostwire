/// GhostWire client daemon
///
/// This crate provides the client-side daemon that:
/// - Manages hybrid WireGuard and QUIC transport
/// - Communicates with coordination server
/// - Handles mesh networking and peer connections
/// - Provides authentication and tunnel management

pub mod client;
pub mod config;
pub mod transport;
pub mod tunnel;
pub mod auth;
pub mod platform;

pub use client::*;
pub use config::*;