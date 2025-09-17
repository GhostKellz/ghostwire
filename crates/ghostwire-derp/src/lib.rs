/// DERP relay implementation for GhostWire
///
/// This crate provides QUIC-based DERP (Designated Encrypted Relay for Packets) server:
/// - High-performance QUIC relay with mesh capabilities
/// - Connection multiplexing and stream management
/// - Congestion control and flow control
/// - Geographic relay selection

pub mod relay;
pub mod mesh;
pub mod client;

pub use relay::*;