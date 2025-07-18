//! Ghostwire Core - Protocol logic, handshake, multiplexed tunnels, crypto primitives
//!
//! This module contains the core protocol implementation for Ghostwire including:
//! - Protocol wire format and message framing
//! - Connection state machines
//! - Cryptographic primitives (X25519, Ed25519, ChaCha20-Poly1305)
//! - Handshake logic
//! - Stream multiplexing
//! - Connection management and keepalives

const std = @import("std");

pub const crypto = @import("crypto.zig");
pub const protocol = @import("protocol.zig");
pub const handshake = @import("handshake.zig");
pub const connection = @import("connection.zig");
pub const stream = @import("stream.zig");

/// Current protocol version
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum transmission unit for Ghostwire packets
pub const MAX_MTU: u16 = 1420;

/// Default keepalive interval in seconds
pub const DEFAULT_KEEPALIVE_INTERVAL: u32 = 25;

/// Core error types for Ghostwire protocol
pub const GhostwireError = error{
    InvalidProtocolVersion,
    InvalidHandshake,
    InvalidSignature,
    EncryptionFailure,
    DecryptionFailure,
    ConnectionClosed,
    StreamClosed,
    InvalidPacket,
    BufferTooSmall,
    OutOfMemory,
};

/// Initialize the Ghostwire core module
pub fn init() void {
    std.log.info("Ghostwire Core v{} initialized", .{PROTOCOL_VERSION});
}

test "ghostwire-core basic initialization" {
    init();
}
