//! Ghostwire Transport - QUIC, UDP/TCP, relay fallback, congestion control
//!
//! This module handles the transport layer for Ghostwire including:
//! - QUIC transport implementation
//! - UDP/TCP fallback
//! - Connection management
//! - Congestion control
//! - Packet handling

const std = @import("std");

pub const udp = @import("udp.zig");
pub const quic = @import("quic.zig");
pub const congestion = @import("congestion.zig");
pub const packet = @import("packet.zig");

/// Transport types supported by Ghostwire
pub const TransportType = enum {
    udp,
    quic,
    tcp,
    websocket,
};

/// Transport configuration
pub const TransportConfig = struct {
    transport_type: TransportType = .quic,
    bind_address: std.net.Address,
    max_packet_size: u16 = 1420,
    keepalive_interval: u32 = 25,
    timeout: u32 = 60,
    enable_congestion_control: bool = true,
};

/// Transport statistics
pub const TransportStats = struct {
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packet_loss: f32 = 0.0,
    rtt_ms: u32 = 0,
    bandwidth_bps: u64 = 0,
};

/// Generic transport interface
pub const Transport = struct {
    config: TransportConfig,
    stats: TransportStats = .{},
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: TransportConfig) Transport {
        return Transport{
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Transport) void {
        _ = self;
        // Cleanup implementation-specific resources
    }

    /// Send packet to destination
    pub fn sendPacket(self: *Transport, dest: std.net.Address, data: []const u8) !void {
        switch (self.config.transport_type) {
            .udp => try udp.sendPacket(dest, data),
            .quic => try quic.sendPacket(dest, data),
            .tcp => return error.NotImplemented,
            .websocket => return error.NotImplemented,
        }

        self.stats.packets_sent += 1;
        self.stats.bytes_sent += data.len;
    }

    /// Receive packet from any source
    pub fn receivePacket(self: *Transport, buffer: []u8) !struct {
        source: std.net.Address,
        data: []u8,
    } {
        const result = switch (self.config.transport_type) {
            .udp => try udp.receivePacket(buffer),
            .quic => try quic.receivePacket(buffer),
            .tcp => return error.NotImplemented,
            .websocket => return error.NotImplemented,
        };

        self.stats.packets_received += 1;
        self.stats.bytes_received += result.data.len;

        return result;
    }

    /// Bind to configured address
    pub fn bind(self: *Transport) !void {
        switch (self.config.transport_type) {
            .udp => try udp.bind(self.config.bind_address),
            .quic => try quic.bind(self.config.bind_address),
            .tcp => return error.NotImplemented,
            .websocket => return error.NotImplemented,
        }
    }

    /// Close transport
    pub fn close(self: *Transport) void {
        switch (self.config.transport_type) {
            .udp => udp.close(),
            .quic => quic.close(),
            .tcp => {},
            .websocket => {},
        }
    }

    /// Get current statistics
    pub fn getStats(self: *const Transport) TransportStats {
        return self.stats;
    }

    /// Update RTT measurement
    pub fn updateRTT(self: *Transport, rtt_ms: u32) void {
        self.stats.rtt_ms = rtt_ms;
    }

    /// Calculate packet loss
    pub fn updatePacketLoss(self: *Transport, lost: u64, total: u64) void {
        if (total > 0) {
            self.stats.packet_loss = @as(f32, @floatFromInt(lost)) / @as(f32, @floatFromInt(total));
        }
    }
};

/// Transport error types
pub const TransportError = error{
    BindFailed,
    SendFailed,
    ReceiveFailed,
    InvalidAddress,
    BufferTooSmall,
    NotConnected,
    TimedOut,
    NotImplemented,
};

test "transport initialization" {
    const allocator = std.testing.allocator;
    const bind_addr = try std.net.Address.parseIp4("127.0.0.1", 0);

    const config = TransportConfig{
        .transport_type = .udp,
        .bind_address = bind_addr,
    };

    var transport = Transport.init(allocator, config);
    defer transport.deinit();

    try std.testing.expectEqual(TransportType.udp, transport.config.transport_type);
}
