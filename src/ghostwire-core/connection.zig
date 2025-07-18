//! Connection management for Ghostwire protocol
//!
//! Handles connection lifecycle, keepalives, and state management

const std = @import("std");
const crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");
const handshake = @import("handshake.zig");

/// Connection state
pub const ConnectionState = enum {
    disconnected,
    handshaking,
    connected,
    closing,
    closed,
};

/// Connection statistics
pub const ConnectionStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    last_activity: i64 = 0,
    rtt_ms: u32 = 0,
};

/// Ghostwire connection
pub const Connection = struct {
    state: ConnectionState = .disconnected,
    handshake_ctx: ?handshake.HandshakeContext = null,
    cipher: ?crypto.ChaCha20Poly1305 = null,
    peer_address: std.net.Address,
    stats: ConnectionStats = .{},
    last_keepalive: i64 = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, peer_address: std.net.Address) Connection {
        return Connection{
            .peer_address = peer_address,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Connection) void {
        if (self.handshake_ctx) |*ctx| {
            // Cleanup handshake context if needed
            _ = ctx;
        }
    }

    /// Start connection as client
    pub fn connect(self: *Connection) !void {
        if (self.state != .disconnected) return error.InvalidState;

        self.handshake_ctx = try handshake.HandshakeContext.init(self.allocator);
        self.state = .handshaking;
        self.stats.last_activity = std.time.timestamp();
    }

    /// Accept incoming connection as server
    pub fn accept(self: *Connection) !void {
        if (self.state != .disconnected) return error.InvalidState;

        self.handshake_ctx = try handshake.HandshakeContext.init(self.allocator);
        self.state = .handshaking;
        self.stats.last_activity = std.time.timestamp();
    }

    /// Process incoming handshake data
    pub fn processHandshake(self: *Connection, data: []const u8, response_buffer: []u8) !?[]u8 {
        if (self.state != .handshaking) return error.InvalidState;
        if (self.handshake_ctx == null) return error.NoHandshakeContext;

        const header = try protocol.ProtocolHeader.decode(data[0..8]);
        var ctx = &self.handshake_ctx.?;

        switch (header.message_type) {
            .handshake_init => {
                // Server responds to init
                const response = try ctx.respond(data, response_buffer);
                self.stats.last_activity = std.time.timestamp();
                return response;
            },
            .handshake_response => {
                // Client completes handshake
                const complete = try ctx.complete(data, response_buffer);
                self.stats.last_activity = std.time.timestamp();

                if (ctx.isComplete()) {
                    self.cipher = try ctx.getCipher();
                    self.state = .connected;
                }

                return complete;
            },
            .handshake_complete => {
                // Server finalizes handshake
                try ctx.processCompletion(data);
                self.stats.last_activity = std.time.timestamp();

                if (ctx.isComplete()) {
                    self.cipher = try ctx.getCipher();
                    self.state = .connected;
                }

                return null; // No response needed
            },
            else => return error.InvalidHandshakeMessage,
        }
    }

    /// Send encrypted data
    pub fn sendData(self: *Connection, data: []const u8, buffer: []u8) ![]u8 {
        if (self.state != .connected) return error.NotConnected;
        if (self.cipher == null) return error.NoCipher;

        // Generate nonce
        var nonce: [12]u8 = undefined;
        crypto.random.bytes(&nonce);

        // Encrypt data
        const cipher = self.cipher.?;
        var encrypted: [1024]u8 = undefined; // TODO: Dynamic sizing
        var tag: [16]u8 = undefined;

        if (data.len > encrypted.len) return error.DataTooLarge;

        try cipher.encrypt(nonce, data, "", encrypted[0..data.len], &tag);

        // Create data packet
        const packet = protocol.DataPacket{
            .nonce = nonce,
            .encrypted_payload = encrypted[0..data.len],
            .tag = tag,
        };

        // Create header
        const header = protocol.ProtocolHeader{
            .version = 1,
            .message_type = .data,
            .flags = protocol.Flags.ENCRYPTED,
            .stream_id = 0,
            .length = @intCast(12 + data.len + 16),
        };

        const total_size = 8 + 12 + data.len + 16;
        if (buffer.len < total_size) return error.BufferTooSmall;

        try header.encode(buffer[0..8]);
        try packet.encode(buffer[8..]);

        self.stats.bytes_sent += total_size;
        self.stats.packets_sent += 1;
        self.stats.last_activity = std.time.timestamp();

        return buffer[0..total_size];
    }

    /// Receive and decrypt data
    pub fn receiveData(self: *Connection, packet_data: []const u8, output_buffer: []u8) ![]u8 {
        if (self.state != .connected) return error.NotConnected;
        if (self.cipher == null) return error.NoCipher;

        const header = try protocol.ProtocolHeader.decode(packet_data[0..8]);
        if (header.message_type != .data) return error.InvalidMessageType;

        const packet = try protocol.DataPacket.decode(packet_data[8..], self.allocator);
        defer packet.deinit(self.allocator);

        const cipher = self.cipher.?;

        if (output_buffer.len < packet.encrypted_payload.len) return error.BufferTooSmall;

        try cipher.decrypt(
            packet.nonce,
            packet.encrypted_payload,
            packet.tag,
            "",
            output_buffer[0..packet.encrypted_payload.len],
        );

        self.stats.bytes_received += packet_data.len;
        self.stats.packets_received += 1;
        self.stats.last_activity = std.time.timestamp();

        return output_buffer[0..packet.encrypted_payload.len];
    }

    /// Send keepalive
    pub fn sendKeepalive(self: *Connection, buffer: []u8) ![]u8 {
        if (self.state != .connected) return error.NotConnected;

        const header = protocol.ProtocolHeader{
            .version = 1,
            .message_type = .keepalive,
            .flags = 0,
            .stream_id = 0,
            .length = 0,
        };

        if (buffer.len < 8) return error.BufferTooSmall;

        try header.encode(buffer[0..8]);

        self.last_keepalive = std.time.timestamp();
        self.stats.packets_sent += 1;

        return buffer[0..8];
    }

    /// Process keepalive
    pub fn processKeepalive(self: *Connection, data: []const u8) !void {
        const header = try protocol.ProtocolHeader.decode(data[0..8]);
        if (header.message_type != .keepalive) return error.InvalidMessageType;

        self.stats.last_activity = std.time.timestamp();
        self.stats.packets_received += 1;
    }

    /// Check if connection needs keepalive
    pub fn needsKeepalive(self: *const Connection) bool {
        const now = std.time.timestamp();
        return (now - self.last_keepalive) > 25; // 25 seconds
    }

    /// Check if connection is idle (no activity)
    pub fn isIdle(self: *const Connection) bool {
        const now = std.time.timestamp();
        return (now - self.stats.last_activity) > 60; // 60 seconds
    }

    /// Close connection
    pub fn close(self: *Connection) void {
        self.state = .closed;
    }

    /// Get connection info
    pub fn getInfo(self: *const Connection) struct {
        state: ConnectionState,
        peer: std.net.Address,
        stats: ConnectionStats,
    } {
        return .{
            .state = self.state,
            .peer = self.peer_address,
            .stats = self.stats,
        };
    }
};

test "connection lifecycle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const peer_addr = try std.net.Address.parseIp4("127.0.0.1", 8080);
    var conn = Connection.init(allocator, peer_addr);
    defer conn.deinit();

    try std.testing.expectEqual(ConnectionState.disconnected, conn.state);

    try conn.connect();
    try std.testing.expectEqual(ConnectionState.handshaking, conn.state);

    conn.close();
    try std.testing.expectEqual(ConnectionState.closed, conn.state);
}
