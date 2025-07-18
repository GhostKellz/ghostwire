//! Protocol definitions and message framing for Ghostwire
//!
//! Defines the wire format, message types, and protocol state machines

const std = @import("std");

/// Protocol message types
pub const MessageType = enum(u8) {
    handshake_init = 0x01,
    handshake_response = 0x02,
    handshake_complete = 0x03,
    data = 0x10,
    keepalive = 0x20,
    close = 0x30,
    stream_open = 0x40,
    stream_data = 0x41,
    stream_close = 0x42,
    _,
};

/// Protocol header structure (8 bytes)
pub const ProtocolHeader = packed struct {
    version: u16,
    message_type: MessageType,
    flags: u8,
    stream_id: u16,
    length: u16,

    pub fn encode(self: *const ProtocolHeader, buffer: []u8) !void {
        if (buffer.len < 8) return error.BufferTooSmall;
        std.mem.writeInt(u16, buffer[0..2], self.version, .big);
        buffer[2] = @intFromEnum(self.message_type);
        buffer[3] = self.flags;
        std.mem.writeInt(u16, buffer[4..6], self.stream_id, .big);
        std.mem.writeInt(u16, buffer[6..8], self.length, .big);
    }

    pub fn decode(buffer: []const u8) !ProtocolHeader {
        if (buffer.len < 8) return error.BufferTooSmall;
        return ProtocolHeader{
            .version = std.mem.readInt(u16, buffer[0..2], .big),
            .message_type = @enumFromInt(buffer[2]),
            .flags = buffer[3],
            .stream_id = std.mem.readInt(u16, buffer[4..6], .big),
            .length = std.mem.readInt(u16, buffer[6..8], .big),
        };
    }
};

/// Protocol flags
pub const Flags = struct {
    pub const ENCRYPTED: u8 = 0x01;
    pub const COMPRESSED: u8 = 0x02;
    pub const URGENT: u8 = 0x04;
    pub const FINAL: u8 = 0x08;
};

/// Handshake initiation message
pub const HandshakeInit = struct {
    sender_public_key: [32]u8,
    timestamp: u64,

    pub fn encode(self: *const HandshakeInit, buffer: []u8) !void {
        if (buffer.len < 40) return error.BufferTooSmall;
        @memcpy(buffer[0..32], &self.sender_public_key);
        std.mem.writeInt(u64, buffer[32..40], self.timestamp, .big);
    }

    pub fn decode(buffer: []const u8) !HandshakeInit {
        if (buffer.len < 40) return error.BufferTooSmall;
        var init: HandshakeInit = undefined;
        @memcpy(&init.sender_public_key, buffer[0..32]);
        init.timestamp = std.mem.readInt(u64, buffer[32..40], .big);
        return init;
    }
};

/// Handshake response message
pub const HandshakeResponse = struct {
    responder_public_key: [32]u8,
    timestamp: u64,
    signature: [64]u8,

    pub fn encode(self: *const HandshakeResponse, buffer: []u8) !void {
        if (buffer.len < 104) return error.BufferTooSmall;
        @memcpy(buffer[0..32], &self.responder_public_key);
        std.mem.writeInt(u64, buffer[32..40], self.timestamp, .big);
        @memcpy(buffer[40..104], &self.signature);
    }

    pub fn decode(buffer: []const u8) !HandshakeResponse {
        if (buffer.len < 104) return error.BufferTooSmall;
        var response: HandshakeResponse = undefined;
        @memcpy(&response.responder_public_key, buffer[0..32]);
        response.timestamp = std.mem.readInt(u64, buffer[32..40], .big);
        @memcpy(&response.signature, buffer[40..104]);
        return response;
    }
};

/// Data packet structure
pub const DataPacket = struct {
    nonce: [12]u8,
    encrypted_payload: []const u8,
    tag: [16]u8,

    pub fn encode(self: *const DataPacket, buffer: []u8) !void {
        const total_size = 12 + self.encrypted_payload.len + 16;
        if (buffer.len < total_size) return error.BufferTooSmall;

        @memcpy(buffer[0..12], &self.nonce);
        @memcpy(buffer[12 .. 12 + self.encrypted_payload.len], self.encrypted_payload);
        @memcpy(buffer[12 + self.encrypted_payload.len .. total_size], &self.tag);
    }

    pub fn decode(buffer: []const u8, allocator: std.mem.Allocator) !DataPacket {
        if (buffer.len < 28) return error.BufferTooSmall; // 12 + 0 + 16 minimum

        var packet: DataPacket = undefined;
        @memcpy(&packet.nonce, buffer[0..12]);

        const payload_len = buffer.len - 12 - 16;
        packet.encrypted_payload = try allocator.dupe(u8, buffer[12 .. 12 + payload_len]);

        @memcpy(&packet.tag, buffer[12 + payload_len .. buffer.len]);
        return packet;
    }

    pub fn deinit(self: *DataPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.encrypted_payload);
    }
};

/// Stream management
pub const StreamFrame = struct {
    stream_id: u16,
    offset: u64,
    data: []const u8,
    is_final: bool,

    pub fn encode(self: *const StreamFrame, buffer: []u8) !void {
        const total_size = 2 + 8 + 1 + self.data.len;
        if (buffer.len < total_size) return error.BufferTooSmall;

        std.mem.writeInt(u16, buffer[0..2], self.stream_id, .big);
        std.mem.writeInt(u64, buffer[2..10], self.offset, .big);
        buffer[10] = if (self.is_final) 1 else 0;
        @memcpy(buffer[11..total_size], self.data);
    }

    pub fn decode(buffer: []const u8, allocator: std.mem.Allocator) !StreamFrame {
        if (buffer.len < 11) return error.BufferTooSmall;

        const stream_id = std.mem.readInt(u16, buffer[0..2], .big);
        const offset = std.mem.readInt(u64, buffer[2..10], .big);
        const is_final = buffer[10] == 1;

        const data = try allocator.dupe(u8, buffer[11..]);

        return StreamFrame{
            .stream_id = stream_id,
            .offset = offset,
            .data = data,
            .is_final = is_final,
        };
    }

    pub fn deinit(self: *StreamFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

test "protocol header encoding/decoding" {
    const header = ProtocolHeader{
        .version = 1,
        .message_type = .handshake_init,
        .flags = Flags.ENCRYPTED,
        .stream_id = 42,
        .length = 256,
    };

    var buffer: [8]u8 = undefined;
    try header.encode(&buffer);

    const decoded = try ProtocolHeader.decode(&buffer);
    try std.testing.expectEqual(header.version, decoded.version);
    try std.testing.expectEqual(header.message_type, decoded.message_type);
    try std.testing.expectEqual(header.flags, decoded.flags);
    try std.testing.expectEqual(header.stream_id, decoded.stream_id);
    try std.testing.expectEqual(header.length, decoded.length);
}

test "handshake init encoding/decoding" {
    const init = HandshakeInit{
        .sender_public_key = [_]u8{1} ** 32,
        .timestamp = 1234567890,
    };

    var buffer: [40]u8 = undefined;
    try init.encode(&buffer);

    const decoded = try HandshakeInit.decode(&buffer);
    try std.testing.expectEqualSlices(u8, &init.sender_public_key, &decoded.sender_public_key);
    try std.testing.expectEqual(init.timestamp, decoded.timestamp);
}
