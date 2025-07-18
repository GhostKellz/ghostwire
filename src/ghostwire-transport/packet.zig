//! Packet handling utilities for Ghostwire transport
//!
//! Provides packet parsing, validation, and utilities

const std = @import("std");

/// Packet header for transport layer
pub const PacketHeader = packed struct {
    version: u8 = 1,
    packet_type: PacketType,
    flags: u8 = 0,
    sequence: u32,
    timestamp: u64,
    length: u16,

    pub const SIZE = 16;

    pub fn encode(self: *const PacketHeader, buffer: []u8) !void {
        if (buffer.len < SIZE) return error.BufferTooSmall;

        buffer[0] = self.version;
        buffer[1] = @intFromEnum(self.packet_type);
        buffer[2] = self.flags;
        buffer[3] = 0; // Reserved
        std.mem.writeInt(u32, buffer[4..8], self.sequence, .big);
        std.mem.writeInt(u64, buffer[8..16], self.timestamp, .big);
        std.mem.writeInt(u16, buffer[16..18], self.length, .big);
    }

    pub fn decode(buffer: []const u8) !PacketHeader {
        if (buffer.len < SIZE) return error.BufferTooSmall;

        return PacketHeader{
            .version = buffer[0],
            .packet_type = @enumFromInt(buffer[1]),
            .flags = buffer[2],
            .sequence = std.mem.readInt(u32, buffer[4..8], .big),
            .timestamp = std.mem.readInt(u64, buffer[8..16], .big),
            .length = std.mem.readInt(u16, buffer[16..18], .big),
        };
    }
};

/// Packet types
pub const PacketType = enum(u8) {
    data = 0x01,
    ack = 0x02,
    ping = 0x03,
    pong = 0x04,
    close = 0x05,
    _,
};

/// Packet flags
pub const PacketFlags = struct {
    pub const RETRANSMIT: u8 = 0x01;
    pub const OUT_OF_ORDER: u8 = 0x02;
    pub const PRIORITY_HIGH: u8 = 0x04;
    pub const FRAGMENTED: u8 = 0x08;
};

/// ACK packet payload
pub const AckPacket = struct {
    acked_sequence: u32,
    ack_delay: u32, // In microseconds

    pub fn encode(self: *const AckPacket, buffer: []u8) !void {
        if (buffer.len < 8) return error.BufferTooSmall;
        std.mem.writeInt(u32, buffer[0..4], self.acked_sequence, .big);
        std.mem.writeInt(u32, buffer[4..8], self.ack_delay, .big);
    }

    pub fn decode(buffer: []const u8) !AckPacket {
        if (buffer.len < 8) return error.BufferTooSmall;
        return AckPacket{
            .acked_sequence = std.mem.readInt(u32, buffer[0..4], .big),
            .ack_delay = std.mem.readInt(u32, buffer[4..8], .big),
        };
    }
};

/// Packet validation
pub fn validatePacket(data: []const u8) !void {
    if (data.len < PacketHeader.SIZE) return error.PacketTooSmall;

    const header = try PacketHeader.decode(data);

    if (header.version != 1) return error.InvalidVersion;
    if (header.length > data.len - PacketHeader.SIZE) return error.InvalidLength;
}

/// Calculate packet checksum (simple XOR for demonstration)
pub fn calculateChecksum(data: []const u8) u32 {
    var checksum: u32 = 0;
    for (data) |byte| {
        checksum ^= byte;
    }
    return checksum;
}

/// Packet builder utility
pub const PacketBuilder = struct {
    buffer: []u8,
    offset: usize = 0,

    pub fn init(buffer: []u8) PacketBuilder {
        return PacketBuilder{ .buffer = buffer };
    }

    pub fn addHeader(self: *PacketBuilder, header: PacketHeader) !void {
        if (self.buffer.len - self.offset < PacketHeader.SIZE) return error.BufferTooSmall;

        try header.encode(self.buffer[self.offset..]);
        self.offset += PacketHeader.SIZE;
    }

    pub fn addPayload(self: *PacketBuilder, payload: []const u8) !void {
        if (self.buffer.len - self.offset < payload.len) return error.BufferTooSmall;

        @memcpy(self.buffer[self.offset .. self.offset + payload.len], payload);
        self.offset += payload.len;
    }

    pub fn finalize(self: *const PacketBuilder) []u8 {
        return self.buffer[0..self.offset];
    }

    pub fn reset(self: *PacketBuilder) void {
        self.offset = 0;
    }
};

/// Packet parser utility
pub const PacketParser = struct {
    data: []const u8,
    offset: usize = 0,

    pub fn init(data: []const u8) !PacketParser {
        try validatePacket(data);
        return PacketParser{ .data = data };
    }

    pub fn getHeader(self: *PacketParser) !PacketHeader {
        if (self.data.len < PacketHeader.SIZE) return error.InvalidPacket;

        const header = try PacketHeader.decode(self.data[0..]);
        self.offset = PacketHeader.SIZE;
        return header;
    }

    pub fn getPayload(self: *const PacketParser) []const u8 {
        if (self.offset >= self.data.len) return &[_]u8{};
        return self.data[self.offset..];
    }

    pub fn parseAck(self: *const PacketParser) !AckPacket {
        const payload = self.getPayload();
        return AckPacket.decode(payload);
    }
};

/// Sequence number management
pub const SequenceManager = struct {
    next_sequence: u32 = 1,
    expected_sequence: u32 = 1,
    received_sequences: std.bit_set.ArrayBitSet(u32, 1024),

    pub fn init() SequenceManager {
        return SequenceManager{
            .received_sequences = std.bit_set.ArrayBitSet(u32, 1024).initEmpty(),
        };
    }

    pub fn getNextSequence(self: *SequenceManager) u32 {
        const seq = self.next_sequence;
        self.next_sequence +%= 1;
        return seq;
    }

    pub fn isSequenceExpected(self: *const SequenceManager, sequence: u32) bool {
        return sequence == self.expected_sequence;
    }

    pub fn markReceived(self: *SequenceManager, sequence: u32) void {
        if (sequence < 1024) {
            self.received_sequences.set(sequence);
        }

        if (sequence == self.expected_sequence) {
            self.expected_sequence +%= 1;
        }
    }

    pub fn hasGaps(self: *const SequenceManager) bool {
        for (1..self.expected_sequence) |seq| {
            if (seq < 1024 and !self.received_sequences.isSet(@intCast(seq))) {
                return true;
            }
        }
        return false;
    }
};

test "packet header encoding/decoding" {
    const header = PacketHeader{
        .packet_type = .data,
        .sequence = 12345,
        .timestamp = 1234567890,
        .length = 256,
    };

    var buffer: [32]u8 = undefined;
    try header.encode(&buffer);

    const decoded = try PacketHeader.decode(&buffer);
    try std.testing.expectEqual(header.packet_type, decoded.packet_type);
    try std.testing.expectEqual(header.sequence, decoded.sequence);
    try std.testing.expectEqual(header.timestamp, decoded.timestamp);
    try std.testing.expectEqual(header.length, decoded.length);
}

test "packet builder" {
    var buffer: [64]u8 = undefined;
    var builder = PacketBuilder.init(&buffer);

    const header = PacketHeader{
        .packet_type = .data,
        .sequence = 1,
        .timestamp = std.time.timestamp(),
        .length = 4,
    };

    try builder.addHeader(header);
    try builder.addPayload("test");

    const packet = builder.finalize();
    try std.testing.expect(packet.len > PacketHeader.SIZE);
}

test "sequence manager" {
    var seq_mgr = SequenceManager.init();

    const seq1 = seq_mgr.getNextSequence();
    const seq2 = seq_mgr.getNextSequence();

    try std.testing.expectEqual(@as(u32, 1), seq1);
    try std.testing.expectEqual(@as(u32, 2), seq2);

    try std.testing.expect(seq_mgr.isSequenceExpected(1));
    try std.testing.expect(!seq_mgr.isSequenceExpected(2));

    seq_mgr.markReceived(1);
    try std.testing.expect(seq_mgr.isSequenceExpected(2));
}
