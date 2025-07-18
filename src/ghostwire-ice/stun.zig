//! STUN protocol implementation (RFC 5389)
//!
//! Implements STUN client and server functionality for NAT discovery

const std = @import("std");
const crypto = std.crypto;

/// STUN message types
pub const MessageType = enum(u16) {
    binding_request = 0x0001,
    binding_response = 0x0101,
    binding_error_response = 0x0111,
    _,
};

/// STUN message header (20 bytes)
pub const MessageHeader = packed struct {
    message_type: u16,
    message_length: u16,
    magic_cookie: u32 = 0x2112A442,
    transaction_id: [12]u8,

    pub fn encode(self: *const MessageHeader, buffer: []u8) !void {
        if (buffer.len < 20) return error.BufferTooSmall;

        std.mem.writeInt(u16, buffer[0..2], @intFromEnum(self.message_type), .big);
        std.mem.writeInt(u16, buffer[2..4], self.message_length, .big);
        std.mem.writeInt(u32, buffer[4..8], self.magic_cookie, .big);
        @memcpy(buffer[8..20], &self.transaction_id);
    }

    pub fn decode(buffer: []const u8) !MessageHeader {
        if (buffer.len < 20) return error.BufferTooSmall;

        const magic = std.mem.readInt(u32, buffer[4..8], .big);
        if (magic != 0x2112A442) return error.InvalidMagicCookie;

        var transaction_id: [12]u8 = undefined;
        @memcpy(&transaction_id, buffer[8..20]);

        return MessageHeader{
            .message_type = std.mem.readInt(u16, buffer[0..2], .big),
            .message_length = std.mem.readInt(u16, buffer[2..4], .big),
            .transaction_id = transaction_id,
        };
    }
};

/// STUN attribute types
pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    username = 0x0006,
    message_integrity = 0x0008,
    error_code = 0x0009,
    unknown_attributes = 0x000A,
    realm = 0x0014,
    nonce = 0x0015,
    xor_mapped_address = 0x0020,
    priority = 0x0024,
    use_candidate = 0x0025,
    ice_controlled = 0x8029,
    ice_controlling = 0x802A,
    _,
};

/// STUN attribute
pub const Attribute = struct {
    attribute_type: AttributeType,
    length: u16,
    value: []const u8,

    pub fn encode(self: *const Attribute, buffer: []u8) !usize {
        const total_length = 4 + self.length;
        const padded_length = std.mem.alignForward(usize, total_length, 4);

        if (buffer.len < padded_length) return error.BufferTooSmall;

        std.mem.writeInt(u16, buffer[0..2], @intFromEnum(self.attribute_type), .big);
        std.mem.writeInt(u16, buffer[2..4], self.length, .big);
        @memcpy(buffer[4 .. 4 + self.length], self.value);

        // Pad to 4-byte boundary
        if (padded_length > total_length) {
            @memset(buffer[total_length..padded_length], 0);
        }

        return padded_length;
    }

    pub fn decode(buffer: []const u8, allocator: std.mem.Allocator) !struct {
        attribute: Attribute,
        bytes_consumed: usize,
    } {
        if (buffer.len < 4) return error.BufferTooSmall;

        const attr_type: AttributeType = @enumFromInt(std.mem.readInt(u16, buffer[0..2], .big));
        const length = std.mem.readInt(u16, buffer[2..4], .big);

        if (buffer.len < 4 + length) return error.BufferTooSmall;

        const value = try allocator.dupe(u8, buffer[4 .. 4 + length]);
        const padded_length = std.mem.alignForward(usize, 4 + length, 4);

        return .{
            .attribute = Attribute{
                .attribute_type = attr_type,
                .length = length,
                .value = value,
            },
            .bytes_consumed = padded_length,
        };
    }
};

/// STUN message
pub const Message = struct {
    header: MessageHeader,
    attributes: std.ArrayList(Attribute),

    pub fn init(allocator: std.mem.Allocator, message_type: MessageType) Message {
        var transaction_id: [12]u8 = undefined;
        crypto.random.bytes(&transaction_id);

        return Message{
            .header = MessageHeader{
                .message_type = @intFromEnum(message_type),
                .message_length = 0,
                .transaction_id = transaction_id,
            },
            .attributes = std.ArrayList(Attribute).init(allocator),
        };
    }

    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        for (self.attributes.items) |attr| {
            allocator.free(attr.value);
        }
        self.attributes.deinit();
    }

    pub fn addAttribute(self: *Message, attribute: Attribute) !void {
        try self.attributes.append(attribute);
        self.updateLength();
    }

    fn updateLength(self: *Message) void {
        var total_length: u16 = 0;
        for (self.attributes.items) |attr| {
            const attr_length = std.mem.alignForward(u16, 4 + attr.length, 4);
            total_length += attr_length;
        }
        self.header.message_length = total_length;
    }

    pub fn encode(self: *Message, buffer: []u8) ![]u8 {
        self.updateLength();

        const total_size = 20 + self.header.message_length;
        if (buffer.len < total_size) return error.BufferTooSmall;

        try self.header.encode(buffer[0..20]);

        var offset: usize = 20;
        for (self.attributes.items) |attr| {
            const bytes_written = try attr.encode(buffer[offset..]);
            offset += bytes_written;
        }

        return buffer[0..total_size];
    }
};

/// Parse STUN message from buffer
pub fn parseMessage(buffer: []const u8) !struct {
    message_type: MessageType,
    transaction_id: [12]u8,
    attributes: std.ArrayList(Attribute),
} {
    const header = try MessageHeader.decode(buffer);

    // TODO: Parse attributes
    var attributes = std.ArrayList(Attribute).init(std.heap.page_allocator);

    return .{
        .message_type = @enumFromInt(header.message_type),
        .transaction_id = header.transaction_id,
        .attributes = attributes,
    };
}

/// Create STUN binding request
pub fn createBindingRequest(allocator: std.mem.Allocator, username: []const u8, password: []const u8) ![]u8 {
    var message = Message.init(allocator, .binding_request);
    defer message.deinit(allocator);

    // Add username if provided
    if (username.len > 0) {
        const username_attr = Attribute{
            .attribute_type = .username,
            .length = @intCast(username.len),
            .value = try allocator.dupe(u8, username),
        };
        try message.addAttribute(username_attr);
    }

    // TODO: Add MESSAGE-INTEGRITY attribute with HMAC-SHA1
    _ = password;

    var buffer = try allocator.alloc(u8, 1024);
    const encoded = try message.encode(buffer);

    return try allocator.dupe(u8, encoded);
}

/// Create STUN binding response
pub fn createBindingResponse(allocator: std.mem.Allocator, mapped_address: std.net.Address, transaction_id: [12]u8) ![]u8 {
    var message = Message{
        .header = MessageHeader{
            .message_type = @intFromEnum(MessageType.binding_response),
            .message_length = 0,
            .transaction_id = transaction_id,
        },
        .attributes = std.ArrayList(Attribute).init(allocator),
    };
    defer message.deinit(allocator);

    // Add XOR-MAPPED-ADDRESS attribute
    var addr_buffer: [8]u8 = undefined;
    try encodeXorMappedAddress(mapped_address, transaction_id, &addr_buffer);

    const addr_attr = Attribute{
        .attribute_type = .xor_mapped_address,
        .length = 8,
        .value = try allocator.dupe(u8, &addr_buffer),
    };
    try message.addAttribute(addr_attr);

    var buffer = try allocator.alloc(u8, 1024);
    const encoded = try message.encode(buffer);

    return try allocator.dupe(u8, encoded);
}

/// Encode XOR-MAPPED-ADDRESS attribute
fn encodeXorMappedAddress(address: std.net.Address, transaction_id: [12]u8, buffer: []u8) !void {
    if (buffer.len < 8) return error.BufferTooSmall;

    switch (address.any.family) {
        std.posix.AF.INET => {
            buffer[0] = 0; // Reserved
            buffer[1] = 0x01; // IPv4

            const port = address.in.port;
            const xor_port = port ^ 0x2112;
            std.mem.writeInt(u16, buffer[2..4], xor_port, .big);

            const ip = @as(u32, @bitCast(address.in.addr));
            const xor_ip = ip ^ 0x2112A442;
            std.mem.writeInt(u32, buffer[4..8], xor_ip, .big);
        },
        else => return error.UnsupportedAddressFamily,
    }
}

/// Decode XOR-MAPPED-ADDRESS attribute
pub fn decodeXorMappedAddress(buffer: []const u8, transaction_id: [12]u8) !std.net.Address {
    if (buffer.len < 8) return error.BufferTooSmall;

    const family = buffer[1];

    switch (family) {
        0x01 => { // IPv4
            const xor_port = std.mem.readInt(u16, buffer[2..4], .big);
            const port = xor_port ^ 0x2112;

            const xor_ip = std.mem.readInt(u32, buffer[4..8], .big);
            const ip = xor_ip ^ 0x2112A442;

            return std.net.Address.initIp4(@bitCast(ip), port);
        },
        else => return error.UnsupportedAddressFamily,
    }
}

test "STUN message header encoding/decoding" {
    var transaction_id: [12]u8 = undefined;
    crypto.random.bytes(&transaction_id);

    const header = MessageHeader{
        .message_type = @intFromEnum(MessageType.binding_request),
        .message_length = 0,
        .transaction_id = transaction_id,
    };

    var buffer: [20]u8 = undefined;
    try header.encode(&buffer);

    const decoded = try MessageHeader.decode(&buffer);
    try std.testing.expectEqual(header.message_type, decoded.message_type);
    try std.testing.expectEqual(header.message_length, decoded.message_length);
    try std.testing.expectEqual(header.magic_cookie, decoded.magic_cookie);
}

test "XOR-MAPPED-ADDRESS encoding/decoding" {
    const address = try std.net.Address.parseIp4("192.168.1.100", 54321);
    var transaction_id: [12]u8 = undefined;
    crypto.random.bytes(&transaction_id);

    var buffer: [8]u8 = undefined;
    try encodeXorMappedAddress(address, transaction_id, &buffer);

    const decoded = try decodeXorMappedAddress(&buffer, transaction_id);
    try std.testing.expectEqual(address.in.port, decoded.in.port);
    try std.testing.expectEqual(address.in.addr, decoded.in.addr);
}
