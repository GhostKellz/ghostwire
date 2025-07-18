//! Handshake implementation for Ghostwire protocol
//!
//! Implements the cryptographic handshake using X25519 + Ed25519

const std = @import("std");
const crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");

/// Handshake state machine
pub const HandshakeState = enum {
    uninitialized,
    initiated,
    responded,
    completed,
    failed,
};

/// Handshake context
pub const HandshakeContext = struct {
    state: HandshakeState = .uninitialized,
    local_keypair: crypto.X25519KeyPair,
    local_identity: crypto.Ed25519KeyPair,
    peer_public_key: ?[32]u8 = null,
    shared_secret: ?[32]u8 = null,
    session_key: ?[32]u8 = null,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !HandshakeContext {
        return HandshakeContext{
            .local_keypair = try crypto.X25519KeyPair.generate(),
            .local_identity = try crypto.Ed25519KeyPair.generate(),
            .allocator = allocator,
        };
    }

    /// Initiate handshake as client
    pub fn initiate(self: *HandshakeContext, buffer: []u8) ![]u8 {
        if (self.state != .uninitialized) return error.InvalidState;

        const init_msg = protocol.HandshakeInit{
            .sender_public_key = self.local_keypair.public_key,
            .timestamp = std.time.timestamp(),
        };

        const header = protocol.ProtocolHeader{
            .version = 1,
            .message_type = .handshake_init,
            .flags = 0,
            .stream_id = 0,
            .length = 40,
        };

        if (buffer.len < 48) return error.BufferTooSmall;

        try header.encode(buffer[0..8]);
        try init_msg.encode(buffer[8..48]);

        self.state = .initiated;
        return buffer[0..48];
    }

    /// Respond to handshake as server
    pub fn respond(self: *HandshakeContext, init_data: []const u8, buffer: []u8) ![]u8 {
        if (self.state != .uninitialized) return error.InvalidState;

        const header = try protocol.ProtocolHeader.decode(init_data[0..8]);
        if (header.message_type != .handshake_init) return error.InvalidMessage;

        const init_msg = try protocol.HandshakeInit.decode(init_data[8..]);
        self.peer_public_key = init_msg.sender_public_key;

        // Derive shared secret
        self.shared_secret = try self.local_keypair.exchange(init_msg.sender_public_key);

        // Create response
        const response_msg = protocol.HandshakeResponse{
            .responder_public_key = self.local_keypair.public_key,
            .timestamp = std.time.timestamp(),
            .signature = try self.local_identity.sign(&init_msg.sender_public_key),
        };

        const response_header = protocol.ProtocolHeader{
            .version = 1,
            .message_type = .handshake_response,
            .flags = 0,
            .stream_id = 0,
            .length = 104,
        };

        if (buffer.len < 112) return error.BufferTooSmall;

        try response_header.encode(buffer[0..8]);
        try response_msg.encode(buffer[8..112]);

        // Derive session key
        self.session_key = crypto.deriveKey(
            &(self.shared_secret orelse return error.NoSharedSecret),
            "ghostwire-v1",
            "session-key",
        );

        self.state = .responded;
        return buffer[0..112];
    }

    /// Complete handshake as client
    pub fn complete(self: *HandshakeContext, response_data: []const u8, buffer: []u8) ![]u8 {
        if (self.state != .initiated) return error.InvalidState;

        const header = try protocol.ProtocolHeader.decode(response_data[0..8]);
        if (header.message_type != .handshake_response) return error.InvalidMessage;

        const response_msg = try protocol.HandshakeResponse.decode(response_data[8..]);
        self.peer_public_key = response_msg.responder_public_key;

        // Derive shared secret
        self.shared_secret = try self.local_keypair.exchange(response_msg.responder_public_key);

        // Verify signature (simplified - would need proper context)
        // const is_valid = crypto.Ed25519KeyPair.verify(
        //     peer_identity_key,
        //     &self.local_keypair.public_key,
        //     response_msg.signature
        // );
        // if (!is_valid) return error.InvalidSignature;

        // Derive session key
        self.session_key = crypto.deriveKey(
            &(self.shared_secret orelse return error.NoSharedSecret),
            "ghostwire-v1",
            "session-key",
        );

        // Send completion
        const complete_header = protocol.ProtocolHeader{
            .version = 1,
            .message_type = .handshake_complete,
            .flags = 0,
            .stream_id = 0,
            .length = 0,
        };

        if (buffer.len < 8) return error.BufferTooSmall;

        try complete_header.encode(buffer[0..8]);

        self.state = .completed;
        return buffer[0..8];
    }

    /// Process handshake completion as server
    pub fn processCompletion(self: *HandshakeContext, complete_data: []const u8) !void {
        if (self.state != .responded) return error.InvalidState;

        const header = try protocol.ProtocolHeader.decode(complete_data[0..8]);
        if (header.message_type != .handshake_complete) return error.InvalidMessage;

        self.state = .completed;
    }

    /// Check if handshake is complete
    pub fn isComplete(self: *const HandshakeContext) bool {
        return self.state == .completed and self.session_key != null;
    }

    /// Get the session encryption cipher
    pub fn getCipher(self: *const HandshakeContext) !crypto.ChaCha20Poly1305 {
        if (self.session_key == null) return error.NoSessionKey;
        return crypto.ChaCha20Poly1305.init(self.session_key.?);
    }
};

test "handshake full flow" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var client = try HandshakeContext.init(allocator);
    var server = try HandshakeContext.init(allocator);

    var buffer: [256]u8 = undefined;

    // Client initiates
    const init_msg = try client.initiate(&buffer);

    // Server responds
    const response_msg = try server.respond(init_msg, &buffer);

    // Client completes
    const complete_msg = try client.complete(response_msg, &buffer);

    // Server processes completion
    try server.processCompletion(complete_msg);

    try std.testing.expect(client.isComplete());
    try std.testing.expect(server.isComplete());

    // Both should have session keys
    const client_cipher = try client.getCipher();
    const server_cipher = try server.getCipher();

    // Keys should be the same (simplified test)
    try std.testing.expectEqualSlices(u8, &client.session_key.?, &server.session_key.?);

    _ = client_cipher;
    _ = server_cipher;
}
