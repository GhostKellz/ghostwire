const std = @import("std");
const crypto = std.crypto;

test "explore crypto api" {
    // Check available X25519 methods
    const info = @typeInfo(@TypeOf(crypto.dh.X25519));
    std.log.warn("X25519 type info: {}", .{info});
}
