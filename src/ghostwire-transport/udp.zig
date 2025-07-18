//! UDP transport implementation for Ghostwire
//!
//! Provides basic UDP packet transport with proper error handling

const std = @import("std");
const net = std.net;

/// UDP socket wrapper
var socket: ?net.UdpSocket = null;
var socket_mutex = std.Thread.Mutex{};

/// Bind UDP socket to address
pub fn bind(address: net.Address) !void {
    socket_mutex.lock();
    defer socket_mutex.unlock();

    if (socket != null) {
        socket.?.close();
    }

    socket = try net.UdpSocket.bind(address);
}

/// Send UDP packet to destination
pub fn sendPacket(dest: net.Address, data: []const u8) !void {
    socket_mutex.lock();
    defer socket_mutex.unlock();

    if (socket == null) return error.NotBound;

    _ = try socket.?.sendTo(data, dest);
}

/// Receive UDP packet
pub fn receivePacket(buffer: []u8) !struct {
    source: net.Address,
    data: []u8,
} {
    socket_mutex.lock();
    defer socket_mutex.unlock();

    if (socket == null) return error.NotBound;

    const result = try socket.?.receiveFrom(buffer);

    return .{
        .source = result.sender,
        .data = buffer[0..result.bytes_received],
    };
}

/// Close UDP socket
pub fn close() void {
    socket_mutex.lock();
    defer socket_mutex.unlock();

    if (socket) |*s| {
        s.close();
        socket = null;
    }
}

/// Check if socket is bound
pub fn isBound() bool {
    socket_mutex.lock();
    defer socket_mutex.unlock();

    return socket != null;
}

test "UDP basic operations" {
    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);

    try bind(addr);
    defer close();

    try std.testing.expect(isBound());
}
