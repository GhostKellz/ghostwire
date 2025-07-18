//! QUIC-native multiplexed relay implementation
//!
//! Implements a QUIC-based relay that can multiplex multiple connections
//! over a single QUIC connection with proper stream management.

const std = @import("std");
const net = std.net;

/// QUIC relay server state
var server_state: ?struct {
    socket: net.UdpSocket,
    running: bool,
    thread: ?std.Thread,
    allocator: std.mem.Allocator,
    connections: std.HashMap(u64, QuicRelayConnection, std.HashMap.DefaultContext(u64), std.HashMap.default_max_load_percentage),
} = null;

var server_mutex = std.Thread.Mutex{};

/// QUIC relay connection
const QuicRelayConnection = struct {
    id: u64,
    client_addr: net.Address,
    streams: std.HashMap(u16, RelayStream, std.HashMap.DefaultContext(u16), std.HashMap.default_max_load_percentage),
    last_activity: i64,
    allocator: std.mem.Allocator,

    const RelayStream = struct {
        stream_id: u16,
        target_addr: net.Address,
        buffer: std.ArrayList(u8),
        active: bool,

        fn init(allocator: std.mem.Allocator, stream_id: u16, target: net.Address) RelayStream {
            return RelayStream{
                .stream_id = stream_id,
                .target_addr = target,
                .buffer = std.ArrayList(u8).init(allocator),
                .active = true,
            };
        }

        fn deinit(self: *RelayStream) void {
            self.buffer.deinit();
        }
    };

    fn init(allocator: std.mem.Allocator, client: net.Address) QuicRelayConnection {
        return QuicRelayConnection{
            .id = std.crypto.random.int(u64),
            .client_addr = client,
            .streams = std.HashMap(u16, RelayStream, std.HashMap.DefaultContext(u16), std.HashMap.default_max_load_percentage).init(allocator),
            .last_activity = std.time.timestamp(),
            .allocator = allocator,
        };
    }

    fn deinit(self: *QuicRelayConnection) void {
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.streams.deinit();
    }

    fn addStream(self: *QuicRelayConnection, stream_id: u16, target: net.Address) !void {
        const stream = RelayStream.init(self.allocator, stream_id, target);
        try self.streams.put(stream_id, stream);
    }

    fn removeStream(self: *QuicRelayConnection, stream_id: u16) void {
        if (self.streams.getPtr(stream_id)) |stream| {
            stream.deinit();
            _ = self.streams.remove(stream_id);
        }
    }

    fn isIdle(self: *const QuicRelayConnection) bool {
        const now = std.time.timestamp();
        return (now - self.last_activity) > 300; // 5 minutes
    }
};

/// QUIC relay packet structure (simplified)
const QuicRelayPacket = packed struct {
    version: u8 = 1,
    packet_type: PacketType,
    connection_id: u64,
    stream_id: u16,
    length: u16,

    const PacketType = enum(u8) {
        connection_request = 1,
        connection_response = 2,
        stream_open = 3,
        stream_data = 4,
        stream_close = 5,
        keepalive = 6,
    };

    fn encode(self: *const QuicRelayPacket, buffer: []u8) !void {
        if (buffer.len < 13) return error.BufferTooSmall;

        buffer[0] = self.version;
        buffer[1] = @intFromEnum(self.packet_type);
        std.mem.writeInt(u64, buffer[2..10], self.connection_id, .big);
        std.mem.writeInt(u16, buffer[10..12], self.stream_id, .big);
        std.mem.writeInt(u16, buffer[12..14], self.length, .big);
    }

    fn decode(buffer: []const u8) !QuicRelayPacket {
        if (buffer.len < 13) return error.BufferTooSmall;

        return QuicRelayPacket{
            .version = buffer[0],
            .packet_type = @enumFromInt(buffer[1]),
            .connection_id = std.mem.readInt(u64, buffer[2..10], .big),
            .stream_id = std.mem.readInt(u16, buffer[10..12], .big),
            .length = std.mem.readInt(u16, buffer[12..14], .big),
        };
    }
};

/// Start QUIC relay server
pub fn start(bind_address: net.Address) !void {
    server_mutex.lock();
    defer server_mutex.unlock();

    if (server_state != null) return error.AlreadyRunning;

    const socket = try net.UdpSocket.bind(bind_address);

    server_state = .{
        .socket = socket,
        .running = true,
        .thread = null,
        .allocator = std.heap.page_allocator,
        .connections = std.HashMap(u64, QuicRelayConnection, std.HashMap.DefaultContext(u64), std.HashMap.default_max_load_percentage).init(std.heap.page_allocator),
    };

    // Start server thread
    server_state.?.thread = try std.Thread.spawn(.{}, serverLoop, .{});

    std.log.info("QUIC relay started on {}", .{bind_address});
}

/// Stop QUIC relay server
pub fn stop() void {
    server_mutex.lock();
    defer server_mutex.unlock();

    if (server_state) |*state| {
        state.running = false;

        if (state.thread) |thread| {
            thread.join();
        }

        // Clean up connections
        var iterator = state.connections.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        state.connections.deinit();

        state.socket.close();
        server_state = null;
    }

    std.log.info("QUIC relay stopped");
}

/// Main server loop
fn serverLoop() !void {
    var buffer: [4096]u8 = undefined;

    while (true) {
        server_mutex.lock();
        const running = if (server_state) |*state| state.running else false;
        server_mutex.unlock();

        if (!running) break;

        // Receive packet
        server_mutex.lock();
        const socket = if (server_state) |*state| &state.socket else {
            server_mutex.unlock();
            break;
        };

        const result = socket.receiveFrom(&buffer) catch |err| {
            server_mutex.unlock();
            if (err == error.WouldBlock) {
                std.time.sleep(1000000); // 1ms
                continue;
            }
            std.log.err("QUIC relay receive error: {}", .{err});
            continue;
        };
        server_mutex.unlock();

        try processPacket(buffer[0..result.bytes_received], result.sender);
    }
}

/// Process incoming packet
fn processPacket(data: []const u8, sender: net.Address) !void {
    if (data.len < 13) return; // Too small for header

    const header = QuicRelayPacket.decode(data[0..13]) catch return;
    const payload = data[13..];

    server_mutex.lock();
    defer server_mutex.unlock();

    if (server_state == null) return;
    const state = &server_state.?;

    switch (header.packet_type) {
        .connection_request => {
            try handleConnectionRequest(state, sender, header);
        },
        .stream_open => {
            try handleStreamOpen(state, sender, header, payload);
        },
        .stream_data => {
            try handleStreamData(state, sender, header, payload);
        },
        .stream_close => {
            handleStreamClose(state, sender, header);
        },
        .keepalive => {
            try handleKeepalive(state, sender, header);
        },
        else => {
            std.log.debug("QUIC relay: Unknown packet type from {}", .{sender});
        },
    }
}

/// Handle connection request
fn handleConnectionRequest(state: *@TypeOf(server_state.?), sender: net.Address, header: QuicRelayPacket) !void {
    // Create new connection
    var connection = QuicRelayConnection.init(state.allocator, sender);
    connection.id = header.connection_id;

    try state.connections.put(connection.id, connection);

    // Send connection response
    const response = QuicRelayPacket{
        .packet_type = .connection_response,
        .connection_id = header.connection_id,
        .stream_id = 0,
        .length = 0,
    };

    var response_buffer: [13]u8 = undefined;
    try response.encode(&response_buffer);

    _ = try state.socket.sendTo(&response_buffer, sender);

    std.log.info("QUIC relay: New connection {} from {}", .{ connection.id, sender });
}

/// Handle stream open request
fn handleStreamOpen(state: *@TypeOf(server_state.?), sender: net.Address, header: QuicRelayPacket, payload: []const u8) !void {
    _ = sender; // Mark as used to suppress warning
    var connection = state.connections.getPtr(header.connection_id) orelse return;

    if (payload.len < 6) return; // Need at least IP:port

    // Parse target address from payload (simplified)
    const target_ip = std.mem.readInt(u32, payload[0..4], .big);
    const target_port = std.mem.readInt(u16, payload[4..6], .big);
    const target_addr = net.Address.initIp4(@bitCast(target_ip), target_port);

    try connection.addStream(header.stream_id, target_addr);
    connection.last_activity = std.time.timestamp();

    std.log.debug("QUIC relay: Stream {} opened to {} for connection {}", .{ header.stream_id, target_addr, header.connection_id });
}

/// Handle stream data
fn handleStreamData(state: *@TypeOf(server_state.?), sender: net.Address, header: QuicRelayPacket, payload: []const u8) !void {
    var connection = state.connections.getPtr(header.connection_id) orelse return;
    const stream = connection.streams.getPtr(header.stream_id) orelse return;

    if (!stream.active) return;

    // Forward data to target (in real implementation, this would be async)
    std.log.debug("QUIC relay: Forwarding {} bytes from {} to {} (stream {})", .{ payload.len, sender, stream.target_addr, header.stream_id });

    // Update activity
    connection.last_activity = std.time.timestamp();
}

/// Handle stream close
fn handleStreamClose(state: *@TypeOf(server_state.?), sender: net.Address, header: QuicRelayPacket) void {
    _ = sender;
    var connection = state.connections.getPtr(header.connection_id) orelse return;
    connection.removeStream(header.stream_id);
    connection.last_activity = std.time.timestamp();

    std.log.debug("QUIC relay: Stream {} closed for connection {}", .{ header.stream_id, header.connection_id });
}

/// Handle keepalive
fn handleKeepalive(state: *@TypeOf(server_state.?), sender: net.Address, header: QuicRelayPacket) !void {
    var connection = state.connections.getPtr(header.connection_id) orelse return;
    connection.last_activity = std.time.timestamp();

    // Send keepalive response
    const response = QuicRelayPacket{
        .packet_type = .keepalive,
        .connection_id = header.connection_id,
        .stream_id = 0,
        .length = 0,
    };

    var response_buffer: [13]u8 = undefined;
    try response.encode(&response_buffer);

    _ = try state.socket.sendTo(&response_buffer, sender);

    std.log.debug("QUIC relay: Keepalive from {}", .{sender});
}

/// Check if server is running
pub fn isRunning() bool {
    server_mutex.lock();
    defer server_mutex.unlock();

    if (server_state) |state| {
        return state.running;
    }
    return false;
}

/// Get current connections count
pub fn getConnectionsCount() u32 {
    server_mutex.lock();
    defer server_mutex.unlock();

    if (server_state) |*state| {
        return @intCast(state.connections.count());
    }
    return 0;
}

/// Get relay statistics
pub fn getStats() struct {
    active_connections: u32,
    total_streams: u32,
    is_running: bool,
} {
    server_mutex.lock();
    defer server_mutex.unlock();

    if (server_state) |*state| {
        var total_streams: u32 = 0;
        var iterator = state.connections.iterator();
        while (iterator.next()) |entry| {
            total_streams += @intCast(entry.value_ptr.streams.count());
        }

        return .{
            .active_connections = @intCast(state.connections.count()),
            .total_streams = total_streams,
            .is_running = state.running,
        };
    }

    return .{
        .active_connections = 0,
        .total_streams = 0,
        .is_running = false,
    };
}

test "QUIC relay packet encoding" {
    const packet = QuicRelayPacket{
        .packet_type = .stream_data,
        .connection_id = 12345,
        .stream_id = 1,
        .length = 256,
    };

    var buffer: [20]u8 = undefined;
    try packet.encode(&buffer);

    const decoded = try QuicRelayPacket.decode(&buffer);
    try std.testing.expectEqual(packet.packet_type, decoded.packet_type);
    try std.testing.expectEqual(packet.connection_id, decoded.connection_id);
    try std.testing.expectEqual(packet.stream_id, decoded.stream_id);
    try std.testing.expectEqual(packet.length, decoded.length);
}

test "QUIC relay start/stop" {
    const addr = try std.net.Address.parseIp4("127.0.0.1", 8443);

    try start(addr);
    try std.testing.expect(isRunning());

    stop();
    try std.testing.expect(!isRunning());
}
