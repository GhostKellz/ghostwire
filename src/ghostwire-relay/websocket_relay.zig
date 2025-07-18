//! WebSocket-based stealth relay implementation
//!
//! Provides HTTP/WebSocket tunneling for environments where QUIC/UDP is blocked.
//! Designed to look like normal web traffic for DPI/firewall evasion.

const std = @import("std");
const net = std.net;

/// WebSocket relay server state
var server_state: ?struct {
    server: net.Server,
    bind_address: net.Address,
    running: bool,
    thread: ?std.Thread,
    allocator: std.mem.Allocator,
    connections: std.ArrayList(WebSocketConnection),
} = null;

var server_mutex = std.Thread.Mutex{};

/// WebSocket connection state
const WebSocketConnection = struct {
    stream: net.Stream,
    address: net.Address,
    handshake_complete: bool,
    peer_address: ?net.Address,
    last_activity: i64,
    bytes_transferred: u64,

    fn init(stream: net.Stream, address: net.Address) WebSocketConnection {
        return WebSocketConnection{
            .stream = stream,
            .address = address,
            .handshake_complete = false,
            .peer_address = null,
            .last_activity = std.time.timestamp(),
            .bytes_transferred = 0,
        };
    }

    fn updateActivity(self: *WebSocketConnection, bytes: u64) void {
        self.last_activity = std.time.timestamp();
        self.bytes_transferred += bytes;
    }

    fn isIdle(self: *const WebSocketConnection) bool {
        const now = std.time.timestamp();
        return (now - self.last_activity) > 300; // 5 minutes
    }

    fn close(self: *WebSocketConnection) void {
        self.stream.close();
    }
};

/// WebSocket frame header
const WebSocketFrame = struct {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload_length: u64,
    mask_key: ?[4]u8,

    const Opcode = enum(u4) {
        continuation = 0x0,
        text = 0x1,
        binary = 0x2,
        close = 0x8,
        ping = 0x9,
        pong = 0xa,
    };

    fn decode(data: []const u8) !struct { frame: WebSocketFrame, header_len: usize } {
        if (data.len < 2) return error.FrameTooSmall;

        const fin = (data[0] & 0x80) != 0;
        const opcode: Opcode = @enumFromInt(data[0] & 0x0F);
        const masked = (data[1] & 0x80) != 0;
        var payload_length: u64 = data[1] & 0x7F;
        var header_len: usize = 2;

        if (payload_length == 126) {
            if (data.len < 4) return error.FrameTooSmall;
            payload_length = std.mem.readInt(u16, data[2..4], .big);
            header_len = 4;
        } else if (payload_length == 127) {
            if (data.len < 10) return error.FrameTooSmall;
            payload_length = std.mem.readInt(u64, data[2..10], .big);
            header_len = 10;
        }

        var mask_key: ?[4]u8 = null;
        if (masked) {
            if (data.len < header_len + 4) return error.FrameTooSmall;
            mask_key = data[header_len .. header_len + 4][0..4].*;
            header_len += 4;
        }

        return .{
            .frame = WebSocketFrame{
                .fin = fin,
                .opcode = opcode,
                .masked = masked,
                .payload_length = payload_length,
                .mask_key = mask_key,
            },
            .header_len = header_len,
        };
    }

    fn encode(self: *const WebSocketFrame, payload: []const u8, buffer: []u8) !usize {
        if (buffer.len < 2) return error.BufferTooSmall;

        buffer[0] = if (self.fin) 0x80 else 0x00;
        buffer[0] |= @intFromEnum(self.opcode);

        var header_len: usize = 2;

        if (payload.len < 126) {
            buffer[1] = @intCast(payload.len);
        } else if (payload.len < 65536) {
            if (buffer.len < 4) return error.BufferTooSmall;
            buffer[1] = 126;
            std.mem.writeInt(u16, buffer[2..4], @intCast(payload.len), .big);
            header_len = 4;
        } else {
            if (buffer.len < 10) return error.BufferTooSmall;
            buffer[1] = 127;
            std.mem.writeInt(u64, buffer[2..10], payload.len, .big);
            header_len = 10;
        }

        if (self.masked) {
            buffer[1] |= 0x80;
            if (buffer.len < header_len + 4) return error.BufferTooSmall;
            if (self.mask_key) |mask| {
                @memcpy(buffer[header_len .. header_len + 4], &mask);
                header_len += 4;
            }
        }

        if (buffer.len < header_len + payload.len) return error.BufferTooSmall;
        @memcpy(buffer[header_len .. header_len + payload.len], payload);

        // Apply masking if needed
        if (self.masked and self.mask_key != null) {
            const mask = self.mask_key.?;
            for (0..payload.len) |i| {
                buffer[header_len + i] ^= mask[i % 4];
            }
        }

        return header_len + payload.len;
    }
};

/// Start WebSocket relay server
pub fn start(bind_address: net.Address) !void {
    server_mutex.lock();
    defer server_mutex.unlock();

    if (server_state != null) return error.AlreadyRunning;

    const server = try bind_address.listen(.{});

    server_state = .{
        .server = server,
        .bind_address = bind_address,
        .running = true,
        .thread = null,
        .allocator = std.heap.page_allocator,
        .connections = std.ArrayList(WebSocketConnection).init(std.heap.page_allocator),
    };

    // Start server thread
    server_state.?.thread = try std.Thread.spawn(.{}, serverLoop, .{});

    std.log.info("WebSocket relay started on {}", .{bind_address});
}

/// Stop WebSocket relay server
pub fn stop() void {
    server_mutex.lock();
    defer server_mutex.unlock();

    if (server_state) |*state| {
        state.running = false;

        if (state.thread) |thread| {
            thread.join();
        }

        // Close all connections
        for (state.connections.items) |*conn| {
            conn.close();
        }
        state.connections.deinit();

        state.server.deinit();
        server_state = null;
    }

    std.log.info("WebSocket relay stopped");
}

/// Main server loop
fn serverLoop() !void {
    while (true) {
        server_mutex.lock();
        const running = if (server_state) |*state| state.running else false;
        const server = if (server_state) |*state| &state.server else {
            server_mutex.unlock();
            break;
        };
        server_mutex.unlock();

        if (!running) break;

        // Accept new connection
        const client_connection = server.accept() catch |err| {
            if (err == error.WouldBlock) {
                std.time.sleep(1000000); // 1ms
                continue;
            }
            std.log.err("WebSocket relay accept error: {}", .{err});
            continue;
        };

        // Handle connection in a separate thread
        const thread = std.Thread.spawn(.{}, handleConnection, .{client_connection}) catch |err| {
            std.log.err("Failed to spawn connection handler: {}", .{err});
            client_connection.stream.close();
            continue;
        };
        thread.detach();
    }
}

/// Handle individual WebSocket connection
fn handleConnection(client_connection: net.Server.Connection) void {
    defer client_connection.stream.close();

    var ws_conn = WebSocketConnection.init(client_connection.stream, client_connection.address);

    // Perform WebSocket handshake
    if (performHandshake(&ws_conn)) {
        ws_conn.handshake_complete = true;
        std.log.info("WebSocket handshake completed for {}", .{ws_conn.address});
    } else |err| {
        std.log.warn("WebSocket handshake failed for {}: {}", .{ ws_conn.address, err });
        return;
    }

    // Handle WebSocket frames
    var buffer: [4096]u8 = undefined;
    while (true) {
        const bytes_read = ws_conn.stream.read(&buffer) catch |err| {
            if (err == error.EndOfStream) break;
            std.log.warn("WebSocket read error: {}", .{err});
            break;
        };

        if (bytes_read == 0) break;

        processWebSocketFrame(&ws_conn, buffer[0..bytes_read]) catch |err| {
            std.log.warn("WebSocket frame processing error: {}", .{err});
            break;
        };

        ws_conn.updateActivity(bytes_read);
    }

    std.log.info("WebSocket connection closed for {}", .{ws_conn.address});
}

/// Perform WebSocket handshake
fn performHandshake(conn: *WebSocketConnection) !void {
    var buffer: [2048]u8 = undefined;
    const bytes_read = try conn.stream.read(&buffer);

    // Parse HTTP request
    const request = buffer[0..bytes_read];
    if (!std.mem.startsWith(u8, request, "GET ")) {
        return error.InvalidRequest;
    }

    // Find WebSocket key
    const key_header = "Sec-WebSocket-Key: ";
    const key_start = std.mem.indexOf(u8, request, key_header) orelse return error.MissingWebSocketKey;
    const key_begin = key_start + key_header.len;
    const key_end = std.mem.indexOfScalarPos(u8, request, key_begin, '\r') orelse return error.MalformedWebSocketKey;
    const client_key = request[key_begin..key_end];

    // Generate accept key
    const websocket_magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var key_buffer: [60]u8 = undefined;
    const combined_key = try std.fmt.bufPrint(&key_buffer, "{s}{s}", .{ client_key, websocket_magic });

    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(combined_key);
    var hash: [20]u8 = undefined;
    sha1.final(&hash);

    var accept_key: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&accept_key, &hash);

    // Send handshake response
    const response = try std.fmt.allocPrint(std.heap.page_allocator, "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: {s}\r\n" ++
        "\r\n", .{accept_key});
    defer std.heap.page_allocator.free(response);

    _ = try conn.stream.writeAll(response);
}

/// Process WebSocket frame
fn processWebSocketFrame(conn: *WebSocketConnection, data: []const u8) !void {
    var offset: usize = 0;

    while (offset < data.len) {
        const frame_result = try WebSocketFrame.decode(data[offset..]);
        const frame = frame_result.frame;
        const header_len = frame_result.header_len;

        if (offset + header_len + frame.payload_length > data.len) {
            return error.IncompleteFrame;
        }

        var payload = data[offset + header_len .. offset + header_len + @as(usize, @intCast(frame.payload_length))];

        // Unmask payload if needed
        if (frame.masked and frame.mask_key != null) {
            const mask = frame.mask_key.?;
            for (0..payload.len) |i| {
                payload[i] ^= mask[i % 4];
            }
        }

        switch (frame.opcode) {
            .binary => {
                // Handle binary data - this is our tunneled data
                try forwardTunneledData(conn, payload);
            },
            .ping => {
                // Respond with pong
                try sendPong(conn, payload);
            },
            .close => {
                // Handle close frame
                try sendCloseFrame(conn);
                return;
            },
            else => {
                // Ignore other frame types
            },
        }

        offset += header_len + @as(usize, @intCast(frame.payload_length));
    }
}

/// Forward tunneled data
fn forwardTunneledData(conn: *WebSocketConnection, data: []const u8) !void {
    _ = conn; // Mark as used to suppress warning
    // Extract target address from tunneled data
    if (data.len < 6) return error.InvalidTunnelData;

    const target_ip = std.mem.readInt(u32, data[0..4], .big);
    const target_port = std.mem.readInt(u16, data[4..6], .big);
    const payload = data[6..];

    const target_addr = net.Address.initIp4(@bitCast(target_ip), target_port);

    // Forward to target (simplified - in reality we'd need proper connection management)
    const udp_socket = net.UdpSocket.init() catch return;
    defer udp_socket.close();

    _ = udp_socket.sendTo(payload, target_addr) catch |err| {
        std.log.warn("WebSocket relay: Failed to forward to {}: {}", .{ target_addr, err });
        return;
    };

    std.log.debug("WebSocket relay: Forwarded {} bytes to {}", .{ payload.len, target_addr });
}

/// Send pong frame
fn sendPong(conn: *WebSocketConnection, payload: []const u8) !void {
    const frame = WebSocketFrame{
        .fin = true,
        .opcode = .pong,
        .masked = false,
        .payload_length = payload.len,
        .mask_key = null,
    };

    var buffer: [1024]u8 = undefined;
    const encoded_len = try frame.encode(payload, &buffer);
    _ = try conn.stream.writeAll(buffer[0..encoded_len]);
}

/// Send close frame
fn sendCloseFrame(conn: *WebSocketConnection) !void {
    const frame = WebSocketFrame{
        .fin = true,
        .opcode = .close,
        .masked = false,
        .payload_length = 0,
        .mask_key = null,
    };

    var buffer: [16]u8 = undefined;
    const encoded_len = try frame.encode(&[_]u8{}, &buffer);
    _ = try conn.stream.writeAll(buffer[0..encoded_len]);
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

/// Get WebSocket relay statistics
pub fn getStats() struct {
    active_connections: u32,
    total_bytes_transferred: u64,
    is_running: bool,
} {
    server_mutex.lock();
    defer server_mutex.unlock();

    if (server_state) |*state| {
        var total_bytes: u64 = 0;

        for (state.connections.items) |*conn| {
            total_bytes += conn.bytes_transferred;
        }

        return .{
            .active_connections = @intCast(state.connections.items.len),
            .total_bytes_transferred = total_bytes,
            .is_running = state.running,
        };
    }

    return .{
        .active_connections = 0,
        .total_bytes_transferred = 0,
        .is_running = false,
    };
}

test "WebSocket frame encoding" {
    const frame = WebSocketFrame{
        .fin = true,
        .opcode = .binary,
        .masked = false,
        .payload_length = 5,
        .mask_key = null,
    };

    const payload = "hello";
    var buffer: [16]u8 = undefined;
    const encoded_len = try frame.encode(payload, &buffer);

    try std.testing.expect(encoded_len >= 2 + payload.len);
    try std.testing.expectEqual(@as(u8, 0x82), buffer[0]); // FIN + binary opcode
    try std.testing.expectEqual(@as(u8, 5), buffer[1]); // payload length
}

test "WebSocket relay start/stop" {
    const addr = try std.net.Address.parseIp4("127.0.0.1", 8080);

    try start(addr);
    try std.testing.expect(isRunning());

    stop();
    try std.testing.expect(!isRunning());
}
