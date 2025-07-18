//! Stream multiplexing for Ghostwire protocol
//!
//! Implements multiplexed streams over a single connection

const std = @import("std");
const protocol = @import("protocol.zig");

/// Stream state
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// Stream flow control
pub const FlowControl = struct {
    window_size: u32 = 65536, // 64KB default window
    bytes_sent: u32 = 0,
    bytes_acked: u32 = 0,

    pub fn canSend(self: *const FlowControl, bytes: u32) bool {
        return (self.bytes_sent - self.bytes_acked + bytes) <= self.window_size;
    }

    pub fn addSent(self: *FlowControl, bytes: u32) void {
        self.bytes_sent += bytes;
    }

    pub fn addAcked(self: *FlowControl, bytes: u32) void {
        self.bytes_acked += bytes;
    }
};

/// Individual stream
pub const Stream = struct {
    id: u16,
    state: StreamState = .idle,
    send_offset: u64 = 0,
    recv_offset: u64 = 0,
    flow_control: FlowControl = .{},
    send_buffer: std.ArrayList(u8),
    recv_buffer: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator, id: u16) Stream {
        return Stream{
            .id = id,
            .send_buffer = std.ArrayList(u8).init(allocator),
            .recv_buffer = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *Stream) void {
        self.send_buffer.deinit();
        self.recv_buffer.deinit();
    }

    /// Open the stream
    pub fn open(self: *Stream) !void {
        if (self.state != .idle) return error.InvalidState;
        self.state = .open;
    }

    /// Write data to stream
    pub fn write(self: *Stream, data: []const u8) !void {
        if (self.state != .open) return error.StreamNotOpen;
        try self.send_buffer.appendSlice(data);
    }

    /// Read data from stream
    pub fn read(self: *Stream, buffer: []u8) !usize {
        if (self.recv_buffer.items.len == 0) return 0;

        const bytes_to_read = @min(buffer.len, self.recv_buffer.items.len);
        @memcpy(buffer[0..bytes_to_read], self.recv_buffer.items[0..bytes_to_read]);

        // Remove read bytes from buffer
        const remaining = self.recv_buffer.items.len - bytes_to_read;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.recv_buffer.items[0..remaining], self.recv_buffer.items[bytes_to_read..]);
        }
        self.recv_buffer.shrinkRetainingCapacity(remaining);

        return bytes_to_read;
    }

    /// Close stream for sending
    pub fn closeWrite(self: *Stream) void {
        if (self.state == .open) {
            self.state = .half_closed_local;
        } else if (self.state == .half_closed_remote) {
            self.state = .closed;
        }
    }

    /// Close stream for receiving
    pub fn closeRead(self: *Stream) void {
        if (self.state == .open) {
            self.state = .half_closed_remote;
        } else if (self.state == .half_closed_local) {
            self.state = .closed;
        }
    }

    /// Check if stream can send data
    pub fn canSend(self: *const Stream) bool {
        return self.state == .open and self.send_buffer.items.len > 0;
    }

    /// Get next frame to send
    pub fn getNextFrame(self: *Stream, max_size: usize) ?protocol.StreamFrame {
        if (!self.canSend()) return null;

        const bytes_to_send = @min(max_size, self.send_buffer.items.len);
        if (bytes_to_send == 0) return null;

        const is_final = bytes_to_send == self.send_buffer.items.len;

        const frame = protocol.StreamFrame{
            .stream_id = self.id,
            .offset = self.send_offset,
            .data = self.send_buffer.items[0..bytes_to_send],
            .is_final = is_final,
        };

        self.send_offset += bytes_to_send;

        return frame;
    }

    /// Process received frame
    pub fn processFrame(self: *Stream, frame: protocol.StreamFrame) !void {
        if (frame.stream_id != self.id) return error.WrongStreamId;

        // For simplicity, assume frames arrive in order
        if (frame.offset != self.recv_offset) return error.OutOfOrder;

        try self.recv_buffer.appendSlice(frame.data);
        self.recv_offset += frame.data.len;

        if (frame.is_final) {
            self.closeRead();
        }
    }
};

/// Stream multiplexer
pub const StreamMux = struct {
    streams: std.HashMap(u16, Stream, std.HashMap.DefaultContext(u16), std.HashMap.default_max_load_percentage),
    next_stream_id: u16 = 1,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StreamMux {
        return StreamMux{
            .streams = std.HashMap(u16, Stream, std.HashMap.DefaultContext(u16), std.HashMap.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StreamMux) void {
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.streams.deinit();
    }

    /// Create a new stream
    pub fn createStream(self: *StreamMux) !u16 {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Odd for client, even for server

        var stream = Stream.init(self.allocator, stream_id);
        try stream.open();

        try self.streams.put(stream_id, stream);
        return stream_id;
    }

    /// Get stream by ID
    pub fn getStream(self: *StreamMux, stream_id: u16) ?*Stream {
        return self.streams.getPtr(stream_id);
    }

    /// Accept incoming stream
    pub fn acceptStream(self: *StreamMux, stream_id: u16) !void {
        if (self.streams.contains(stream_id)) return error.StreamExists;

        var stream = Stream.init(self.allocator, stream_id);
        try stream.open();

        try self.streams.put(stream_id, stream);
    }

    /// Process incoming stream frame
    pub fn processFrame(self: *StreamMux, frame: protocol.StreamFrame) !void {
        var stream = self.getStream(frame.stream_id);

        if (stream == null) {
            // Auto-accept new stream
            try self.acceptStream(frame.stream_id);
            stream = self.getStream(frame.stream_id);
        }

        if (stream) |s| {
            try s.processFrame(frame);
        }
    }

    /// Get all frames ready to send
    pub fn getFramesToSend(self: *StreamMux, allocator: std.mem.Allocator, max_frame_size: usize) !std.ArrayList(protocol.StreamFrame) {
        var frames = std.ArrayList(protocol.StreamFrame).init(allocator);

        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            var stream = entry.value_ptr;
            if (stream.canSend()) {
                if (stream.getNextFrame(max_frame_size)) |frame| {
                    try frames.append(frame);
                }
            }
        }

        return frames;
    }

    /// Close stream
    pub fn closeStream(self: *StreamMux, stream_id: u16) void {
        if (self.streams.getPtr(stream_id)) |stream| {
            stream.closeWrite();
            stream.closeRead();

            if (stream.state == .closed) {
                stream.deinit();
                _ = self.streams.remove(stream_id);
            }
        }
    }

    /// Get statistics
    pub fn getStats(self: *const StreamMux) struct {
        active_streams: usize,
        total_streams: usize,
    } {
        return .{
            .active_streams = self.streams.count(),
            .total_streams = self.next_stream_id / 2,
        };
    }
};

test "stream basic operations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stream = Stream.init(allocator, 1);
    defer stream.deinit();

    try stream.open();
    try std.testing.expectEqual(StreamState.open, stream.state);

    const test_data = "Hello, Ghostwire!";
    try stream.write(test_data);

    var read_buffer: [32]u8 = undefined;
    const bytes_read = try stream.read(&read_buffer);
    try std.testing.expectEqual(test_data.len, bytes_read);
    try std.testing.expectEqualSlices(u8, test_data, read_buffer[0..bytes_read]);
}

test "stream multiplexer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var mux = StreamMux.init(allocator);
    defer mux.deinit();

    const stream_id = try mux.createStream();
    try std.testing.expect(stream_id > 0);

    const stream = mux.getStream(stream_id);
    try std.testing.expect(stream != null);
    try std.testing.expectEqual(StreamState.open, stream.?.state);

    const stats = mux.getStats();
    try std.testing.expectEqual(@as(usize, 1), stats.active_streams);
}
