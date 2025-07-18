//! Ghostwire Relay - QUIC-native multiplexed relays and TURN/DERP fallback
//!
//! This module implements the relay architecture from RELAY.md including:
//! - QUIC-native multiplexed relays (preferred)
//! - TURN/DERP-style UDP relays (fallback)
//! - WebSocket/HTTP(S) proxy (stealth/last resort)
//! - Relay orchestration and management

const std = @import("std");

pub const quic_relay = @import("quic_relay.zig");
pub const turn_relay = @import("turn_relay.zig");
pub const websocket_relay = @import("websocket_relay.zig");
pub const relay_manager = @import("relay_manager.zig");

/// Relay types supported by Ghostwire
pub const RelayType = enum {
    quic_native, // QUIC-native multiplexed relay (preferred)
    turn_derp, // TURN/DERP-style UDP relay
    websocket_http, // WebSocket/HTTP(S) proxy
    masque_http3, // MASQUE/HTTP/3 tunneling (future)
};

/// Relay configuration
pub const RelayConfig = struct {
    relay_type: RelayType = .quic_native,
    bind_address: std.net.Address,
    max_connections: u32 = 1000,
    max_bandwidth_bps: u64 = 100_000_000, // 100 Mbps
    auth_required: bool = true,
    access_control: bool = true,
    metrics_enabled: bool = true,
    log_level: std.log.Level = .info,
};

/// Relay statistics
pub const RelayStats = struct {
    active_connections: u32 = 0,
    total_connections: u64 = 0,
    bytes_relayed: u64 = 0,
    packets_relayed: u64 = 0,
    bandwidth_bps: u64 = 0,
    uptime_seconds: u64 = 0,
    error_count: u64 = 0,
};

/// Relay connection info
pub const RelayConnection = struct {
    id: u64,
    client_address: std.net.Address,
    target_address: std.net.Address,
    established_time: i64,
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    last_activity: i64,

    pub fn init(client: std.net.Address, target: std.net.Address) RelayConnection {
        const now = std.time.timestamp();
        return RelayConnection{
            .id = std.crypto.random.int(u64),
            .client_address = client,
            .target_address = target,
            .established_time = now,
            .last_activity = now,
        };
    }

    pub fn updateActivity(self: *RelayConnection, bytes_in: u64, bytes_out: u64) void {
        self.bytes_in += bytes_in;
        self.bytes_out += bytes_out;
        self.last_activity = std.time.timestamp();
    }

    pub fn getDuration(self: *const RelayConnection) u64 {
        return @intCast(std.time.timestamp() - self.established_time);
    }

    pub fn isIdle(self: *const RelayConnection, timeout_seconds: u32) bool {
        const now = std.time.timestamp();
        return (now - self.last_activity) > timeout_seconds;
    }
};

/// Generic relay interface
pub const Relay = struct {
    config: RelayConfig,
    stats: RelayStats = .{},
    connections: std.HashMap(u64, RelayConnection, std.HashMap.DefaultContext(u64), std.HashMap.default_max_load_percentage),
    start_time: i64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: RelayConfig) Relay {
        return Relay{
            .config = config,
            .connections = std.HashMap(u64, RelayConnection, std.HashMap.DefaultContext(u64), std.HashMap.default_max_load_percentage).init(allocator),
            .start_time = std.time.timestamp(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Relay) void {
        self.connections.deinit();
    }

    /// Start relay server
    pub fn start(self: *Relay) !void {
        switch (self.config.relay_type) {
            .quic_native => try quic_relay.start(self.config.bind_address),
            .turn_derp => try turn_relay.start(self.config.bind_address),
            .websocket_http => try websocket_relay.start(self.config.bind_address),
            .masque_http3 => return error.NotImplemented,
        }

        std.log.info("Relay started: {} on {}", .{ self.config.relay_type, self.config.bind_address });
    }

    /// Stop relay server
    pub fn stop(self: *Relay) void {
        switch (self.config.relay_type) {
            .quic_native => quic_relay.stop(),
            .turn_derp => turn_relay.stop(),
            .websocket_http => websocket_relay.stop(),
            .masque_http3 => {},
        }

        // Close all connections
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            self.closeConnection(entry.key_ptr.*);
        }

        std.log.info("Relay stopped");
    }

    /// Accept new relay connection
    pub fn acceptConnection(self: *Relay, client: std.net.Address, target: std.net.Address) !u64 {
        if (self.connections.count() >= self.config.max_connections) {
            return error.TooManyConnections;
        }

        const connection = RelayConnection.init(client, target);
        try self.connections.put(connection.id, connection);

        self.stats.active_connections += 1;
        self.stats.total_connections += 1;

        std.log.info("Relay: New connection {} -> {} (ID: {})", .{ client, target, connection.id });
        return connection.id;
    }

    /// Close relay connection
    pub fn closeConnection(self: *Relay, connection_id: u64) void {
        if (self.connections.remove(connection_id)) {
            self.stats.active_connections -= 1;
            std.log.debug("Relay: Closed connection {}", .{connection_id});
        }
    }

    /// Relay data between client and target
    pub fn relayData(self: *Relay, connection_id: u64, data: []const u8, from_client: bool) !void {
        var connection = self.connections.getPtr(connection_id) orelse return error.ConnectionNotFound;

        // TODO: Implement actual data relaying based on relay type
        // For now, just update statistics

        if (from_client) {
            connection.updateActivity(data.len, 0);
            self.stats.bytes_relayed += data.len;
        } else {
            connection.updateActivity(0, data.len);
            self.stats.bytes_relayed += data.len;
        }

        self.stats.packets_relayed += 1;

        std.log.debug("Relay: Forwarded {} bytes for connection {}", .{ data.len, connection_id });
    }

    /// Update relay statistics
    pub fn updateStats(self: *Relay) void {
        self.stats.uptime_seconds = @intCast(std.time.timestamp() - self.start_time);

        // Calculate bandwidth (simplified)
        if (self.stats.uptime_seconds > 0) {
            self.stats.bandwidth_bps = self.stats.bytes_relayed / self.stats.uptime_seconds;
        }

        // Clean up idle connections
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isIdle(300)) { // 5 minutes timeout
                to_remove.append(entry.key_ptr.*) catch {};
            }
        }

        for (to_remove.items) |conn_id| {
            self.closeConnection(conn_id);
        }
    }

    /// Get relay statistics
    pub fn getStats(self: *const Relay) RelayStats {
        return self.stats;
    }

    /// Get connection info
    pub fn getConnection(self: *const Relay, connection_id: u64) ?RelayConnection {
        return self.connections.get(connection_id);
    }

    /// Get all active connections
    pub fn getActiveConnections(self: *const Relay, allocator: std.mem.Allocator) ![]RelayConnection {
        var connections = std.ArrayList(RelayConnection).init(allocator);

        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            try connections.append(entry.value_ptr.*);
        }

        return connections.toOwnedSlice();
    }

    /// Check relay health
    pub fn getHealth(self: *const Relay) struct {
        status: enum { healthy, degraded, unhealthy },
        load_percentage: f32,
        error_rate: f32,
        uptime_seconds: u64,
    } {
        const load = @as(f32, @floatFromInt(self.stats.active_connections)) / @as(f32, @floatFromInt(self.config.max_connections));
        const error_rate = if (self.stats.total_connections > 0)
            @as(f32, @floatFromInt(self.stats.error_count)) / @as(f32, @floatFromInt(self.stats.total_connections))
        else
            0.0;

        const status = if (error_rate > 0.1 or load > 0.9)
            .unhealthy
        else if (error_rate > 0.05 or load > 0.7)
            .degraded
        else
            .healthy;

        return .{
            .status = status,
            .load_percentage = load * 100.0,
            .error_rate = error_rate * 100.0,
            .uptime_seconds = self.stats.uptime_seconds,
        };
    }
};

/// Relay discovery and selection
pub const RelayDiscovery = struct {
    known_relays: std.ArrayList(RelayInfo),
    allocator: std.mem.Allocator,

    const RelayInfo = struct {
        address: std.net.Address,
        relay_type: RelayType,
        latency_ms: u32 = 0,
        load: f32 = 0.0,
        available: bool = true,
        last_check: i64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) RelayDiscovery {
        return RelayDiscovery{
            .known_relays = std.ArrayList(RelayInfo).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RelayDiscovery) void {
        self.known_relays.deinit();
    }

    /// Add relay to discovery list
    pub fn addRelay(self: *RelayDiscovery, address: std.net.Address, relay_type: RelayType) !void {
        const relay_info = RelayInfo{
            .address = address,
            .relay_type = relay_type,
            .last_check = std.time.timestamp(),
        };

        try self.known_relays.append(relay_info);
    }

    /// Select best relay for connection
    pub fn selectBestRelay(self: *RelayDiscovery, prefer_type: ?RelayType) ?RelayInfo {
        var best_relay: ?RelayInfo = null;
        var best_score: f32 = std.math.floatMax(f32);

        for (self.known_relays.items) |relay| {
            if (!relay.available) continue;

            // Calculate score (lower is better)
            var score: f32 = @as(f32, @floatFromInt(relay.latency_ms)) + (relay.load * 100.0);

            // Prefer specific relay type if requested
            if (prefer_type) |pref_type| {
                if (relay.relay_type == pref_type) {
                    score *= 0.5; // 50% bonus for preferred type
                }
            }

            if (score < best_score) {
                best_score = score;
                best_relay = relay;
            }
        }

        return best_relay;
    }

    /// Health check all known relays
    pub fn healthCheckRelays(self: *RelayDiscovery) !void {
        for (self.known_relays.items) |*relay| {
            // TODO: Implement actual health check
            // For now, simulate random availability
            const random_val = std.crypto.random.float(f32);
            relay.available = random_val > 0.1; // 90% availability
            relay.latency_ms = @intFromFloat(random_val * 200.0); // 0-200ms latency
            relay.load = std.crypto.random.float(f32);
            relay.last_check = std.time.timestamp();
        }
    }
};

test "relay initialization" {
    const allocator = std.testing.allocator;
    const bind_addr = try std.net.Address.parseIp4("127.0.0.1", 8080);

    const config = RelayConfig{
        .relay_type = .quic_native,
        .bind_address = bind_addr,
    };

    var relay = Relay.init(allocator, config);
    defer relay.deinit();

    try std.testing.expectEqual(RelayType.quic_native, relay.config.relay_type);
    try std.testing.expectEqual(@as(u32, 0), relay.stats.active_connections);
}

test "relay connection management" {
    const allocator = std.testing.allocator;
    const bind_addr = try std.net.Address.parseIp4("127.0.0.1", 8080);
    const config = RelayConfig{ .bind_address = bind_addr };

    var relay = Relay.init(allocator, config);
    defer relay.deinit();

    const client = try std.net.Address.parseIp4("192.168.1.100", 54321);
    const target = try std.net.Address.parseIp4("203.0.113.100", 80);

    const conn_id = try relay.acceptConnection(client, target);
    try std.testing.expect(conn_id > 0);
    try std.testing.expectEqual(@as(u32, 1), relay.stats.active_connections);

    relay.closeConnection(conn_id);
    try std.testing.expectEqual(@as(u32, 0), relay.stats.active_connections);
}

test "relay discovery" {
    const allocator = std.testing.allocator;
    var discovery = RelayDiscovery.init(allocator);
    defer discovery.deinit();

    const relay_addr = try std.net.Address.parseIp4("203.0.113.10", 8080);
    try discovery.addRelay(relay_addr, .quic_native);

    const best = discovery.selectBestRelay(.quic_native);
    try std.testing.expect(best != null);
    try std.testing.expectEqual(RelayType.quic_native, best.?.relay_type);
}
