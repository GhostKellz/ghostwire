//! NAT type detection and handling utilities
//!
//! Implements NAT type detection using STUN protocol

const std = @import("std");
const stun = @import("stun.zig");

/// NAT types according to RFC 3489 and RFC 5389
pub const NatType = enum {
    open_internet, // No NAT or firewall
    full_cone, // Full Cone NAT
    restricted_cone, // Address-Restricted Cone NAT
    port_restricted, // Port-Restricted Cone NAT
    symmetric, // Symmetric NAT
    blocked, // UDP blocked
    unknown, // Could not determine

    /// Get NAT traversal difficulty
    pub fn getDifficulty(self: NatType) enum { easy, medium, hard, impossible } {
        return switch (self) {
            .open_internet => .easy,
            .full_cone => .easy,
            .restricted_cone => .medium,
            .port_restricted => .medium,
            .symmetric => .hard,
            .blocked => .impossible,
            .unknown => .hard,
        };
    }

    /// Check if P2P connection is likely possible
    pub fn canDirectConnect(self: NatType, peer_type: NatType) bool {
        return switch (self) {
            .open_internet => true,
            .full_cone => peer_type != .blocked,
            .restricted_cone, .port_restricted => peer_type == .open_internet or peer_type == .full_cone,
            .symmetric => peer_type == .open_internet,
            .blocked => false,
            .unknown => false,
        };
    }
};

/// NAT detection result
pub const NatDetectionResult = struct {
    nat_type: NatType,
    public_address: ?std.net.Address = null,
    local_address: ?std.net.Address = null,
    supports_hairpin: bool = false,
    external_port_prediction: bool = false,
    detection_time_ms: u32 = 0,
};

/// NAT detector using STUN protocol
pub const NatDetector = struct {
    stun_servers: []const []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, stun_servers: []const []const u8) NatDetector {
        return NatDetector{
            .stun_servers = stun_servers,
            .allocator = allocator,
        };
    }

    /// Perform NAT type detection
    pub fn detectNatType(self: *NatDetector) !NatDetectionResult {
        const start_time = std.time.milliTimestamp();

        // Step 1: Try to get mapped address from primary STUN server
        const test1_result = try self.performTest1();
        if (test1_result.failed) {
            return NatDetectionResult{
                .nat_type = .blocked,
                .detection_time_ms = @intCast(std.time.milliTimestamp() - start_time),
            };
        }

        const mapped_addr = test1_result.mapped_address.?;
        const local_addr = test1_result.local_address.?;

        // Check if we're behind NAT
        if (self.addressesEqual(mapped_addr, local_addr)) {
            return NatDetectionResult{
                .nat_type = .open_internet,
                .public_address = mapped_addr,
                .local_address = local_addr,
                .detection_time_ms = @intCast(std.time.milliTimestamp() - start_time),
            };
        }

        // Step 2: Try different server/port to detect cone vs symmetric
        const test2_result = try self.performTest2(local_addr);

        var nat_type: NatType = .unknown;

        if (test2_result.same_external_address) {
            // Cone NAT - determine which type
            const test3_result = try self.performTest3(mapped_addr);

            if (test3_result.received_response) {
                nat_type = .full_cone;
            } else {
                // Need to distinguish between restricted cone and port restricted
                const test4_result = try self.performTest4(mapped_addr);

                if (test4_result.received_response) {
                    nat_type = .restricted_cone;
                } else {
                    nat_type = .port_restricted;
                }
            }
        } else {
            // Different external addresses = Symmetric NAT
            nat_type = .symmetric;
        }

        return NatDetectionResult{
            .nat_type = nat_type,
            .public_address = mapped_addr,
            .local_address = local_addr,
            .supports_hairpin = false, // TODO: Implement hairpin detection
            .external_port_prediction = nat_type == .symmetric,
            .detection_time_ms = @intCast(std.time.milliTimestamp() - start_time),
        };
    }

    /// Test 1: Basic STUN query to get mapped address
    fn performTest1(self: *NatDetector) !struct {
        failed: bool,
        mapped_address: ?std.net.Address,
        local_address: ?std.net.Address,
    } {
        if (self.stun_servers.len == 0) {
            return .{ .failed = true, .mapped_address = null, .local_address = null };
        }

        const server = self.stun_servers[0];

        // TODO: Implement actual STUN query
        // For now, simulate a successful response
        const local_addr = try std.net.Address.parseIp4("192.168.1.100", 54321);
        const mapped_addr = try std.net.Address.parseIp4("203.0.113.100", 54321);

        std.log.debug("NAT: Test1 - Local: {}, Mapped: {}", .{ local_addr, mapped_addr });

        _ = server;
        return .{
            .failed = false,
            .mapped_address = mapped_addr,
            .local_address = local_addr,
        };
    }

    /// Test 2: Query different server to check for symmetric NAT
    fn performTest2(self: *NatDetector, local_addr: std.net.Address) !struct {
        same_external_address: bool,
    } {
        if (self.stun_servers.len < 2) {
            // Can't perform test without second server
            return .{ .same_external_address = true };
        }

        const server = self.stun_servers[1];

        // TODO: Implement actual STUN query to different server
        // For now, simulate cone NAT behavior (same external address)

        std.log.debug("NAT: Test2 - Using server: {s}, Local: {}", .{ server, local_addr });

        return .{ .same_external_address = true };
    }

    /// Test 3: Request response from different IP (changed IP and port)
    fn performTest3(self: *NatDetector, mapped_addr: std.net.Address) !struct {
        received_response: bool,
    } {
        // TODO: Implement STUN request with CHANGE-REQUEST attribute
        // For simulation, assume restricted NAT (no response)

        std.log.debug("NAT: Test3 - Testing full cone with mapped: {}", .{mapped_addr});

        return .{ .received_response = false };
    }

    /// Test 4: Request response from same IP, different port
    fn performTest4(self: *NatDetector, mapped_addr: std.net.Address) !struct {
        received_response: bool,
    } {
        // TODO: Implement STUN request with CHANGE-REQUEST (port only)
        // For simulation, assume port-restricted behavior

        std.log.debug("NAT: Test4 - Testing restricted cone with mapped: {}", .{mapped_addr});

        return .{ .received_response = false };
    }

    /// Compare if two addresses are equal
    fn addressesEqual(self: *NatDetector, addr1: std.net.Address, addr2: std.net.Address) bool {
        _ = self;
        return addr1.eql(addr2);
    }

    /// Get recommended strategy for NAT traversal
    pub fn getTraversalStrategy(nat_type: NatType) struct {
        use_stun: bool,
        use_turn: bool,
        try_upnp: bool,
        hole_punching: bool,
    } {
        return switch (nat_type) {
            .open_internet => .{
                .use_stun = false,
                .use_turn = false,
                .try_upnp = false,
                .hole_punching = false,
            },
            .full_cone => .{
                .use_stun = true,
                .use_turn = false,
                .try_upnp = true,
                .hole_punching = true,
            },
            .restricted_cone, .port_restricted => .{
                .use_stun = true,
                .use_turn = true,
                .try_upnp = true,
                .hole_punching = true,
            },
            .symmetric => .{
                .use_stun = true,
                .use_turn = true,
                .try_upnp = false,
                .hole_punching = false,
            },
            .blocked => .{
                .use_stun = false,
                .use_turn = true,
                .try_upnp = false,
                .hole_punching = false,
            },
            .unknown => .{
                .use_stun = true,
                .use_turn = true,
                .try_upnp = true,
                .hole_punching = true,
            },
        };
    }
};

/// NAT behavior analyzer for ongoing connections
pub const NatBehaviorAnalyzer = struct {
    external_addresses: std.ArrayList(std.net.Address),
    port_predictions: std.ArrayList(u16),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) NatBehaviorAnalyzer {
        return NatBehaviorAnalyzer{
            .external_addresses = std.ArrayList(std.net.Address).init(allocator),
            .port_predictions = std.ArrayList(u16).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NatBehaviorAnalyzer) void {
        self.external_addresses.deinit();
        self.port_predictions.deinit();
    }

    /// Record observed external address
    pub fn recordExternalAddress(self: *NatBehaviorAnalyzer, address: std.net.Address) !void {
        try self.external_addresses.append(address);
    }

    /// Analyze port allocation pattern
    pub fn analyzePortPattern(self: *NatBehaviorAnalyzer) struct {
        is_sequential: bool,
        increment: i32,
        predictable: bool,
    } {
        if (self.external_addresses.items.len < 3) {
            return .{ .is_sequential = false, .increment = 0, .predictable = false };
        }

        const ports = self.external_addresses.items;
        var increments = std.ArrayList(i32).init(self.allocator);
        defer increments.deinit();

        for (1..ports.len) |i| {
            const prev_port = @as(i32, ports[i - 1].getPort());
            const curr_port = @as(i32, ports[i].getPort());
            increments.append(curr_port - prev_port) catch {};
        }

        // Check if increments are consistent
        if (increments.items.len > 0) {
            const first_increment = increments.items[0];
            var is_sequential = true;

            for (increments.items) |inc| {
                if (inc != first_increment) {
                    is_sequential = false;
                    break;
                }
            }

            return .{
                .is_sequential = is_sequential,
                .increment = first_increment,
                .predictable = is_sequential and @abs(first_increment) <= 10,
            };
        }

        return .{ .is_sequential = false, .increment = 0, .predictable = false };
    }

    /// Predict next external port
    pub fn predictNextPort(self: *NatBehaviorAnalyzer) ?u16 {
        const pattern = self.analyzePortPattern();

        if (pattern.predictable and self.external_addresses.items.len > 0) {
            const last_port = @as(i32, self.external_addresses.items[self.external_addresses.items.len - 1].getPort());
            const predicted = last_port + pattern.increment;

            if (predicted > 0 and predicted <= 65535) {
                return @intCast(predicted);
            }
        }

        return null;
    }
};

test "NAT type detection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stun_servers = [_][]const u8{ "stun.l.google.com:19302", "stun1.l.google.com:19302" };
    var detector = NatDetector.init(allocator, &stun_servers);

    const result = try detector.detectNatType();

    try std.testing.expect(result.nat_type != .unknown);
    try std.testing.expect(result.detection_time_ms > 0);
}

test "NAT traversal strategy" {
    const strategy = NatDetector.getTraversalStrategy(.symmetric);

    try std.testing.expect(strategy.use_stun);
    try std.testing.expect(strategy.use_turn);
    try std.testing.expect(!strategy.hole_punching);
}

test "NAT behavior analysis" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var analyzer = NatBehaviorAnalyzer.init(allocator);
    defer analyzer.deinit();

    // Simulate sequential port allocation
    try analyzer.recordExternalAddress(try std.net.Address.parseIp4("203.0.113.100", 50000));
    try analyzer.recordExternalAddress(try std.net.Address.parseIp4("203.0.113.100", 50001));
    try analyzer.recordExternalAddress(try std.net.Address.parseIp4("203.0.113.100", 50002));

    const pattern = analyzer.analyzePortPattern();
    try std.testing.expect(pattern.is_sequential);
    try std.testing.expectEqual(@as(i32, 1), pattern.increment);

    const predicted = analyzer.predictNextPort();
    try std.testing.expectEqual(@as(u16, 50003), predicted.?);
}
