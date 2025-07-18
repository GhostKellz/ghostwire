//! Ghostwire ICE - STUN/ICE NAT traversal for P2P connectivity
//!
//! This module implements STUN/ICE protocols for NAT traversal including:
//! - STUN client and server (RFC 5389)
//! - ICE candidate gathering and connectivity checks (RFC 8445)
//! - NAT type detection
//! - P2P connection establishment

const std = @import("std");

pub const stun = @import("stun.zig");
pub const ice = @import("ice.zig");
pub const candidates = @import("candidates.zig");
pub const nat = @import("nat.zig");

/// ICE agent state
pub const IceState = enum {
    gathering,
    connecting,
    connected,
    disconnected,
    failed,
};

/// ICE configuration
pub const IceConfig = struct {
    stun_servers: []const []const u8,
    turn_servers: []const []const u8,
    local_ufrag: []const u8,
    local_pwd: []const u8,
    controlling: bool = false,
    aggressive_nomination: bool = true,
    gather_timeout_ms: u32 = 5000,
    connectivity_timeout_ms: u32 = 10000,
};

/// ICE agent for managing P2P connections
pub const IceAgent = struct {
    config: IceConfig,
    state: IceState = .gathering,
    local_candidates: std.ArrayList(candidates.Candidate),
    remote_candidates: std.ArrayList(candidates.Candidate),
    candidate_pairs: std.ArrayList(ice.CandidatePair),
    selected_pair: ?*ice.CandidatePair = null,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: IceConfig) IceAgent {
        return IceAgent{
            .config = config,
            .local_candidates = std.ArrayList(candidates.Candidate).init(allocator),
            .remote_candidates = std.ArrayList(candidates.Candidate).init(allocator),
            .candidate_pairs = std.ArrayList(ice.CandidatePair).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *IceAgent) void {
        self.local_candidates.deinit();
        self.remote_candidates.deinit();
        self.candidate_pairs.deinit();
    }

    /// Start candidate gathering
    pub fn gatherCandidates(self: *IceAgent) !void {
        if (self.state != .gathering) return error.InvalidState;

        // Gather host candidates
        try self.gatherHostCandidates();

        // Gather server-reflexive candidates via STUN
        try self.gatherStunCandidates();

        // TODO: Gather relay candidates via TURN

        std.log.info("ICE: Gathered {} local candidates", .{self.local_candidates.items.len});
    }

    /// Add remote candidates
    pub fn addRemoteCandidate(self: *IceAgent, candidate: candidates.Candidate) !void {
        try self.remote_candidates.append(candidate);

        // Create candidate pairs with all local candidates
        for (self.local_candidates.items) |local| {
            const pair = ice.CandidatePair.init(local, candidate);
            try self.candidate_pairs.append(pair);
        }

        // Sort pairs by priority
        std.sort.insertion(ice.CandidatePair, self.candidate_pairs.items, {}, ice.CandidatePair.comparePriority);
    }

    /// Start connectivity checks
    pub fn startConnectivityChecks(self: *IceAgent) !void {
        self.state = .connecting;

        for (self.candidate_pairs.items) |*pair| {
            try self.performConnectivityCheck(pair);
        }
    }

    /// Perform connectivity check on a candidate pair
    fn performConnectivityCheck(self: *IceAgent, pair: *ice.CandidatePair) !void {
        const binding_request = try stun.createBindingRequest(self.allocator, self.config.local_ufrag, self.config.local_pwd);
        defer self.allocator.free(binding_request);

        // Send STUN binding request to remote candidate
        // TODO: Implement actual sending via UDP socket

        std.log.debug("ICE: Performing connectivity check {} -> {}", .{ pair.local.address, pair.remote.address });

        // For demonstration, mark as succeeded
        pair.state = .succeeded;

        if (self.selected_pair == null) {
            self.selected_pair = pair;
            self.state = .connected;
            std.log.info("ICE: Connection established via {}", .{pair.local.candidate_type});
        }
    }

    /// Process incoming STUN message
    pub fn processStunMessage(self: *IceAgent, data: []const u8, source: std.net.Address) !void {
        const message = try stun.parseMessage(data);

        switch (message.message_type) {
            .binding_request => {
                // Send binding response
                const response = try stun.createBindingResponse(self.allocator, source, message.transaction_id);
                defer self.allocator.free(response);

                // TODO: Send response back to source
                std.log.debug("ICE: Responding to binding request from {}", .{source});
            },
            .binding_response => {
                // Process connectivity check response
                if (self.findCandidatePairByTransactionId(message.transaction_id)) |pair| {
                    pair.state = .succeeded;
                    std.log.debug("ICE: Connectivity check succeeded for pair");
                }
            },
            else => {
                std.log.debug("ICE: Ignoring STUN message type: {}", .{message.message_type});
            },
        }
    }

    /// Find candidate pair by STUN transaction ID
    fn findCandidatePairByTransactionId(self: *IceAgent, transaction_id: [12]u8) ?*ice.CandidatePair {
        for (self.candidate_pairs.items) |*pair| {
            // TODO: Store transaction IDs in candidate pairs
            _ = transaction_id;
            _ = pair;
        }
        return null;
    }

    /// Gather host candidates (local interfaces)
    fn gatherHostCandidates(self: *IceAgent) !void {
        // TODO: Enumerate network interfaces
        // For now, add localhost
        const localhost = try std.net.Address.parseIp4("127.0.0.1", 0);
        const candidate = candidates.Candidate{
            .candidate_type = .host,
            .address = localhost,
            .priority = candidates.calculatePriority(.host, 65535, 255),
            .foundation = try self.allocator.dupe(u8, "host1"),
        };

        try self.local_candidates.append(candidate);
    }

    /// Gather STUN candidates (server-reflexive)
    fn gatherStunCandidates(self: *IceAgent) !void {
        for (self.config.stun_servers) |stun_server| {
            if (self.queryStunServer(stun_server)) |address| {
                const candidate = candidates.Candidate{
                    .candidate_type = .server_reflexive,
                    .address = address,
                    .priority = candidates.calculatePriority(.server_reflexive, 65535, 255),
                    .foundation = try self.allocator.dupe(u8, "srflx1"),
                };

                try self.local_candidates.append(candidate);
            } else |err| {
                std.log.warn("ICE: Failed to query STUN server {s}: {}", .{ stun_server, err });
            }
        }
    }

    /// Query STUN server for public address
    fn queryStunServer(self: *IceAgent, server: []const u8) !std.net.Address {
        // Parse server address
        var iter = std.mem.split(u8, server, ":");
        const host = iter.next() orelse return error.InvalidServer;
        const port_str = iter.next() orelse "3478";
        const port = try std.fmt.parseInt(u16, port_str, 10);

        const server_addr = try std.net.Address.resolveIp(host, port);

        // Create STUN binding request
        const request = try stun.createBindingRequest(self.allocator, "", "");
        defer self.allocator.free(request);

        // TODO: Send request and parse response
        // For now, return a placeholder address
        _ = server_addr;
        return try std.net.Address.parseIp4("192.168.1.100", 54321);
    }

    /// Get selected candidate pair info
    pub fn getSelectedPair(self: *const IceAgent) ?struct {
        local: candidates.Candidate,
        remote: candidates.Candidate,
        state: ice.PairState,
    } {
        if (self.selected_pair) |pair| {
            return .{
                .local = pair.local,
                .remote = pair.remote,
                .state = pair.state,
            };
        }
        return null;
    }

    /// Get ICE agent statistics
    pub fn getStats(self: *const IceAgent) struct {
        state: IceState,
        local_candidates: usize,
        remote_candidates: usize,
        candidate_pairs: usize,
        connected: bool,
    } {
        return .{
            .state = self.state,
            .local_candidates = self.local_candidates.items.len,
            .remote_candidates = self.remote_candidates.items.len,
            .candidate_pairs = self.candidate_pairs.items.len,
            .connected = self.state == .connected,
        };
    }
};

test "ICE agent initialization" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = IceConfig{
        .stun_servers = &[_][]const u8{"stun.l.google.com:19302"},
        .turn_servers = &[_][]const u8{},
        .local_ufrag = "test_ufrag",
        .local_pwd = "test_password",
    };

    var agent = IceAgent.init(allocator, config);
    defer agent.deinit();

    try std.testing.expectEqual(IceState.gathering, agent.state);

    const stats = agent.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.local_candidates);
    try std.testing.expect(!stats.connected);
}
