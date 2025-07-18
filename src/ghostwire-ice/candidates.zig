//! ICE candidate types and management
//!
//! Defines candidate types and priority calculation according to ICE spec

const std = @import("std");

/// ICE candidate types
pub const CandidateType = enum {
    host,
    server_reflexive,
    peer_reflexive,
    relay,

    /// Get type preference for priority calculation
    pub fn getTypePreference(self: CandidateType) u8 {
        return switch (self) {
            .host => 126,
            .peer_reflexive => 110,
            .server_reflexive => 100,
            .relay => 0,
        };
    }
};

/// ICE candidate
pub const Candidate = struct {
    candidate_type: CandidateType,
    address: std.net.Address,
    priority: u32,
    foundation: []const u8,
    component_id: u8 = 1,
    transport: enum { udp, tcp } = .udp,

    /// Create host candidate
    pub fn createHost(allocator: std.mem.Allocator, address: std.net.Address, component_id: u8) !Candidate {
        const priority = calculatePriority(.host, 65535, component_id);
        const foundation = try std.fmt.allocPrint(allocator, "host{}", .{address.getPort()});

        return Candidate{
            .candidate_type = .host,
            .address = address,
            .priority = priority,
            .foundation = foundation,
            .component_id = component_id,
        };
    }

    /// Create server-reflexive candidate
    pub fn createServerReflexive(allocator: std.mem.Allocator, address: std.net.Address, base_address: std.net.Address, component_id: u8) !Candidate {
        const priority = calculatePriority(.server_reflexive, 65535, component_id);
        const foundation = try std.fmt.allocPrint(allocator, "srflx{}", .{base_address.getPort()});

        return Candidate{
            .candidate_type = .server_reflexive,
            .address = address,
            .priority = priority,
            .foundation = foundation,
            .component_id = component_id,
        };
    }

    /// Create relay candidate
    pub fn createRelay(allocator: std.mem.Allocator, address: std.net.Address, relay_address: std.net.Address, component_id: u8) !Candidate {
        const priority = calculatePriority(.relay, 65535, component_id);
        const foundation = try std.fmt.allocPrint(allocator, "relay{}", .{relay_address.getPort()});

        return Candidate{
            .candidate_type = .relay,
            .address = address,
            .priority = priority,
            .foundation = foundation,
            .component_id = component_id,
        };
    }

    /// Free allocated foundation string
    pub fn deinit(self: *Candidate, allocator: std.mem.Allocator) void {
        allocator.free(self.foundation);
    }

    /// Get candidate description for SDP
    pub fn getSdpString(self: *const Candidate, allocator: std.mem.Allocator) ![]u8 {
        const type_str = switch (self.candidate_type) {
            .host => "host",
            .server_reflexive => "srflx",
            .peer_reflexive => "prflx",
            .relay => "relay",
        };

        const ip = try self.address.getIpString(allocator);
        defer allocator.free(ip);

        return std.fmt.allocPrint(allocator, "candidate:{s} {} {} UDP {} {s} {} typ {s}", .{
            self.foundation,
            self.component_id,
            self.priority,
            self.priority, // TODO: Use actual transport priority
            ip,
            self.address.getPort(),
            type_str,
        });
    }

    /// Parse candidate from SDP string
    pub fn fromSdpString(allocator: std.mem.Allocator, sdp: []const u8) !Candidate {
        // Simplified SDP parsing - real implementation would be more robust
        var iter = std.mem.split(u8, sdp, " ");

        _ = iter.next() orelse return error.InvalidSdp; // Skip "candidate:"
        const foundation = iter.next() orelse return error.InvalidSdp;
        const component_str = iter.next() orelse return error.InvalidSdp;
        _ = iter.next() orelse return error.InvalidSdp; // Skip transport
        const priority_str = iter.next() orelse return error.InvalidSdp;
        const ip_str = iter.next() orelse return error.InvalidSdp;
        const port_str = iter.next() orelse return error.InvalidSdp;
        _ = iter.next() orelse return error.InvalidSdp; // Skip "typ"
        const type_str = iter.next() orelse return error.InvalidSdp;

        const component_id = try std.fmt.parseInt(u8, component_str, 10);
        const priority = try std.fmt.parseInt(u32, priority_str, 10);
        const port = try std.fmt.parseInt(u16, port_str, 10);

        const candidate_type: CandidateType = if (std.mem.eql(u8, type_str, "host"))
            .host
        else if (std.mem.eql(u8, type_str, "srflx"))
            .server_reflexive
        else if (std.mem.eql(u8, type_str, "prflx"))
            .peer_reflexive
        else if (std.mem.eql(u8, type_str, "relay"))
            .relay
        else
            return error.InvalidCandidateType;

        const address = try std.net.Address.resolveIp(ip_str, port);
        const foundation_copy = try allocator.dupe(u8, foundation);

        return Candidate{
            .candidate_type = candidate_type,
            .address = address,
            .priority = priority,
            .foundation = foundation_copy,
            .component_id = component_id,
        };
    }
};

/// Calculate candidate priority according to ICE specification
/// priority = (2^24) * type_preference + (2^8) * local_preference + component_id
pub fn calculatePriority(candidate_type: CandidateType, local_preference: u16, component_id: u8) u32 {
    const type_preference = candidate_type.getTypePreference();

    return (@as(u32, type_preference) << 24) +
        (@as(u32, local_preference) << 8) +
        @as(u32, component_id);
}

/// Candidate gathering utility
pub const CandidateGatherer = struct {
    candidates: std.ArrayList(Candidate),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) CandidateGatherer {
        return CandidateGatherer{
            .candidates = std.ArrayList(Candidate).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *CandidateGatherer) void {
        for (self.candidates.items) |*candidate| {
            candidate.deinit(self.allocator);
        }
        self.candidates.deinit();
    }

    /// Gather host candidates from local interfaces
    pub fn gatherHostCandidates(self: *CandidateGatherer) !void {
        // TODO: Enumerate actual network interfaces
        // For now, add common local addresses
        const addresses = [_][]const u8{
            "127.0.0.1",
            "192.168.1.100", // Common private IP
            "10.0.0.100", // Another common private IP
        };

        for (addresses) |addr_str| {
            if (std.net.Address.resolveIp(addr_str, 0)) |address| {
                const candidate = try Candidate.createHost(self.allocator, address, 1);
                try self.candidates.append(candidate);
            } else |_| {
                // Skip invalid addresses
            }
        }
    }

    /// Add server-reflexive candidate from STUN discovery
    pub fn addServerReflexiveCandidate(self: *CandidateGatherer, public_address: std.net.Address, local_address: std.net.Address) !void {
        const candidate = try Candidate.createServerReflexive(self.allocator, public_address, local_address, 1);
        try self.candidates.append(candidate);
    }

    /// Add relay candidate from TURN allocation
    pub fn addRelayCandidate(self: *CandidateGatherer, relay_address: std.net.Address, turn_server: std.net.Address) !void {
        const candidate = try Candidate.createRelay(self.allocator, relay_address, turn_server, 1);
        try self.candidates.append(candidate);
    }

    /// Get all gathered candidates
    pub fn getCandidates(self: *const CandidateGatherer) []const Candidate {
        return self.candidates.items;
    }

    /// Sort candidates by priority
    pub fn sortByPriority(self: *CandidateGatherer) void {
        std.sort.insertion(Candidate, self.candidates.items, {}, compareCandidatePriority);
    }

    /// Get candidates by type
    pub fn getCandidatesByType(self: *const CandidateGatherer, candidate_type: CandidateType, allocator: std.mem.Allocator) ![]Candidate {
        var filtered = std.ArrayList(Candidate).init(allocator);

        for (self.candidates.items) |candidate| {
            if (candidate.candidate_type == candidate_type) {
                try filtered.append(candidate);
            }
        }

        return filtered.toOwnedSlice();
    }

    /// Get statistics
    pub fn getStats(self: *const CandidateGatherer) struct {
        total: usize,
        host: usize,
        server_reflexive: usize,
        peer_reflexive: usize,
        relay: usize,
    } {
        var stats = .{
            .total = self.candidates.items.len,
            .host = @as(usize, 0),
            .server_reflexive = @as(usize, 0),
            .peer_reflexive = @as(usize, 0),
            .relay = @as(usize, 0),
        };

        for (self.candidates.items) |candidate| {
            switch (candidate.candidate_type) {
                .host => stats.host += 1,
                .server_reflexive => stats.server_reflexive += 1,
                .peer_reflexive => stats.peer_reflexive += 1,
                .relay => stats.relay += 1,
            }
        }

        return stats;
    }
};

/// Compare candidates by priority for sorting
fn compareCandidatePriority(_: void, a: Candidate, b: Candidate) bool {
    return a.priority > b.priority;
}

test "candidate priority calculation" {
    const priority = calculatePriority(.host, 65535, 1);
    try std.testing.expect(priority > 0);

    const host_priority = calculatePriority(.host, 65535, 1);
    const srflx_priority = calculatePriority(.server_reflexive, 65535, 1);

    try std.testing.expect(host_priority > srflx_priority);
}

test "candidate creation and SDP" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const address = try std.net.Address.parseIp4("192.168.1.100", 54321);
    var candidate = try Candidate.createHost(allocator, address, 1);
    defer candidate.deinit(allocator);

    try std.testing.expectEqual(CandidateType.host, candidate.candidate_type);
    try std.testing.expect(candidate.priority > 0);

    const sdp = try candidate.getSdpString(allocator);
    defer allocator.free(sdp);

    try std.testing.expect(std.mem.indexOf(u8, sdp, "host") != null);
}

test "candidate gatherer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var gatherer = CandidateGatherer.init(allocator);
    defer gatherer.deinit();

    try gatherer.gatherHostCandidates();

    const stats = gatherer.getStats();
    try std.testing.expect(stats.total > 0);
    try std.testing.expect(stats.host > 0);
}
