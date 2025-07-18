//! ICE candidate management and connectivity checks
//!
//! Implements ICE candidate pairs and connectivity checking logic

const std = @import("std");
const candidates = @import("candidates.zig");

/// ICE candidate pair state
pub const PairState = enum {
    waiting,
    in_progress,
    succeeded,
    failed,
    frozen,
};

/// ICE candidate pair
pub const CandidatePair = struct {
    local: candidates.Candidate,
    remote: candidates.Candidate,
    state: PairState = .waiting,
    priority: u64,
    nominated: bool = false,
    valid: bool = false,

    pub fn init(local: candidates.Candidate, remote: candidates.Candidate) CandidatePair {
        const priority = calculatePairPriority(local.priority, remote.priority);

        return CandidatePair{
            .local = local,
            .remote = remote,
            .priority = priority,
        };
    }

    /// Calculate pair priority according to ICE specification
    fn calculatePairPriority(local_priority: u32, remote_priority: u32) u64 {
        const controlling_priority = @max(local_priority, remote_priority);
        const controlled_priority = @min(local_priority, remote_priority);

        return (@as(u64, controlling_priority) << 32) | controlled_priority;
    }

    /// Compare pairs by priority for sorting
    pub fn comparePriority(_: void, a: CandidatePair, b: CandidatePair) bool {
        return a.priority > b.priority;
    }

    /// Check if pair can be used for connectivity check
    pub fn canCheck(self: *const CandidatePair) bool {
        return self.state == .waiting or self.state == .failed;
    }

    /// Mark pair as nominated
    pub fn nominate(self: *CandidatePair) void {
        if (self.state == .succeeded) {
            self.nominated = true;
        }
    }

    /// Get pair description for logging
    pub fn getDescription(self: *const CandidatePair, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{} -> {s}:{} ({})", .{
            @tagName(self.local.candidate_type),
            self.local.address.getPort(),
            @tagName(self.remote.candidate_type),
            self.remote.address.getPort(),
            @tagName(self.state),
        });
    }
};

/// ICE checklist for managing connectivity checks
pub const Checklist = struct {
    pairs: std.ArrayList(CandidatePair),
    state: enum { running, completed, failed } = .running,
    nominated_pair: ?*CandidatePair = null,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Checklist {
        return Checklist{
            .pairs = std.ArrayList(CandidatePair).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Checklist) void {
        self.pairs.deinit();
    }

    /// Add candidate pair to checklist
    pub fn addPair(self: *Checklist, pair: CandidatePair) !void {
        try self.pairs.append(pair);
        self.sortPairs();
    }

    /// Sort pairs by priority
    fn sortPairs(self: *Checklist) void {
        std.sort.insertion(CandidatePair, self.pairs.items, {}, CandidatePair.comparePriority);
    }

    /// Get next pair to check
    pub fn getNextPair(self: *Checklist) ?*CandidatePair {
        for (self.pairs.items) |*pair| {
            if (pair.canCheck()) {
                return pair;
            }
        }
        return null;
    }

    /// Update pair state after connectivity check
    pub fn updatePairState(self: *Checklist, pair: *CandidatePair, new_state: PairState) void {
        pair.state = new_state;

        if (new_state == .succeeded) {
            pair.valid = true;

            // Check if this is the first valid pair (becomes nominated)
            if (self.nominated_pair == null) {
                pair.nominate();
                self.nominated_pair = pair;
                self.state = .completed;
            }
        }

        // Check if all pairs have been checked
        if (self.allPairsChecked()) {
            if (self.nominated_pair != null) {
                self.state = .completed;
            } else {
                self.state = .failed;
            }
        }
    }

    /// Check if all pairs have been processed
    fn allPairsChecked(self: *const Checklist) bool {
        for (self.pairs.items) |pair| {
            if (pair.state == .waiting or pair.state == .in_progress) {
                return false;
            }
        }
        return true;
    }

    /// Get statistics
    pub fn getStats(self: *const Checklist) struct {
        total_pairs: usize,
        waiting: usize,
        in_progress: usize,
        succeeded: usize,
        failed: usize,
        nominated: bool,
    } {
        var stats = .{
            .total_pairs = self.pairs.items.len,
            .waiting = @as(usize, 0),
            .in_progress = @as(usize, 0),
            .succeeded = @as(usize, 0),
            .failed = @as(usize, 0),
            .nominated = self.nominated_pair != null,
        };

        for (self.pairs.items) |pair| {
            switch (pair.state) {
                .waiting => stats.waiting += 1,
                .in_progress => stats.in_progress += 1,
                .succeeded => stats.succeeded += 1,
                .failed => stats.failed += 1,
                .frozen => {},
            }
        }

        return stats;
    }

    /// Get best pair (nominated or highest priority valid)
    pub fn getBestPair(self: *const Checklist) ?*const CandidatePair {
        if (self.nominated_pair) |pair| {
            return pair;
        }

        // Find highest priority valid pair
        for (self.pairs.items) |*pair| {
            if (pair.valid) {
                return pair;
            }
        }

        return null;
    }
};

/// Connectivity check manager
pub const ConnectivityChecker = struct {
    checklist: Checklist,
    check_interval_ms: u32 = 50, // 20 checks per second
    last_check_time: i64 = 0,

    pub fn init(allocator: std.mem.Allocator) ConnectivityChecker {
        return ConnectivityChecker{
            .checklist = Checklist.init(allocator),
        };
    }

    pub fn deinit(self: *ConnectivityChecker) void {
        self.checklist.deinit();
    }

    /// Add candidate pair for checking
    pub fn addPair(self: *ConnectivityChecker, pair: CandidatePair) !void {
        try self.checklist.addPair(pair);
    }

    /// Perform periodic connectivity checks
    pub fn performChecks(self: *ConnectivityChecker) !bool {
        const now = std.time.milliTimestamp();

        if (now - self.last_check_time < self.check_interval_ms) {
            return false; // Not time for next check yet
        }

        if (self.checklist.getNextPair()) |pair| {
            pair.state = .in_progress;

            // Simulate connectivity check
            // In real implementation, this would send STUN binding request
            const success = self.simulateConnectivityCheck(pair);

            if (success) {
                self.checklist.updatePairState(pair, .succeeded);
            } else {
                self.checklist.updatePairState(pair, .failed);
            }

            self.last_check_time = now;
            return true;
        }

        return false; // No more pairs to check
    }

    /// Simulate connectivity check (placeholder)
    fn simulateConnectivityCheck(self: *ConnectivityChecker, pair: *CandidatePair) bool {
        _ = self;

        // Simulate success for host and server-reflexive candidates
        return pair.local.candidate_type == .host or
            pair.local.candidate_type == .server_reflexive or
            pair.remote.candidate_type == .host or
            pair.remote.candidate_type == .server_reflexive;
    }

    /// Check if connectivity checks are complete
    pub fn isComplete(self: *const ConnectivityChecker) bool {
        return self.checklist.state == .completed or self.checklist.state == .failed;
    }

    /// Get selected pair
    pub fn getSelectedPair(self: *const ConnectivityChecker) ?*const CandidatePair {
        return self.checklist.getBestPair();
    }

    /// Get checker statistics
    pub fn getStats(self: *const ConnectivityChecker) struct {
        checklist_state: @TypeOf(self.checklist.state),
        pairs: @TypeOf(self.checklist.getStats()),
    } {
        return .{
            .checklist_state = self.checklist.state,
            .pairs = self.checklist.getStats(),
        };
    }
};

test "candidate pair priority calculation" {
    const local = candidates.Candidate{
        .candidate_type = .host,
        .address = try std.net.Address.parseIp4("192.168.1.100", 54321),
        .priority = 2113667326,
        .foundation = "host1",
    };

    const remote = candidates.Candidate{
        .candidate_type = .server_reflexive,
        .address = try std.net.Address.parseIp4("203.0.113.100", 54321),
        .priority = 1694498815,
        .foundation = "srflx1",
    };

    const pair = CandidatePair.init(local, remote);
    try std.testing.expect(pair.priority > 0);
    try std.testing.expectEqual(PairState.waiting, pair.state);
}

test "connectivity checker" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var checker = ConnectivityChecker.init(allocator);
    defer checker.deinit();

    const local = candidates.Candidate{
        .candidate_type = .host,
        .address = try std.net.Address.parseIp4("192.168.1.100", 54321),
        .priority = 2113667326,
        .foundation = "host1",
    };

    const remote = candidates.Candidate{
        .candidate_type = .host,
        .address = try std.net.Address.parseIp4("192.168.1.200", 54321),
        .priority = 2113667326,
        .foundation = "host2",
    };

    const pair = CandidatePair.init(local, remote);
    try checker.addPair(pair);

    // Perform connectivity check
    const performed_check = try checker.performChecks();
    try std.testing.expect(performed_check);

    const stats = checker.getStats();
    try std.testing.expect(stats.pairs.total_pairs > 0);
}
