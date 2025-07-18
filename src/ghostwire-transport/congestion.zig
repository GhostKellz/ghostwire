//! Congestion control for Ghostwire transport
//!
//! Implements congestion control algorithms for reliable packet delivery

const std = @import("std");

/// Congestion control algorithm types
pub const Algorithm = enum {
    none,
    cubic,
    bbr,
    new_reno,
};

/// Congestion control state
pub const CongestionControl = struct {
    algorithm: Algorithm = .cubic,
    window_size: u32 = 10, // Initial window size in packets
    ssthresh: u32 = 65535, // Slow start threshold
    rtt_min: u32 = std.math.maxInt(u32),
    rtt_smoothed: u32 = 0,
    rtt_var: u32 = 0,
    bytes_in_flight: u32 = 0,
    packet_count: u64 = 0,
    loss_count: u64 = 0,

    /// Initialize congestion control
    pub fn init(algorithm: Algorithm) CongestionControl {
        return CongestionControl{
            .algorithm = algorithm,
        };
    }

    /// Check if we can send more data
    pub fn canSend(self: *const CongestionControl, packet_size: u32) bool {
        return self.bytes_in_flight + packet_size <= self.window_size * 1400; // Assume 1400 byte packets
    }

    /// Record packet sent
    pub fn onPacketSent(self: *CongestionControl, packet_size: u32) void {
        self.bytes_in_flight += packet_size;
        self.packet_count += 1;
    }

    /// Record packet acknowledged
    pub fn onPacketAcked(self: *CongestionControl, packet_size: u32, rtt: u32) void {
        self.bytes_in_flight = if (self.bytes_in_flight >= packet_size)
            self.bytes_in_flight - packet_size
        else
            0;

        self.updateRTT(rtt);

        switch (self.algorithm) {
            .none => {},
            .cubic => self.cubicOnAck(),
            .bbr => self.bbrOnAck(),
            .new_reno => self.newRenoOnAck(packet_size),
        }
    }

    /// Record packet loss
    pub fn onPacketLost(self: *CongestionControl, packet_size: u32) void {
        self.bytes_in_flight = if (self.bytes_in_flight >= packet_size)
            self.bytes_in_flight - packet_size
        else
            0;
        self.loss_count += 1;

        switch (self.algorithm) {
            .none => {},
            .cubic => self.cubicOnLoss(),
            .bbr => self.bbrOnLoss(),
            .new_reno => self.newRenoOnLoss(),
        }
    }

    /// Update RTT measurements
    fn updateRTT(self: *CongestionControl, rtt: u32) void {
        if (rtt < self.rtt_min) {
            self.rtt_min = rtt;
        }

        if (self.rtt_smoothed == 0) {
            self.rtt_smoothed = rtt;
            self.rtt_var = rtt / 2;
        } else {
            const diff = if (rtt > self.rtt_smoothed)
                rtt - self.rtt_smoothed
            else
                self.rtt_smoothed - rtt;
            self.rtt_var = (3 * self.rtt_var + diff) / 4;
            self.rtt_smoothed = (7 * self.rtt_smoothed + rtt) / 8;
        }
    }

    /// CUBIC congestion control - on ACK
    fn cubicOnAck(self: *CongestionControl) void {
        if (self.window_size < self.ssthresh) {
            // Slow start
            self.window_size += 1;
        } else {
            // Congestion avoidance - simplified CUBIC
            self.window_size += 1; // TODO: Implement proper CUBIC algorithm
        }
    }

    /// CUBIC congestion control - on loss
    fn cubicOnLoss(self: *CongestionControl) void {
        self.ssthresh = @max(self.window_size / 2, 2);
        self.window_size = self.ssthresh;
    }

    /// BBR congestion control - on ACK
    fn bbrOnAck(self: *CongestionControl) void {
        // TODO: Implement BBR algorithm
        // BBR uses bandwidth and RTT measurements to set the window
        self.window_size = @min(self.window_size + 1, 1000);
    }

    /// BBR congestion control - on loss
    fn bbrOnLoss(self: *CongestionControl) void {
        // TODO: Implement BBR loss handling
        self.window_size = @max(self.window_size * 3 / 4, 2);
    }

    /// New Reno congestion control - on ACK
    fn newRenoOnAck(self: *CongestionControl, packet_size: u32) void {
        if (self.window_size < self.ssthresh) {
            // Slow start
            self.window_size += 1;
        } else {
            // Congestion avoidance
            const increment = @max(packet_size / self.window_size, 1);
            self.window_size += increment;
        }
    }

    /// New Reno congestion control - on loss
    fn newRenoOnLoss(self: *CongestionControl) void {
        self.ssthresh = @max(self.window_size / 2, 2);
        self.window_size = 1; // Back to slow start
    }

    /// Get current congestion window in bytes
    pub fn getWindowBytes(self: *const CongestionControl) u32 {
        return self.window_size * 1400; // Assume 1400 byte packets
    }

    /// Get loss rate
    pub fn getLossRate(self: *const CongestionControl) f32 {
        if (self.packet_count == 0) return 0.0;
        return @as(f32, @floatFromInt(self.loss_count)) / @as(f32, @floatFromInt(self.packet_count));
    }

    /// Get statistics
    pub fn getStats(self: *const CongestionControl) struct {
        window_size: u32,
        bytes_in_flight: u32,
        rtt_smoothed: u32,
        loss_rate: f32,
    } {
        return .{
            .window_size = self.window_size,
            .bytes_in_flight = self.bytes_in_flight,
            .rtt_smoothed = self.rtt_smoothed,
            .loss_rate = self.getLossRate(),
        };
    }
};

test "congestion control basic operations" {
    var cc = CongestionControl.init(.cubic);

    try std.testing.expect(cc.canSend(1400));

    cc.onPacketSent(1400);
    try std.testing.expectEqual(@as(u32, 1400), cc.bytes_in_flight);

    cc.onPacketAcked(1400, 50);
    try std.testing.expectEqual(@as(u32, 0), cc.bytes_in_flight);
    try std.testing.expectEqual(@as(u32, 50), cc.rtt_smoothed);
}

test "congestion control loss handling" {
    var cc = CongestionControl.init(.new_reno);
    const initial_window = cc.window_size;

    cc.onPacketLost(1400);
    try std.testing.expect(cc.window_size < initial_window);
    try std.testing.expectEqual(@as(u64, 1), cc.loss_count);
}
