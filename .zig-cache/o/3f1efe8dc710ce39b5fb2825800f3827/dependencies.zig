pub const packages = struct {
    pub const @"flash-0.2.0-dnj73-FkAwCEijnprnIBvqsegqxbKP9yIfMdKTZl5SJF" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/flash-0.2.0-dnj73-FkAwCEijnprnIBvqsegqxbKP9yIfMdKTZl5SJF";
        pub const build_zig = @import("flash-0.2.0-dnj73-FkAwCEijnprnIBvqsegqxbKP9yIfMdKTZl5SJF");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zsync", "zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS" },
        };
    };
    pub const @"zcrypto-0.8.4-rgQAI6I0DQD3T7Vk5_S-EaUxMAhoXp7YvJtnzInpG7U1" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zcrypto-0.8.4-rgQAI6I0DQD3T7Vk5_S-EaUxMAhoXp7YvJtnzInpG7U1";
        pub const build_zig = @import("zcrypto-0.8.4-rgQAI6I0DQD3T7Vk5_S-EaUxMAhoXp7YvJtnzInpG7U1");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "zsync", "zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS" },
        };
    };
    pub const @"zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS";
        pub const build_zig = @import("zsync-0.3.2-KAuhed0XGADaOKjYNl34Ragvca2zBYqvoAsBV-AhkoLS");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "zcrypto", "zcrypto-0.8.4-rgQAI6I0DQD3T7Vk5_S-EaUxMAhoXp7YvJtnzInpG7U1" },
    .{ "flash", "flash-0.2.0-dnj73-FkAwCEijnprnIBvqsegqxbKP9yIfMdKTZl5SJF" },
};
