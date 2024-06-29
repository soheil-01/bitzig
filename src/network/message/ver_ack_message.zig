const std = @import("std");

const VerAckMessage = @This();

pub const command = "verack";

pub fn serialize(_: VerAckMessage, allocator: std.mem.Allocator) ![]u8 {
    const result = try allocator.alloc(u8, 0);

    return result;
}

pub fn parse(_: std.mem.Allocator, _: []const u8) !VerAckMessage {
    return .{};
}
