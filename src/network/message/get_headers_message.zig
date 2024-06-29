const std = @import("std");
const utils = @import("../../utils.zig");

const GetHeadersMessage = @This();

pub const command = "getheaders";

version: u32 = 70015,
num_hashes: u64 = 1,
start_block: [32]u8,
end_block: [32]u8 = [_]u8{0} ** 32,

pub fn serialize(self: GetHeadersMessage, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    const version = utils.encodeInt(u32, self.version, .little);
    try result.appendSlice(&version);

    const num_hashes = try utils.encodeVarint(allocator, self.num_hashes);
    defer allocator.free(num_hashes);
    try result.appendSlice(num_hashes);

    var start_block_tmp = self.start_block;
    std.mem.reverse(u8, &start_block_tmp);
    try result.appendSlice(&start_block_tmp);

    var end_block_tmp = self.end_block;
    std.mem.reverse(u8, &end_block_tmp);
    try result.appendSlice(&end_block_tmp);

    return result.toOwnedSlice();
}

pub fn parse(_: []const u8) !GetHeadersMessage {
    return .{};
}
