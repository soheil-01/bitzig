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

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !GetHeadersMessage {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(_: std.mem.Allocator, reader: anytype) !GetHeadersMessage {
    const version = try reader.readInt(u32, .little);
    const num_hashes = try utils.readVarintFromReader(reader);

    var start_block_tmp = try reader.readBytesNoEof(32);
    std.mem.reverse(u8, &start_block_tmp);

    var end_block_tmp = try reader.readBytesNoEof(32);
    std.mem.reverse(u8, &end_block_tmp);

    return .{
        .version = version,
        .num_hashes = num_hashes,
        .start_block = start_block_tmp,
        .end_block = end_block_tmp,
    };
}

const testing = std.testing;
const testing_alloc = testing.allocator;

test "GetHeadersMessage: serialize" {
    const start_block = try utils.hexToBytes(testing_alloc, "0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3");
    defer testing_alloc.free(start_block);

    const get_header = GetHeadersMessage{ .start_block = std.mem.bytesToValue([32]u8, start_block) };
    const serialized = try get_header.serialize(testing_alloc);
    defer testing_alloc.free(serialized);

    const expected = try utils.hexToBytes(testing_alloc, "7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    defer testing_alloc.free(expected);

    try testing.expectEqualSlices(u8, expected, serialized);
}

test "GetHeadersMessage: parse" {
    const start_block = try utils.hexToBytes(testing_alloc, "0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3");
    defer testing_alloc.free(start_block);

    const message_bytes = try utils.hexToBytes(testing_alloc, "7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    defer testing_alloc.free(message_bytes);

    const get_header = try GetHeadersMessage.parse(testing_alloc, message_bytes);

    try testing.expectEqualSlices(u8, start_block, &get_header.start_block);
}
