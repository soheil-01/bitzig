const std = @import("std");
const Block = @import("../../block/block.zig");
const utils = @import("../../utils.zig");

const HeadersMessage = @This();

pub const command = "headers";

blocks: []Block,

pub fn deinit(self: HeadersMessage, allocator: std.mem.Allocator) void {
    allocator.free(self.blocks);
}

pub fn serialize(self: HeadersMessage, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    const num_headers = try utils.encodeVarint(allocator, self.blocks.len);
    defer allocator.free(num_headers);
    try result.appendSlice(num_headers);

    for (self.blocks) |block| {
        const block_serialized = try block.serialize();
        try result.appendSlice(&block_serialized);

        try result.append(0);
    }

    return result.toOwnedSlice();
}

pub fn parse(source: []const u8, allocator: std.mem.Allocator) !HeadersMessage {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(reader, allocator);
}

pub fn parseFromReader(reader: anytype, allocator: std.mem.Allocator) !HeadersMessage {
    const num_headers = try utils.readVarintFromReader(reader);

    var blocks = try std.ArrayList(Block).initCapacity(allocator, num_headers);

    for (0..num_headers) |_| {
        const block = try Block.parseFromReader(reader);
        try blocks.append(block);

        const num_txs = try utils.readVarintFromReader(reader);
        if (num_txs != 0) {
            return error.NumOfTxsNot0;
        }
    }

    return .{ .blocks = try blocks.toOwnedSlice() };
}
