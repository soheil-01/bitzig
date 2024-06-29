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

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !HeadersMessage {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(allocator: std.mem.Allocator, reader: anytype) !HeadersMessage {
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

const testing = std.testing;
const testing_alloc = testing.allocator;

test "HeadersMessage: parse and serialize" {
    const message_bytes = try utils.hexToBytes(testing_alloc, "0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600");
    defer testing_alloc.free(message_bytes);

    const headers = try HeadersMessage.parse(testing_alloc, message_bytes);
    defer headers.deinit(testing_alloc);

    try testing.expectEqual(headers.blocks.len, 2);

    const serialized = try headers.serialize(testing_alloc);
    defer testing_alloc.free(serialized);

    try testing.expectEqualSlices(u8, message_bytes, serialized);
}
