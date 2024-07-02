const std = @import("std");
const utils = @import("../utils.zig");

const murmur3 = std.hash.Murmur3_32;

const BloomFilter = @This();

const BIP37_CONSTANT = 0xfba4c795;

pub const command = "filterload";

size: u8,
bit_field: []u1,
function_count: u32,
tweak: u32,

pub fn init(allocator: std.mem.Allocator, size: u8, function_count: u32, tweak: u32) !BloomFilter {
    const bit_field = try allocator.alloc(u1, size * 8);
    @memset(bit_field, 0);

    return .{
        .size = size,
        .bit_field = bit_field,
        .function_count = function_count,
        .tweak = tweak,
    };
}

pub fn deinit(self: BloomFilter, allocator: std.mem.Allocator) void {
    allocator.free(self.bit_field);
}

pub fn add(self: BloomFilter, item: []const u8) void {
    for (0..self.function_count) |i| {
        const seed: u32 = @truncate(i * BIP37_CONSTANT + self.tweak);
        const h = murmur3.hashWithSeed(item, seed);
        const bit = h % (self.size * 8);
        self.bit_field[bit] = 1;
    }
}

pub fn filterBytes(self: BloomFilter, allocator: std.mem.Allocator) ![]u8 {
    return utils.bitFieldToBytes(allocator, self.bit_field);
}

pub fn serialize(self: BloomFilter, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    const size = try utils.encodeVarint(allocator, self.size);
    defer allocator.free(size);
    try result.appendSlice(size);

    const filter_bytes = try self.filterBytes(allocator);
    defer allocator.free(filter_bytes);
    try result.appendSlice(filter_bytes);

    const function_count = utils.encodeInt(u32, self.function_count, .little);
    try result.appendSlice(&function_count);

    const tweak = utils.encodeInt(u32, self.tweak, .little);
    try result.appendSlice(&tweak);

    try result.append(1);

    return result.toOwnedSlice();
}
