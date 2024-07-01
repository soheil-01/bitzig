const std = @import("std");
const MerkleTree = @import("merkle_tree.zig");
const utils = @import("../utils.zig");

const MerkleBlock = @This();

pub const command = "merkleblock";

allocator: std.mem.Allocator,
version: u32,
prev_block: [32]u8,
merkle_root: [32]u8,
timestamp: u32,
bits: [4]u8,
nonce: [4]u8,
total: u32,
hashes: [][32]u8,
flags: []u8,

pub fn deinit(self: MerkleBlock) void {
    self.allocator.free(self.hashes);
    self.allocator.free(self.flags);
}

pub fn isValid(self: MerkleBlock) !bool {
    const flag_bits = try utils.bytesToBitField(self.allocator, self.flags);
    defer self.allocator.free(flag_bits);

    var hashes = try self.allocator.dupe([32]u8, self.hashes);
    defer self.allocator.free(hashes);

    for (0..hashes.len) |i| {
        std.mem.reverse(u8, &hashes[i]);
    }

    const merkle_tree = try MerkleTree.init(self.allocator, self.total);
    defer merkle_tree.deinit();

    try merkle_tree.populateTree(flag_bits, self.hashes);

    var root = merkle_tree.root().?;
    std.mem.reverse(u8, &root);

    return std.mem.eql(u8, &self.merkle_root, &root);
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !MerkleBlock {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(allocator: std.mem.Allocator, reader: anytype) !MerkleBlock {
    const version = reader.readInt(u32, .little) catch return error.InvalidEncoding;

    var prev_block = reader.readBytesNoEof(32) catch return error.InvalidEncoding;
    std.mem.reverse(u8, &prev_block);

    var merkle_root: [32]u8 = reader.readBytesNoEof(32) catch return error.InvalidEncoding;
    std.mem.reverse(u8, &merkle_root);

    const timestamp = reader.readInt(u32, .little) catch return error.InvalidEncoding;
    const bits = reader.readBytesNoEof(4) catch return error.InvalidEncoding;
    const nonce = reader.readBytesNoEof(4) catch return error.InvalidEncoding;

    const total = reader.readInt(u32, .little) catch return error.InvalidEncoding;

    const num_hashes = utils.readVarintFromReader(reader) catch return error.InvalidEncoding;
    var hashes = try std.ArrayList([32]u8).initCapacity(allocator, num_hashes);

    for (0..num_hashes) |_| {
        var hash: [32]u8 = reader.readBytesNoEof(32) catch return error.InvalidEncoding;
        std.mem.reverse(u8, &hash);

        try hashes.append(hash);
    }

    const flags_len = utils.readVarintFromReader(reader) catch return error.InvalidEncoding;
    const flags = try std.ArrayList(u8).initCapacity(allocator, flags_len);

    for (0..flags_len) |_| {
        try flags.append(try reader.readByte());
    }

    return .{
        .allocator = allocator,
        .version = version,
        .prev_block = prev_block,
        .merkle_root = merkle_root,
        .timestamp = timestamp,
        .bits = bits,
        .nonce = nonce,
        .total = total,
        .hashes = try hashes.toOwnedSlice(),
        .flags = try flags.toOwnedSlice(),
    };
}
