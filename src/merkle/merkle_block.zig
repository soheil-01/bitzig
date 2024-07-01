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

    var merkle_tree = try MerkleTree.init(self.allocator, self.total);
    defer merkle_tree.deinit();

    try merkle_tree.populateTree(flag_bits, hashes);

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
    var flags = try std.ArrayList(u8).initCapacity(allocator, flags_len);

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

const testing = std.testing;
const testing_alloc = testing.allocator;

test "MerkleBlock: parse" {
    const merkle_block_bytes = try utils.hexToBytes(testing_alloc, "00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635");
    defer testing_alloc.free(merkle_block_bytes);

    const merkle_block = try MerkleBlock.parse(testing_alloc, merkle_block_bytes);
    defer merkle_block.deinit();

    const version = 0x20000000;
    try testing.expectEqual(version, merkle_block.version);

    const merkle_root = try utils.hexToBytes(testing_alloc, "ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4");
    defer testing_alloc.free(merkle_root);
    std.mem.reverse(u8, merkle_root);
    try testing.expectEqualSlices(u8, merkle_root, &merkle_block.merkle_root);

    const prev_block = try utils.hexToBytes(testing_alloc, "df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000");
    defer testing_alloc.free(prev_block);
    std.mem.reverse(u8, prev_block);
    try testing.expectEqualSlices(u8, prev_block, &merkle_block.prev_block);

    const timestamp = std.mem.readInt(u32, &[_]u8{ 0xdc, 0x7c, 0x83, 0x5b }, .little);
    try testing.expectEqual(timestamp, merkle_block.timestamp);

    const bits = [_]u8{ 0x67, 0xd8, 0x00, 0x1a };
    try testing.expectEqualSlices(u8, &bits, &merkle_block.bits);

    const nonce = [_]u8{ 0xc1, 0x57, 0xe6, 0x70 };
    try testing.expectEqualSlices(u8, &nonce, &merkle_block.nonce);

    const total = std.mem.readInt(u32, &[_]u8{ 0xbf, 0x0d, 0x00, 0x00 }, .little);
    try testing.expectEqual(total, merkle_block.total);

    const hashes = [_][]u8{
        try utils.hexToBytes(testing_alloc, "ba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a"),
        try utils.hexToBytes(testing_alloc, "7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d"),
        try utils.hexToBytes(testing_alloc, "34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2"),
        try utils.hexToBytes(testing_alloc, "158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cba"),
        try utils.hexToBytes(testing_alloc, "ee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763ce"),
        try utils.hexToBytes(testing_alloc, "f8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097"),
        try utils.hexToBytes(testing_alloc, "c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d"),
        try utils.hexToBytes(testing_alloc, "6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543"),
        try utils.hexToBytes(testing_alloc, "d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274c"),
        try utils.hexToBytes(testing_alloc, "dfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb62261"),
    };
    defer for (hashes) |hash| testing_alloc.free(hash);

    for (0..hashes.len) |i| {
        std.mem.reverse(u8, hashes[i]);
        try testing.expectEqualSlices(u8, hashes[i], &merkle_block.hashes[i]);
    }

    const flags = [_]u8{ 0xb5, 0x56, 0x35 };
    try testing.expectEqualSlices(u8, &flags, merkle_block.flags);
}

test "MerkleBlock: isValid" {
    const merkle_block_bytes = try utils.hexToBytes(testing_alloc, "00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635");
    defer testing_alloc.free(merkle_block_bytes);

    const merkle_block = try MerkleBlock.parse(testing_alloc, merkle_block_bytes);
    defer merkle_block.deinit();

    try testing.expect(try merkle_block.isValid());
}
