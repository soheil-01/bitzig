const std = @import("std");
const utils = @import("../utils.zig");

const Block = @This();

version: u32,
prev_block: [32]u8,
merkle_root: [32]u8,
timestamp: u32,
bits: [4]u8,
nonce: [4]u8,

pub fn init(version: u32, prev_block: [32]u8, merkle_root: [32]u8, timestamp: u32, bits: [4]u8, nonce: [4]u8) Block {
    return .{
        .version = version,
        .prev_block = prev_block,
        .merkle_root = merkle_root,
        .timestamp = timestamp,
        .bits = bits,
        .nonce = nonce,
    };
}

pub fn hash(self: Block) ![32]u8 {
    const serialized = try self.serialize();

    var result = utils.hash256(&serialized);
    std.mem.reverse(u8, &result);

    return result;
}

pub fn bip9(self: Block) bool {
    return self.version >> 29 == 1;
}

pub fn bip91(self: Block) bool {
    return self.version >> 4 & 1 == 1;
}

pub fn bip141(self: Block) bool {
    return self.version >> 1 & 1 == 1;
}

pub fn target(self: Block) u256 {
    return utils.bitsToTarget(self.bits);
}

pub fn difficulty(self: Block, allocator: std.mem.Allocator) f64 {
    var a = try std.math.big.Rational.init(allocator);
    defer a.deinit();
    try a.setInt(0xffff * std.math.pow(u256, 256, 0x1d - 3));

    var b = try std.math.big.Rational.init(allocator);
    defer b.deinit();
    try b.setInt(self.target());

    var result = try std.math.big.Rational.init(allocator);
    defer result.deinit();
    try result.div(a, b);

    return result.toFloat(f64);
}

pub fn serialize(self: Block) ![80]u8 {
    var result: [80]u8 = undefined;
    var bf = std.io.fixedBufferStream(&result);
    const writer = bf.writer();

    try writer.writeInt(u32, self.version, .little);

    var prev_block = self.prev_block;
    std.mem.reverse(u8, &prev_block);
    try writer.writeAll(&prev_block);

    var merkle_root = self.merkle_root;
    std.mem.reverse(u8, &merkle_root);
    try writer.writeAll(&merkle_root);

    try writer.writeInt(u32, self.timestamp, .little);

    try writer.writeAll(&self.bits);
    try writer.writeAll(&self.nonce);

    return result;
}

pub fn parse(source: []const u8) !Block {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(reader);
}

pub fn parseFromReader(reader: anytype) !Block {
    const version = utils.readIntFromReader(u32, reader, .little) catch return error.InvalidEncoding;

    var prev_block: [32]u8 = undefined;
    reader.readNoEof(&prev_block) catch return error.InvalidEncoding;
    std.mem.reverse(u8, &prev_block);

    var merkle_root: [32]u8 = undefined;
    reader.readNoEof(&merkle_root) catch return error.InvalidEncoding;
    std.mem.reverse(u8, &merkle_root);

    const timestamp = utils.readIntFromReader(u32, reader, .little) catch return error.InvalidEncoding;

    var bits: [4]u8 = undefined;
    reader.readNoEof(&bits) catch return error.InvalidEncoding;

    var nonce: [4]u8 = undefined;
    reader.readNoEof(&nonce) catch return error.InvalidEncoding;

    return init(version, prev_block, merkle_root, timestamp, bits, nonce);
}
