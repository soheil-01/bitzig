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

pub fn difficulty(self: Block, allocator: std.mem.Allocator) !f64 {
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

pub fn checkPow(self: Block) !bool {
    const h256 = utils.hash256(&try self.serialize());
    const proof = std.mem.readInt(u256, &h256, .little);

    return proof < self.target();
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
    const version = reader.readInt(u32, .little) catch return error.InvalidEncoding;

    var prev_block = reader.readBytesNoEof(32) catch return error.InvalidEncoding;
    std.mem.reverse(u8, &prev_block);

    var merkle_root: [32]u8 = reader.readBytesNoEof(32) catch return error.InvalidEncoding;
    std.mem.reverse(u8, &merkle_root);

    const timestamp = reader.readInt(u32, .little) catch return error.InvalidEncoding;
    const bits = reader.readBytesNoEof(4) catch return error.InvalidEncoding;
    const nonce = reader.readBytesNoEof(4) catch return error.InvalidEncoding;

    return init(version, prev_block, merkle_root, timestamp, bits, nonce);
}

const testing = std.testing;
const testing_alloc = testing.allocator;

test "Block: parse" {
    const block_raw = try utils.hexToBytes(testing_alloc, "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d");
    defer testing_alloc.free(block_raw);

    const block = try Block.parse(block_raw);

    try testing.expectEqual(@as(u32, 0x20000002), block.version);

    const want_prev_block = try utils.hexToBytes(testing_alloc, "000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e");
    defer testing_alloc.free(want_prev_block);
    try testing.expectEqualSlices(u8, &block.prev_block, want_prev_block);

    const want_merkle_root = try utils.hexToBytes(testing_alloc, "be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b");
    defer testing_alloc.free(want_merkle_root);
    try testing.expectEqualSlices(u8, &block.merkle_root, want_merkle_root);

    try testing.expectEqual(@as(u32, 0x59a7771e), block.timestamp);
    try testing.expectEqualSlices(u8, &block.bits, &[_]u8{ 0xe9, 0x3c, 0x01, 0x18 });
    try testing.expectEqualSlices(u8, &block.nonce, &[_]u8{ 0xa4, 0xff, 0xd7, 0x1d });
}

test "Block: serialize" {
    const block_raw = try utils.hexToBytes(testing_alloc, "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d");
    defer testing_alloc.free(block_raw);

    const block = try Block.parse(block_raw);
    const serialized = try block.serialize();

    try testing.expectEqualSlices(u8, block_raw, &serialized);
}

test "Block: hash" {
    const block_raw = try utils.hexToBytes(testing_alloc, "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d");
    defer testing_alloc.free(block_raw);

    const block = try Block.parse(block_raw);
    const block_hash = try block.hash();

    const expected_hash = try utils.hexToBytes(testing_alloc, "0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523");
    defer testing_alloc.free(expected_hash);

    try testing.expectEqualSlices(u8, &block_hash, expected_hash);
}

test "Block: bip9" {
    {
        const block_raw = try utils.hexToBytes(testing_alloc, "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d");
        defer testing_alloc.free(block_raw);
        const block = try Block.parse(block_raw);
        try testing.expect(block.bip9());
    }

    {
        const block_raw = try utils.hexToBytes(testing_alloc, "0400000039fa821848781f027a2e6dfabbf6bda920d9ae61b63400030000000000000000ecae536a304042e3154be0e3e9a8220e5568c3433a9ab49ac4cbb74f8df8e8b0cc2acf569fb9061806652c27");
        defer testing_alloc.free(block_raw);
        const block = try Block.parse(block_raw);
        try testing.expect(!block.bip9());
    }
}

test "Block: bip91" {
    {
        const block_raw = try utils.hexToBytes(testing_alloc, "1200002028856ec5bca29cf76980d368b0a163a0bb81fc192951270100000000000000003288f32a2831833c31a25401c52093eb545d28157e200a64b21b3ae8f21c507401877b5935470118144dbfd1");
        defer testing_alloc.free(block_raw);
        const block = try Block.parse(block_raw);
        try testing.expect(block.bip91());
    }

    {
        const block_raw = try utils.hexToBytes(testing_alloc, "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d");
        defer testing_alloc.free(block_raw);
        const block = try Block.parse(block_raw);
        try testing.expect(!block.bip91());
    }
}

test "Block: bip141" {
    {
        const block_raw = try utils.hexToBytes(testing_alloc, "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d");
        defer testing_alloc.free(block_raw);
        const block = try Block.parse(block_raw);
        try testing.expect(block.bip141());
    }

    {
        const block_raw = try utils.hexToBytes(testing_alloc, "0000002066f09203c1cf5ef1531f24ed21b1915ae9abeb691f0d2e0100000000000000003de0976428ce56125351bae62c5b8b8c79d8297c702ea05d60feabb4ed188b59c36fa759e93c0118b74b2618");
        defer testing_alloc.free(block_raw);
        const block = try Block.parse(block_raw);
        try testing.expect(!block.bip141());
    }
}

test "Block: target" {
    const block_raw = try utils.hexToBytes(testing_alloc, "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d");
    defer testing_alloc.free(block_raw);
    const block = try Block.parse(block_raw);

    const expected_target: u256 = 0x13ce9000000000000000000000000000000000000000000;
    try testing.expectEqual(expected_target, block.target());
}

test "Block: difficulty" {
    const block_raw = try utils.hexToBytes(testing_alloc, "020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d");
    defer testing_alloc.free(block_raw);
    const block = try Block.parse(block_raw);

    try testing.expectApproxEqAbs(@as(f64, 888171856257), try block.difficulty(testing_alloc), 1);
}

test "Block: checkPow" {
    {
        const block_raw = try utils.hexToBytes(testing_alloc, "04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1");
        defer testing_alloc.free(block_raw);
        const block = try Block.parse(block_raw);
        try testing.expect(try block.checkPow());
    }

    {
        const block_raw = try utils.hexToBytes(testing_alloc, "04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0");
        defer testing_alloc.free(block_raw);
        const block = try Block.parse(block_raw);
        try testing.expect(!try block.checkPow());
    }
}
