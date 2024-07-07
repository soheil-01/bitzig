const std = @import("std");
const c = @cImport({
    @cInclude("ripemd160.h");
});

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const TWO_WEEKS = 60 * 60 * 24 * 14;
const MAX_TARGET: u256 = 0xffff * std.math.pow(u256, 256, 0x1d - 3);

const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn modPow(a: u256, b: u256, mod: u256) u256 {
    var base = a;
    var exponent = b;

    var result: u256 = 1;

    while (exponent > 0) : (exponent >>= 1) {
        if (exponent & 1 == 1) {
            var tmp: u512 = result;
            tmp *= base;
            result = @intCast(@mod(tmp, mod));
        }

        var sqr: u512 = base;
        sqr *= sqr;
        base = @intCast(@mod(sqr, mod));
    }

    return result;
}

pub fn readIntWithPadding(comptime T: type, source: []const u8, endian: std.builtin.Endian) T {
    const byte_count = @divExact(@typeInfo(T).Int.bits, 8);
    assert(source.len <= byte_count);

    var padded_source: [byte_count]u8 = undefined;
    if (source.len != byte_count) {
        padded_source = [_]u8{0} ** byte_count;
    }

    std.mem.copyForwards(u8, switch (endian) {
        .big => padded_source[byte_count - source.len ..],
        .little => padded_source[0..source.len],
    }, source);

    return std.mem.readInt(T, &padded_source, endian);
}

pub fn encodeBase58(dest: []u8, source: []const u8) []u8 {
    var num = readIntWithPadding(u1024, source, .big);

    var i = dest.len;
    while (num > 0) : (num /= 58) {
        assert(i > 0);
        i -= 1;
        dest[i] = BASE58_ALPHABET[@intCast(num % 58)];
    }

    for (source) |ch| {
        if (ch == 0) {
            assert(i > 0);
            i -= 1;
            dest[i] = BASE58_ALPHABET[0];
        } else break;
    }

    return dest[i..];
}

pub fn encodeBase58Checksum(dest: []u8, comptime source_len: usize, source: [source_len]u8) []u8 {
    const hash256_source = hash256(&source);

    return encodeBase58(dest, source ++ hash256_source[0..4]);
}

pub fn decodeBase58Address(source: []const u8) ![]u8 {
    var num: u200 = 0;
    for (source) |char| {
        num *= 58;
        num += std.mem.indexOf(u8, BASE58_ALPHABET, &.{char}).?;
    }

    var combined = encodeInt(u200, num, .big);
    const checksum = combined[combined.len - 4 ..];
    const expected_checksum = hash256(combined[0 .. combined.len - 4])[0..4];

    if (!std.mem.eql(u8, checksum, expected_checksum)) {
        return error.BadAddress;
    }

    return combined[1 .. combined.len - 4];
}

pub fn sha256(msg: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(msg, &result, .{});

    return result;
}

pub fn hash256(msg: []const u8) [32]u8 {
    var sha256_1: [32]u8 = undefined;
    Sha256.hash(msg, &sha256_1, .{});

    var sha256_2: [32]u8 = undefined;
    Sha256.hash(&sha256_1, &sha256_2, .{});

    return sha256_2;
}

pub fn hash160(msg: []const u8) [20]u8 {
    var sha256_msg: [32]u8 = undefined;
    Sha256.hash(msg, &sha256_msg, .{});

    return ripemd160(sha256_msg);
}

pub fn ripemd160(msg: [32]u8) [20]u8 {
    var hash: [20]u8 = undefined;
    c.ripemd160(&msg, msg.len, &hash);

    return hash;
}

pub fn readVarintFromReader(reader: anytype) !u64 {
    const i = try reader.readByte();

    switch (i) {
        0xfd => {
            const buf = try reader.readBytesNoEof(2);
            const int = std.mem.readInt(u16, &buf, .little);

            return @intCast(int);
        },
        0xfe => {
            const buf = try reader.readBytesNoEof(4);
            const int = std.mem.readInt(u32, &buf, .little);

            return @intCast(int);
        },
        0xff => {
            const buf = try reader.readBytesNoEof(8);
            const int = std.mem.readInt(u64, &buf, .little);

            return int;
        },
        else => {
            return i;
        },
    }
}

pub fn encodeVarint(allocator: std.mem.Allocator, int: u64) ![]u8 {
    if (int < 0xfd) {
        var buf = try allocator.alloc(u8, 1);
        buf[0] = @intCast(int);
        return buf;
    } else if (int < 0x10000) {
        var buf = try allocator.alloc(u8, 3);
        buf[0] = 0xfd;
        std.mem.writeInt(u16, buf[1..3], @intCast(int), .little);
        return buf;
    } else if (int < 0x100000000) {
        var buf = try allocator.alloc(u8, 5);
        buf[0] = 0xfe;
        std.mem.writeInt(u32, buf[1..5], @intCast(int), .little);
        return buf;
    } else if (int < 0x10000000000000000) {
        var buf = try allocator.alloc(u8, 9);
        buf[0] = 0xff;
        std.mem.writeInt(u64, buf[1..9], int, .little);
        return buf;
    }
}

pub fn encodeInt(comptime T: type, int: T, endian: std.builtin.Endian) [@divExact(@typeInfo(T).Int.bits, 8)]u8 {
    var int_bytes: [@divExact(@typeInfo(T).Int.bits, 8)]u8 = undefined;
    std.mem.writeInt(T, &int_bytes, int, endian);

    return int_bytes;
}

pub fn hexToBytes(allocator: std.mem.Allocator, source: []const u8) ![]u8 {
    const bytes = try allocator.alloc(u8, source.len / 2);
    errdefer allocator.free(bytes);

    return std.fmt.hexToBytes(bytes, source);
}

pub fn h160ToP2pkhAddress(dest: []u8, h160: [20]u8, testnet: bool) []u8 {
    const prefix: u8 = if (testnet) 0x6f else 0x00;
    return encodeBase58Checksum(dest, 21, [_]u8{prefix} ++ h160);
}

pub fn h160ToP2shAddress(dest: []u8, h160: [20]u8, testnet: bool) []u8 {
    const prefix: u8 = if (testnet) 0xc4 else 0x05;
    return encodeBase58Checksum(dest, 21, [_]u8{prefix} ++ h160);
}

pub fn bitsToTarget(bits: [4]u8) u256 {
    const exponent = bits[3];
    const coefficient = std.mem.readInt(u24, bits[0..3], .little);

    var target: u256 = coefficient;
    target *= std.math.pow(u256, 256, exponent - 3);

    return target;
}

pub fn targetToBits(target: u256) [4]u8 {
    var raw_bytes = encodeInt(u256, target, .big);

    var i: usize = 0;
    for (raw_bytes) |byte| {
        if (byte == 0) {
            i += 1;
        } else break;
    }

    const bytes = raw_bytes[i..];
    const bytes_len: u8 = @intCast(bytes.len);

    var exponent: u8 = 0;
    var coefficient: [3]u8 = undefined;

    if (bytes[0] > 0x7f) {
        exponent = bytes_len + 1;
        coefficient = [_]u8{0} ++ bytes[0..2].*;
    } else {
        exponent = bytes_len;
        coefficient = bytes[0..3].*;
    }

    std.mem.reverse(u8, &coefficient);
    const new_bits = coefficient ++ [_]u8{exponent};

    return new_bits;
}

pub fn calculateNewBits(previous_bits: [4]u8, time_differential: u32) [4]u8 {
    var time_diff = time_differential;

    if (time_diff > TWO_WEEKS * 4) {
        time_diff = TWO_WEEKS * 4;
    }
    if (time_diff < TWO_WEEKS / 4) {
        time_diff = TWO_WEEKS / 4;
    }

    var new_target = bitsToTarget(previous_bits) * time_diff / TWO_WEEKS;
    if (new_target > MAX_TARGET) {
        new_target = MAX_TARGET;
    }

    return targetToBits(new_target);
}

pub fn merkleParent(hash1: [32]u8, hash2: [32]u8) [32]u8 {
    const combined = hash1 ++ hash2;
    return hash256(&combined);
}

pub fn merkleParentLevel(allocator: std.mem.Allocator, hashes: [][32]u8) ![][32]u8 {
    var parent_level = try allocator.alloc([32]u8, (hashes.len / 2) + (hashes.len & 1));

    var i: usize = 0;
    while (i < hashes.len / 2) : (i += 1) {
        parent_level[i] = merkleParent(hashes[i * 2], hashes[i * 2 + 1]);
    }

    if (hashes.len & 1 == 1) {
        parent_level[i] = merkleParent(hashes[hashes.len - 1], hashes[hashes.len - 1]);
    }

    return parent_level;
}

pub fn merkleRoot(allocator: std.mem.Allocator, hashes: [][32]u8) ![32]u8 {
    if (hashes.len == 0) return error.EmptyInput;
    if (hashes.len == 1) return hashes[0];

    var current_hashes = try allocator.dupe([32]u8, hashes);
    defer allocator.free(current_hashes);

    while (current_hashes.len > 1) {
        const parent_level = try merkleParentLevel(allocator, current_hashes);
        allocator.free(current_hashes);
        current_hashes = parent_level;
    }

    return current_hashes[0];
}

pub fn bytesToBitField(allocator: std.mem.Allocator, bytes: []const u8) ![]u1 {
    var flag_bits = std.ArrayList(u1).init(allocator);

    for (0..bytes.len) |i| {
        var byte = bytes[i];

        for (0..8) |_| {
            try flag_bits.append(@intCast(byte & 1));
            byte >>= 1;
        }
    }

    return flag_bits.toOwnedSlice();
}

pub fn bitFieldToBytes(allocator: std.mem.Allocator, bit_field: []const u1) ![]u8 {
    assert(bit_field.len % 8 == 0);

    var result = try allocator.alloc(u8, bit_field.len / 8);
    @memset(result, 0);

    for (bit_field, 0..) |bit, i| {
        const byte_index = i / 8;
        const bit_index: u3 = @intCast(i % 8);
        if (bit == 1) result[byte_index] |= @as(u8, 1) << bit_index;
    }

    return result;
}

const testing = std.testing;
const testing_alloc = testing.allocator;

test "calculateNewBits" {
    const prev_bits = [_]u8{ 0x54, 0xd8, 0x01, 0x18 };
    const time_differential: u32 = 302400;
    const want = [_]u8{ 0x00, 0x15, 0x76, 0x17 };

    const new_bits = calculateNewBits(prev_bits, time_differential);

    try testing.expectEqualSlices(u8, &want, &new_bits);
}

test "merkleParent" {
    const hash0 = try hexToBytes(testing_alloc, "c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5");
    defer testing_alloc.free(hash0);

    const hash1 = try hexToBytes(testing_alloc, "c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5");
    defer testing_alloc.free(hash1);

    const want = try hexToBytes(testing_alloc, "8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd");
    defer testing_alloc.free(want);

    try testing.expectEqualSlices(u8, want, &merkleParent(std.mem.bytesToValue([32]u8, hash0), std.mem.bytesToValue([32]u8, hash1)));
}

test "merkleParentLevel" {
    const hashes_bytes = [_][]u8{
        try hexToBytes(testing_alloc, "c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5"),
        try hexToBytes(testing_alloc, "c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5"),
        try hexToBytes(testing_alloc, "f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0"),
        try hexToBytes(testing_alloc, "3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181"),
        try hexToBytes(testing_alloc, "10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae"),
        try hexToBytes(testing_alloc, "7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161"),
        try hexToBytes(testing_alloc, "8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc"),
        try hexToBytes(testing_alloc, "dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877"),
        try hexToBytes(testing_alloc, "b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59"),
        try hexToBytes(testing_alloc, "95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c"),
        try hexToBytes(testing_alloc, "2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908"),
    };
    defer for (hashes_bytes) |hash_bytes| testing_alloc.free(hash_bytes);

    var hashes = try testing_alloc.alloc([32]u8, hashes_bytes.len);
    defer testing_alloc.free(hashes);

    for (0..hashes.len) |i| {
        hashes[i] = std.mem.bytesToValue([32]u8, hashes_bytes[i]);
    }

    const want_hashes = [_][]u8{
        try hexToBytes(testing_alloc, "8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd"),
        try hexToBytes(testing_alloc, "7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800"),
        try hexToBytes(testing_alloc, "ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7"),
        try hexToBytes(testing_alloc, "68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069"),
        try hexToBytes(testing_alloc, "43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27"),
        try hexToBytes(testing_alloc, "1796cd3ca4fef00236e07b723d3ed88e1ac433acaaa21da64c4b33c946cf3d10"),
    };
    defer for (want_hashes) |hash| testing_alloc.free(hash);

    const actual_hashes = try merkleParentLevel(testing_alloc, hashes);
    defer testing_alloc.free(actual_hashes);

    for (0..want_hashes.len) |i| {
        try testing.expectEqualSlices(u8, want_hashes[i], &actual_hashes[i]);
    }
}

test "merkleRoot" {
    const hashes_bytes = [_][]u8{
        try hexToBytes(testing_alloc, "c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5"),
        try hexToBytes(testing_alloc, "c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5"),
        try hexToBytes(testing_alloc, "f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0"),
        try hexToBytes(testing_alloc, "3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181"),
        try hexToBytes(testing_alloc, "10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae"),
        try hexToBytes(testing_alloc, "7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161"),
        try hexToBytes(testing_alloc, "8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc"),
        try hexToBytes(testing_alloc, "dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877"),
        try hexToBytes(testing_alloc, "b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59"),
        try hexToBytes(testing_alloc, "95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c"),
        try hexToBytes(testing_alloc, "2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908"),
        try hexToBytes(testing_alloc, "b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0"),
    };
    defer for (hashes_bytes) |hash_bytes| testing_alloc.free(hash_bytes);

    var hashes = try testing_alloc.alloc([32]u8, hashes_bytes.len);
    defer testing_alloc.free(hashes);

    for (0..hashes.len) |i| {
        hashes[i] = std.mem.bytesToValue([32]u8, hashes_bytes[i]);
    }

    const expected = try hexToBytes(testing_alloc, "acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6");
    defer testing_alloc.free(expected);

    const actual = try merkleRoot(testing_alloc, hashes);

    try testing.expectEqualSlices(u8, expected, &actual);
}

test "bytesToBitField and bitFieldToBytes" {
    const bit_field = [_]u1{ 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0 };
    const bytes = [_]u8{ 0x40, 0x00, 0x60, 0x0a, 0x08, 0x00, 0x00, 0x01, 0x09, 0x40 };

    {
        const actual = try bitFieldToBytes(testing_alloc, &bit_field);
        defer testing_alloc.free(actual);
        try testing.expectEqualSlices(u8, &bytes, actual);
    }

    {
        const actual = try bytesToBitField(testing_alloc, &bytes);
        defer testing_alloc.free(actual);
        try testing.expectEqualSlices(u1, &bit_field, actual);
    }
}
