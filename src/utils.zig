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

const testing = std.testing;

test "calculateNewBits" {
    const prev_bits = [_]u8{ 0x54, 0xd8, 0x01, 0x18 };
    const time_differential: u32 = 302400;
    const want = [_]u8{ 0x00, 0x15, 0x76, 0x17 };

    const new_bits = calculateNewBits(prev_bits, time_differential);

    try testing.expectEqualSlices(u8, &want, &new_bits);
}
