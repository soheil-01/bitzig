const std = @import("std");
const c = @cImport({
    @cInclude("ripemd160.h");
});

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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

pub fn encodeBase58(dest: []u8, source: []const u8) []u8 {
    assert(source.len <= 128);

    var source_extended: [128]u8 = undefined;
    if (source.len != 128) {
        source_extended = [_]u8{0} ** 128;
    }

    std.mem.copyForwards(u8, source_extended[(128 - source.len)..], source);

    var num = std.mem.readInt(u1024, &source_extended, .big);

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
            var buf: [2]u8 = undefined;
            try reader.readNoEof(&buf);
            const int = std.mem.readInt(u16, &buf, .little);

            return @intCast(int);
        },
        0xfe => {
            var buf: [4]u8 = undefined;
            try reader.readNoEof(&buf);
            const int = std.mem.readInt(u32, &buf, .little);

            return @intCast(int);
        },
        0xff => {
            var buf: [8]u8 = undefined;
            try reader.readNoEof(&buf);
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

pub fn readIntFromReader(comptime T: type, reader: anytype, endian: std.builtin.Endian) !T {
    var int_bytes: [@divExact(@typeInfo(T).Int.bits, 8)]u8 = undefined;
    try reader.readNoEof(&int_bytes);
    const int = std.mem.readInt(T, &int_bytes, endian);

    return int;
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
