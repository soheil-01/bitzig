const std = @import("std");
const c = @cImport({
    @cInclude("ripemd160.h");
});

const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn mod_pow(a: u256, b: u256, mod: u256) u256 {
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

pub fn encode_base58(dest: []u8, source: []const u8) usize {
    assert(source.len <= 128);
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
        dest[i] = alphabet[@intCast(num % 58)];
    }

    for (source) |ch| {
        if (ch == 0) {
            assert(i > 0);
            i -= 1;
            dest[i] = alphabet[0];
        } else break;
    }

    return i;
}

pub fn ripemd160(msg: [:0]const u8) [20]u8 {
    var hash: [20]u8 = undefined;
    c.ripemd160(&msg, msg.len, &hash);

    return hash;
}
