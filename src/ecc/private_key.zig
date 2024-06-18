const std = @import("std");
const constants = @import("constants.zig");
const utils = @import("../utils.zig");
const S256Point = @import("s256_point.zig");
const Signature = @import("signature.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const PrivateKey = @This();

const n = constants.secp256k1_n;
const G = S256Point.G;

secret: u256,
point: S256Point,

pub fn init(secret: u256) PrivateKey {
    return .{ .secret = secret, .point = G.rmul(secret) };
}

pub fn toString(self: PrivateKey, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "0x{x}", .{self.secret});
}

pub fn sign(self: PrivateKey, z: u256) Signature {
    const k = self.deterministicK(z);
    const r = G.rmul(k).inner.x.?.num;
    const k_inv = utils.modPow(k, n - 2, n);

    var s: u256 = blk: {
        var tmp: u512 = self.secret;
        tmp = @mod(tmp * r, n);
        tmp = @mod(tmp + z, n);
        tmp = @mod(tmp * k_inv, n);

        break :blk @intCast(tmp);
    };

    if (s > n / 2) {
        s = n - s;
    }

    return Signature.init(r, s);
}

pub fn deterministicK(self: PrivateKey, z: u256) u256 {
    var z_var = z;
    var k = [_]u8{0} ** 32;
    var v = [_]u8{1} ** 32;

    if (z_var > n) {
        z_var -= n;
    }

    const z_bytes = utils.encodeInt(u256, z_var, .big);

    const secret_bytes = utils.encodeInt(u256, self.secret, .big);

    var msg = v ++ [_]u8{0} ++ secret_bytes ++ z_bytes;
    HmacSha256.create(&k, &msg, &k);

    HmacSha256.create(&v, &v, &k);

    msg = v ++ [_]u8{1} ++ secret_bytes ++ z_bytes;
    HmacSha256.create(&k, &msg, &k);

    HmacSha256.create(&v, &v, &k);

    while (true) {
        HmacSha256.create(&v, &v, &k);
        const candidate = std.mem.readInt(u256, &v, .big);
        if (candidate >= 1 and candidate < n) {
            return candidate;
        }

        const tmp_msg = v ++ [_]u8{0};
        HmacSha256.create(&k, &tmp_msg, &k);
        HmacSha256.create(&v, &v, &k);
    }
}

pub fn toUncompressedWif(self: PrivateKey, dest: []u8, testnet: bool) []u8 {
    const secret_bytes = utils.encodeInt(u256, self.secret, .big);
    const prefix: u8 = if (testnet) 0xef else 0x80;

    return utils.encodeBase58Checksum(dest, secret_bytes.len + 1, [_]u8{prefix} ++ secret_bytes);
}

pub fn toCompressedWif(self: PrivateKey, dest: []u8, testnet: bool) []u8 {
    const secret_bytes = utils.encodeInt(u256, self.secret, .big);

    const prefix: u8 = if (testnet) 0xef else 0x80;
    const suffix = 0x01;

    return utils.encodeBase58Checksum(dest, secret_bytes.len + 2, [_]u8{prefix} ++ secret_bytes ++ [_]u8{suffix});
}

const testing = std.testing;

test "PrivateKey: sign and verify" {
    const rand = std.crypto.random;
    const secret = @mod(rand.int(u256), n);
    const pk = PrivateKey.init(secret);
    const z = rand.int(u256);
    const sig = pk.sign(z);

    try testing.expect(pk.point.verify(z, sig));
}

test "PrivateKey: wif" {
    var wif_buffer: [53]u8 = undefined;

    {
        const secret: u256 = @intCast(std.math.pow(u257, 2, 256) - std.math.pow(u256, 2, 199));
        const pk = PrivateKey.init(secret);
        const expected = "L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC";
        const wif = pk.toCompressedWif(&wif_buffer, false);
        try testing.expectEqualStrings(expected, wif);
    }

    {
        const secret: u256 = @intCast(std.math.pow(u257, 2, 256) - std.math.pow(u256, 2, 201));
        const pk = PrivateKey.init(secret);
        const expected = "93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn";
        const wif = pk.toUncompressedWif(&wif_buffer, true);
        try testing.expectEqualStrings(expected, wif);
    }

    {
        const secret: u256 = 0x0dba685b4511dbd3d368e5c4358a1277de9486447af7b3604a69b8d9d8b7889d;
        const pk = PrivateKey.init(secret);
        const expected = "5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty";
        const wif = pk.toUncompressedWif(&wif_buffer, false);
        try testing.expectEqualStrings(expected, wif);
    }

    {
        const secret: u256 = 0x1cca23de92fd1862fb5b76e5f4f50eb082165e5191e116c18ed1a6b24be6a53f;
        const pk = PrivateKey.init(secret);
        const expected = "cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg";
        const wif = pk.toCompressedWif(&wif_buffer, true);
        try testing.expectEqualStrings(expected, wif);
    }
}
