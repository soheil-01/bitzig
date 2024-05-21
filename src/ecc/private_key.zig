const std = @import("std");
const constants = @import("constants.zig");
const utils = @import("utils.zig");
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
    return std.fmt.allocPrint(allocator, "{x}", .{self.secret});
}

pub fn sign(self: PrivateKey, z: u256) Signature {
    const k = self.deterministic_k(z);
    const r = G.rmul(k).inner.x.?.num;
    const k_inv = utils.mod_pow(k, n - 2, n);

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

pub fn deterministic_k(self: PrivateKey, z: u256) u256 {
    var z_var = z;
    var k = [_]u8{0} ** 32;
    var v = [_]u8{1} ** 32;

    if (z_var > n) {
        z_var -= n;
    }

    var z_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &z_bytes, z_var, .big);

    var secret_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &secret_bytes, self.secret, .big);

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

const testing = std.testing;

test "PrivateKey: sign and verify" {
    const rand = std.crypto.random;
    const secret = @mod(rand.int(u256), n);
    const pk = PrivateKey.init(secret);
    const z = rand.int(u256);
    const sig = pk.sign(z);

    try testing.expect(pk.point.verify(z, sig));
}
