const std = @import("std");
const constants = @import("constants.zig");
const utils = @import("../utils.zig");
const FieldElement = @import("field_element.zig");
const Point = @import("point.zig");
const Signature = @import("signature.zig");

const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const S256Point = @This();

const p = constants.secp256k1_p;
const a = constants.secp256k1_a;
const b = constants.secp256k1_b;
const n = constants.secp256k1_n;
const gx = constants.secp256k1_gx;
const gy = constants.secp256k1_gy;

pub const G = S256Point.init(gx, gy) catch unreachable;
pub const Error = error{InvalidEncoding} || Point.Error || FieldElement.Error;

inner: Point,

fn initS256Field(num: u256) !FieldElement {
    return FieldElement.init(num, p);
}

pub fn init(x: ?u256, y: ?u256) !S256Point {
    const a_fe = try initS256Field(a);
    const b_fe = try initS256Field(b);

    if (x == null) {
        assert(x == null and y == null);
        return .{ .inner = try Point.init(null, null, a_fe, b_fe) };
    }

    return .{ .inner = try Point.init(try initS256Field(x.?), try initS256Field(y.?), a_fe, b_fe) };
}

pub fn toString(self: S256Point, allocator: std.mem.Allocator) ![]u8 {
    return self.inner.toString(allocator);
}

pub fn eql(self: S256Point, other: S256Point) bool {
    return self.inner.eql(other.inner);
}

pub fn neql(self: S256Point, other: S256Point) bool {
    return self.inner.neql(other.inner);
}

pub fn atInfinity(self: S256Point) bool {
    return self.inner.atInfinity();
}

pub fn add(self: S256Point, other: S256Point) S256Point {
    return .{ .inner = self.inner.add(other.inner) };
}

pub fn rmul(self: S256Point, coefficient: u256) S256Point {
    const coef = @mod(coefficient, n);
    return .{ .inner = self.inner.rmul(coef) };
}

pub fn verify(self: S256Point, z: u256, sig: Signature) bool {
    const s_inv = utils.modPow(sig.s, n - 2, n);

    const u: u256 = blk: {
        var tmp: u512 = z;
        tmp = @mod(tmp * s_inv, n);
        break :blk @intCast(tmp);
    };

    const v: u256 = blk: {
        var tmp: u512 = sig.r;
        tmp = @mod(tmp * s_inv, n);
        break :blk @intCast(tmp);
    };

    const total = G.rmul(u).add(self.rmul(v));

    return total.inner.x.?.num == sig.r;
}

pub fn toUncompressedSec(self: S256Point) [65]u8 {
    assert(self.inner.x != null and self.inner.y != null);

    var out: [65]u8 = undefined;
    out[0] = 4;
    out[1..33].* = utils.encodeInt(u256, self.inner.x.?.num, .big);
    out[33..65].* = utils.encodeInt(u256, self.inner.y.?.num, .big);

    return out;
}

pub fn toCompressedSec(self: S256Point) [33]u8 {
    assert(self.inner.x != null and self.inner.y != null);

    var out: [33]u8 = undefined;
    out[0] = if (self.inner.y.?.isOdd()) 3 else 2;
    out[1..].* = utils.encodeInt(u256, self.inner.x.?.num, .big);

    return out;
}

pub fn fromSec(s: []const u8) !S256Point {
    if (s.len < 1) {
        return Error.InvalidEncoding;
    }

    const encoding_type = s[0];

    switch (encoding_type) {
        4 => {
            if (s.len != 65) {
                return Error.InvalidEncoding;
            }

            const x = std.mem.readInt(u256, s[1..33], .big);
            const y = std.mem.readInt(u256, s[33..65], .big);

            return init(x, y);
        },
        2, 3 => {
            if (s.len != 33) {
                return Error.InvalidEncoding;
            }

            const x = try initS256Field(std.mem.readInt(u256, s[1..33], .big));

            // y ** 2 = x ** 3 + 7
            const y_squared = x.pow(3).add(try initS256Field(b));
            const y = utils.modPow(y_squared.num, (p + 1) / 4, p);

            var even_y: u256 = undefined;
            var odd_y: u256 = undefined;

            if (y & 1 == 1) {
                odd_y = y;
                even_y = p - y;
            } else {
                odd_y = p - y;
                even_y = y;
            }

            if (encoding_type == 2) {
                return S256Point.init(x.num, even_y);
            }
            return S256Point.init(x.num, odd_y);
        },
        else => {
            return Error.InvalidEncoding;
        },
    }
}

pub fn address(self: S256Point, dest: []u8, compressed: bool, testnet: bool) []u8 {
    const sec: []const u8 = if (compressed) &self.toCompressedSec() else &self.toUncompressedSec();

    var hash160: [21]u8 = undefined;
    hash160[1..].* = utils.hash160(sec);
    hash160[0] = if (testnet) 0x6f else 0x00;

    return utils.encodeBase58Checksum(dest, hash160.len, hash160);
}

const testing = std.testing;

test "S256Point: order" {
    const point = G.rmul(n);
    try testing.expect(point.atInfinity());
}

test "S256Point: pubpoint" {
    const points = .{
        .{ .secret = 7, .x = 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc, .y = 0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da },
        .{ .secret = 1485, .x = 0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda, .y = 0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55 },
        .{ .secret = std.math.pow(u256, 2, 128), .x = 0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da, .y = 0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82 },
        .{ .secret = std.math.pow(u256, 2, 240) + std.math.pow(u256, 2, 31), .x = 0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116, .y = 0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053 },
    };

    inline for (points) |point| {
        const result = try S256Point.init(point.x, point.y);
        const expected = G.rmul(point.secret);
        try testing.expect(result.eql(expected));
    }
}

test "S256Point: verify" {
    const point = try S256Point.init(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c, 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34);
    {
        const z = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60;
        const r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395;
        const s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4;
        const sig = Signature.init(r, s);
        try testing.expect(point.verify(z, sig));
    }

    {
        const z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d;
        const r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c;
        const s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6;
        const sig = Signature.init(r, s);
        try testing.expect(point.verify(z, sig));
    }
}

test "S256Point: sec" {
    {
        const coef = std.math.pow(u256, 999, 3);
        const uncompressed = [_]u8{ 4, 157, 92, 164, 150, 112, 203, 228, 195, 191, 168, 76, 150, 168, 200, 125, 240, 134, 198, 234, 106, 36, 186, 107, 128, 156, 157, 226, 52, 73, 104, 8, 213, 111, 161, 92, 199, 243, 211, 140, 218, 152, 222, 226, 65, 159, 65, 91, 117, 19, 221, 225, 48, 31, 134, 67, 205, 146, 69, 174, 167, 243, 249, 17, 249 };
        const compressed = [_]u8{ 3, 157, 92, 164, 150, 112, 203, 228, 195, 191, 168, 76, 150, 168, 200, 125, 240, 134, 198, 234, 106, 36, 186, 107, 128, 156, 157, 226, 52, 73, 104, 8, 213 };
        const point = G.rmul(coef);

        try testing.expectEqualStrings(&uncompressed, &point.toUncompressedSec());
        try testing.expectEqualStrings(&compressed, &point.toCompressedSec());
    }

    {
        const coef = 123;
        const uncompressed = [_]u8{ 4, 165, 152, 168, 3, 13, 166, 216, 108, 107, 199, 242, 245, 20, 78, 165, 73, 210, 130, 17, 234, 88, 250, 167, 14, 191, 76, 30, 102, 92, 31, 233, 181, 32, 75, 93, 111, 132, 130, 44, 48, 126, 75, 74, 113, 64, 115, 122, 236, 35, 252, 99, 182, 91, 53, 248, 106, 16, 2, 109, 189, 45, 134, 78, 107 };
        const compressed = [_]u8{ 3, 165, 152, 168, 3, 13, 166, 216, 108, 107, 199, 242, 245, 20, 78, 165, 73, 210, 130, 17, 234, 88, 250, 167, 14, 191, 76, 30, 102, 92, 31, 233, 181 };
        const point = G.rmul(coef);

        try testing.expectEqualStrings(&uncompressed, &point.toUncompressedSec());
        try testing.expectEqualStrings(&compressed, &point.toCompressedSec());
    }

    {
        const coef = 42424242;
        const uncompressed = [_]u8{ 4, 174, 226, 231, 216, 67, 247, 67, 0, 151, 133, 158, 43, 198, 3, 171, 204, 50, 116, 255, 129, 105, 193, 164, 105, 254, 224, 242, 6, 20, 6, 111, 142, 33, 236, 83, 244, 14, 250, 196, 122, 193, 197, 33, 27, 33, 35, 82, 126, 14, 155, 87, 237, 231, 144, 196, 218, 30, 114, 201, 31, 183, 218, 84, 163 };
        const compressed = [_]u8{ 3, 174, 226, 231, 216, 67, 247, 67, 0, 151, 133, 158, 43, 198, 3, 171, 204, 50, 116, 255, 129, 105, 193, 164, 105, 254, 224, 242, 6, 20, 6, 111, 142 };
        const point = G.rmul(coef);

        try testing.expectEqualStrings(&uncompressed, &point.toUncompressedSec());
        try testing.expectEqualStrings(&compressed, &point.toCompressedSec());
    }
}

test "S256Point: address" {
    {
        const secret: u256 = 888 * 888 * 888;
        const mainnet_address = "148dY81A9BmdpMhvYEVznrM45kWN32vSCN";
        const testnet_address = "mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP";
        const point = G.rmul(secret);

        var buf: [34]u8 = undefined;
        var addr = point.address(&buf, true, false);
        try testing.expectEqualStrings(mainnet_address, addr);

        addr = point.address(&buf, true, true);
        try testing.expectEqualStrings(testnet_address, addr);
    }

    {
        const secret: u256 = 321;
        const mainnet_address = "1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj";
        const testnet_address = "mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP";
        const point = G.rmul(secret);

        var buf: [34]u8 = undefined;
        var addr = point.address(&buf, false, false);
        try testing.expectEqualStrings(mainnet_address, addr);

        addr = point.address(&buf, false, true);
        try testing.expectEqualStrings(testnet_address, addr);
    }

    {
        const secret: u256 = 4242424242;
        const mainnet_address = "1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb";
        const testnet_address = "mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s";
        const point = G.rmul(secret);

        var buf: [34]u8 = undefined;
        var addr = point.address(&buf, false, false);
        try testing.expectEqualStrings(mainnet_address, addr);

        addr = point.address(&buf, false, true);
        try testing.expectEqualStrings(testnet_address, addr);
    }
}
