const std = @import("std");
const constants = @import("constants.zig");
const utils = @import("utils.zig");
const FieldElement = @import("field_element.zig");
const ECPoint = @import("ec_point.zig");
const Signature = @import("signature.zig");

const assert = std.debug.assert;

const S256ECPoint = @This();

const p = constants.secp256k1_p;
const a = constants.secp256k1_a;
const b = constants.secp256k1_b;
const n = constants.secp256k1_n;
const gx = constants.secp256k1_gx;
const gy = constants.secp256k1_gy;

pub const G = S256ECPoint.init(gx, gy) catch unreachable;

inner: ECPoint,

fn initS256FieldElement(num: u256) !FieldElement {
    return FieldElement.init(num, p);
}

pub fn init(x: ?u256, y: ?u256) !S256ECPoint {
    const a_fe = try initS256FieldElement(a);
    const b_fe = try initS256FieldElement(b);

    if (x == null) {
        assert(x == null and y == null);
        return .{ .inner = try ECPoint.init(null, null, a_fe, b_fe) };
    }

    return .{ .inner = try ECPoint.init(try initS256FieldElement(x.?), try initS256FieldElement(y.?), a_fe, b_fe) };
}

pub fn toString(self: S256ECPoint, allocator: std.mem.Allocator) ![]u8 {
    return self.inner.toString(allocator);
}

pub fn eql(self: S256ECPoint, other: S256ECPoint) bool {
    return self.inner.eql(other.inner);
}

pub fn neql(self: S256ECPoint, other: S256ECPoint) bool {
    return self.inner.neql(other.inner);
}

pub fn atInfinity(self: S256ECPoint) bool {
    return self.inner.atInfinity();
}

pub fn add(self: S256ECPoint, other: S256ECPoint) S256ECPoint {
    return .{ .inner = self.inner.add(other.inner) };
}

pub fn rmul(self: S256ECPoint, coefficient: u256) S256ECPoint {
    const coef = @mod(coefficient, n);
    return .{ .inner = self.inner.rmul(coef) };
}

pub fn verify(self: S256ECPoint, z: u256, sig: Signature) bool {
    const s_inv = utils.mod_pow(sig.s, n - 2, n);

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
