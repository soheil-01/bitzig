const std = @import("std");
const utils = @import("../utils.zig");

const assert = std.debug.assert;

const FieldElement = @This();

pub const Error = error{NumNotInFieldRange};

num: u256,
prime: u256,

pub fn init(num: u256, prime: u256) !FieldElement {
    // 0 < num < prime
    if (num >= prime) {
        return Error.NumNotInFieldRange;
    }

    return .{ .num = num, .prime = prime };
}

pub fn toString(self: FieldElement, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "FieldElement_{d}({d})", .{ self.prime, self.num });
}

pub fn eql(self: FieldElement, other: FieldElement) bool {
    return self.num == other.num and self.prime == other.prime;
}

pub fn neql(self: FieldElement, other: FieldElement) bool {
    return !self.eql(other);
}

pub fn eqlZero(self: FieldElement) bool {
    return self.num == 0;
}

pub fn add(a: FieldElement, b: FieldElement) FieldElement {
    assert(a.prime == b.prime);

    var num: u257 = a.num;
    num += b.num;
    num = @mod(num, a.prime);

    return FieldElement{ .num = @intCast(num), .prime = a.prime };
}

pub fn sub(a: FieldElement, b: FieldElement) FieldElement {
    assert(a.prime == b.prime);

    if (a.num >= b.num) {
        const num = @mod(a.num - b.num, a.prime);
        return FieldElement{ .num = num, .prime = a.prime };
    }

    var num: u257 = a.num;
    num += a.prime;
    num -= b.num;
    return FieldElement{ .num = @intCast(num), .prime = a.prime };
}

pub fn mul(a: FieldElement, b: FieldElement) FieldElement {
    assert(a.prime == b.prime);

    var num: u512 = a.num;
    num *= b.num;
    num = @mod(num, a.prime);

    return FieldElement{ .num = @intCast(num), .prime = a.prime };
}

pub fn rmul(a: FieldElement, b: u256) FieldElement {
    const scalar = FieldElement{ .num = b, .prime = a.prime };

    return a.mul(scalar);
}

pub fn pow(a: FieldElement, b: u256) FieldElement {
    var exponent = b;
    exponent = @mod(exponent, a.prime - 1);

    const num = utils.modPow(a.num, exponent, a.prime);

    return FieldElement{ .num = num, .prime = a.prime };
}

pub fn div(a: FieldElement, b: FieldElement) FieldElement {
    assert(a.prime == b.prime);

    // 1 / b
    const b_inverse = b.inverse();

    return a.mul(b_inverse);
}

pub fn inverse(self: FieldElement) FieldElement {
    // 1 / num = num ** (prime - 2)
    return self.pow(self.prime - 2);
}

pub fn isOdd(self: FieldElement) bool {
    return self.num & 1 == 1;
}

const expect = std.testing.expect;

test "FieldElement: equality" {
    const a = try FieldElement.init(2, 31);
    const b = try FieldElement.init(2, 31);
    const c = try FieldElement.init(15, 31);

    try expect(a.eql(b));
    try expect(!a.neql(b));
    try expect(a.neql(c));
}

test "FieldElement: add" {
    {
        const a = try FieldElement.init(2, 31);
        const b = try FieldElement.init(15, 31);
        const result = a.add(b);
        const expected = try FieldElement.init(17, 31);
        try expect(result.eql(expected));
    }

    {
        const a = try FieldElement.init(17, 31);
        const b = try FieldElement.init(21, 31);
        const result = a.add(b);
        const expected = try FieldElement.init(7, 31);
        try expect(result.eql(expected));
    }
}

test "FieldElement: sub" {
    {
        const a = try FieldElement.init(29, 31);
        const b = try FieldElement.init(4, 31);
        const result = a.sub(b);
        const expected = try FieldElement.init(25, 31);
        try expect(result.eql(expected));
    }

    {
        const a = try FieldElement.init(15, 31);
        const b = try FieldElement.init(30, 31);
        const result = a.sub(b);
        const expected = try FieldElement.init(16, 31);
        try expect(result.eql(expected));
    }
}

test "FieldElement: mul" {
    const a = try FieldElement.init(24, 31);
    const b = try FieldElement.init(19, 31);

    const result = a.mul(b);
    const expected = try FieldElement.init(22, 31);

    try expect(result.eql(expected));
}

test "FieldElement: rmul" {
    const a = try FieldElement.init(17, 31);
    const result = a.rmul(4);
    const expected = try FieldElement.init(6, 31);

    try expect(result.eql(expected));
}

test "FieldElement: pow" {
    {
        const a = try FieldElement.init(17, 31);
        const result = a.pow(3);
        const expected = try FieldElement.init(15, 31);
        try expect(result.eql(expected));
    }

    {
        const a = try FieldElement.init(5, 31);
        const b = try FieldElement.init(18, 31);
        const c = a.pow(5);
        const result = b.mul(c);
        const expected = try FieldElement.init(16, 31);
        try expect(result.eql(expected));
    }
}

test "FieldElement: div" {
    const a = try FieldElement.init(3, 31);
    const b = try FieldElement.init(24, 31);
    const result = a.div(b);
    const expected = try FieldElement.init(4, 31);
    try expect(result.eql(expected));
}
