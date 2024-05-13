const std = @import("std");
const BigInt = std.math.big.int.Managed;

const FieldElement = @This();

allocator: std.mem.Allocator,
num: BigInt,
prime: BigInt,

pub fn init(allocator: std.mem.Allocator, num: anytype, prime: anytype) !FieldElement {
    const big_num = try BigInt.initSet(allocator, num);
    const big_prime = try BigInt.initSet(allocator, prime);

    if (big_num.order(big_prime) != .lt or !big_num.isPositive()) {
        return error.NumNotInFieldRange;
    }

    return .{ .allocator = allocator, .num = big_num, .prime = big_prime };
}

pub fn deinit(self: *FieldElement) void {
    self.num.deinit();
    self.prime.deinit();
}

pub fn toString(self: FieldElement) ![]u8 {
    const num_str = try self.num.toString(self.allocator, 10, .lower);
    defer self.allocator.free(num_str);

    const prime_str = try self.prime.toString(self.allocator, 10, .lower);
    defer self.allocator.free(prime_str);

    return std.fmt.allocPrint(self.allocator, "FieldElement_{s}({s})", .{ prime_str, num_str });
}

pub fn eql(self: FieldElement, other: ?FieldElement) bool {
    if (other) |value| {
        return self.num.eql(value.num) and self.prime.eql(value.prime);
    }

    return false;
}

pub fn neql(self: FieldElement, other: ?FieldElement) bool {
    return !self.eql(other);
}

pub fn add(allocator: std.mem.Allocator, a: FieldElement, b: FieldElement) !FieldElement {
    if (!a.prime.eql(b.prime)) {
        return error.DifferentFields;
    }

    var sum = try BigInt.init(allocator);
    try sum.add(&a.num, &b.num);
    defer sum.deinit();

    const num = try mod(allocator, &sum, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

pub fn sub(allocator: std.mem.Allocator, a: FieldElement, b: FieldElement) !FieldElement {
    if (!a.prime.eql(b.prime)) {
        return error.DifferentFields;
    }

    var diff = try BigInt.init(allocator);
    try diff.sub(&a.num, &b.num);
    defer diff.deinit();

    const num = try mod(allocator, &diff, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

pub fn mul(allocator: std.mem.Allocator, a: FieldElement, b: FieldElement) !FieldElement {
    if (!a.prime.eql(b.prime)) {
        return error.DifferentFields;
    }

    var product = try BigInt.init(allocator);
    try product.mul(&a.num, &b.num);
    defer product.deinit();

    const num = try mod(allocator, &product, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

pub fn pow(allocator: std.mem.Allocator, a: FieldElement, b: anytype) !FieldElement {
    var exponent = try BigInt.initSet(allocator, b);
    defer exponent.deinit();

    var tmp = try BigInt.initSet(allocator, 1);
    defer tmp.deinit();

    try tmp.sub(&a.prime, &tmp);

    // exponent % prime - 1
    var n = try mod(allocator, &exponent, &tmp);
    defer n.deinit();

    const num = try modularPow(allocator, &a.num, &n, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

pub fn div(allocator: std.mem.Allocator, a: FieldElement, b: FieldElement) !FieldElement {
    if (!a.prime.eql(b.prime)) {
        return error.DifferentFields;
    }

    var exponent = try BigInt.initSet(allocator, 2);
    defer exponent.deinit();

    // exponent = prime - 2
    try exponent.sub(&b.prime, &exponent);

    // 1 / b = b ** (prime - 2)
    var r = try modularPow(allocator, &b.num, &exponent, &b.prime);
    defer r.deinit();

    var tmp = try BigInt.init(allocator);
    defer tmp.deinit();
    try tmp.mul(&a.num, &r);

    // num = a * 1/b % prime
    const num = try mod(allocator, &tmp, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

fn mod(allocator: std.mem.Allocator, a: *const BigInt, b: *const BigInt) !BigInt {
    var q = try BigInt.init(allocator);
    defer q.deinit();
    var rem = try BigInt.init(allocator);

    try BigInt.divFloor(&q, &rem, a, b);

    return rem;
}

fn modularPow(allocator: std.mem.Allocator, base: *const BigInt, exponent: *const BigInt, modules: *const BigInt) !BigInt {
    var result = try BigInt.initSet(allocator, 1);

    var b = try base.cloneWithDifferentAllocator(allocator);
    defer b.deinit();

    var e = try exponent.cloneWithDifferentAllocator(allocator);
    defer e.deinit();

    while (e.isPositive() and !e.eqlZero()) : (try e.shiftRight(&e, 1)) {
        if (e.isOdd()) {
            var tmp = try BigInt.init(allocator);
            try tmp.mul(&result, &b);
            defer tmp.deinit();

            result.deinit();
            result = try mod(allocator, &tmp, modules);
        }

        var tmp = try BigInt.init(allocator);
        try tmp.mul(&b, &b);
        defer tmp.deinit();

        b.deinit();
        b = try mod(allocator, &tmp, modules);
    }

    return result;
}

const testing = std.testing;

test "FieldElement: equality" {
    const allocator = testing.allocator;

    var a = try FieldElement.init(allocator, 2, 31);
    defer a.deinit();
    var b = try FieldElement.init(allocator, 2, 31);
    defer b.deinit();
    var c = try FieldElement.init(allocator, 15, 31);
    defer c.deinit();

    try testing.expect(a.eql(b));
    try testing.expect(!a.neql(b));
    try testing.expect(a.neql(null));
    try testing.expect(a.neql(c));
}

test "FieldElement: add" {
    const allocator = testing.allocator;

    var a1 = try FieldElement.init(allocator, 2, 31);
    defer a1.deinit();
    var b1 = try FieldElement.init(allocator, 15, 31);
    defer b1.deinit();
    var result1 = try FieldElement.add(allocator, a1, b1);
    defer result1.deinit();
    var expected1 = try FieldElement.init(allocator, 17, 31);
    defer expected1.deinit();
    try testing.expect(result1.eql(expected1));

    var a2 = try FieldElement.init(allocator, 17, 31);
    defer a2.deinit();
    var b2 = try FieldElement.init(allocator, 21, 31);
    defer b2.deinit();
    var result2 = try FieldElement.add(allocator, a2, b2);
    defer result2.deinit();
    var expected2 = try FieldElement.init(allocator, 7, 31);
    defer expected2.deinit();
    try testing.expect(result2.eql(expected2));
}

test "FieldElement: sub" {
    const allocator = testing.allocator;

    var a1 = try FieldElement.init(allocator, 29, 31);
    defer a1.deinit();
    var b1 = try FieldElement.init(allocator, 4, 31);
    defer b1.deinit();
    var result1 = try FieldElement.sub(allocator, a1, b1);
    defer result1.deinit();
    var expected1 = try FieldElement.init(allocator, 25, 31);
    defer expected1.deinit();
    try testing.expect(result1.eql(expected1));

    var a2 = try FieldElement.init(allocator, 15, 31);
    defer a2.deinit();
    var b2 = try FieldElement.init(allocator, 30, 31);
    defer b2.deinit();
    var result2 = try FieldElement.sub(allocator, a2, b2);
    defer result2.deinit();
    var expected2 = try FieldElement.init(allocator, 16, 31);
    defer expected2.deinit();
    try testing.expect(result2.eql(expected2));
}

test "FieldElement: mul" {
    const allocator = testing.allocator;

    var a = try FieldElement.init(allocator, 24, 31);
    defer a.deinit();
    var b = try FieldElement.init(allocator, 19, 31);
    defer b.deinit();

    var result = try FieldElement.mul(allocator, a, b);
    defer result.deinit();

    var expected = try FieldElement.init(allocator, 22, 31);
    defer expected.deinit();

    try testing.expect(result.eql(expected));
}

test "FieldElement: pow" {
    const allocator = testing.allocator;

    var a1 = try FieldElement.init(allocator, 17, 31);
    defer a1.deinit();
    var result1 = try FieldElement.pow(allocator, a1, 3);
    defer result1.deinit();
    var expected1 = try FieldElement.init(allocator, 15, 31);
    defer expected1.deinit();
    try testing.expect(result1.eql(expected1));

    var a2 = try FieldElement.init(allocator, 5, 31);
    defer a2.deinit();
    var b2 = try FieldElement.init(allocator, 18, 31);
    defer b2.deinit();
    var c2 = try FieldElement.pow(allocator, a2, 5);
    defer c2.deinit();
    var result2 = try FieldElement.mul(allocator, b2, c2);
    defer result2.deinit();
    var expected2 = try FieldElement.init(allocator, 16, 31);
    defer expected2.deinit();
    try testing.expect(result2.eql(expected2));
}

test "FieldElement: div" {
    const allocator = testing.allocator;

    var a1 = try FieldElement.init(allocator, 3, 31);
    defer a1.deinit();
    var b1 = try FieldElement.init(allocator, 24, 31);
    defer b1.deinit();
    var result1 = try FieldElement.div(allocator, a1, b1);
    defer result1.deinit();
    var expected1 = try FieldElement.init(allocator, 4, 31);
    defer expected1.deinit();
    try testing.expect(result1.eql(expected1));

    var a2 = try FieldElement.init(allocator, 17, 31);
    defer a2.deinit();
    var result2 = try FieldElement.pow(allocator, a2, -3);
    defer result2.deinit();
    var expected2 = try FieldElement.init(allocator, 29, 31);
    defer expected2.deinit();
    try testing.expect(result2.eql(expected2));

    var a3 = try FieldElement.init(allocator, 4, 31);
    defer a3.deinit();
    var b3 = try FieldElement.init(allocator, 11, 31);
    defer b3.deinit();
    var tmp = try FieldElement.pow(allocator, a3, -4);
    defer tmp.deinit();
    var result3 = try FieldElement.mul(allocator, tmp, b3);
    defer result3.deinit();
    var expected3 = try FieldElement.init(allocator, 13, 31);
    defer expected3.deinit();
    try testing.expect(result3.eql(expected3));
}
