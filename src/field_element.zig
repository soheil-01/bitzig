const std = @import("std");
const BigInt = std.math.big.int.Managed;

const FieldElement = @This();

pub const Error = error{ NumNotInFieldRange, DifferentFields };

allocator: std.mem.Allocator,
num: BigInt,
prime: BigInt,

pub fn init(allocator: std.mem.Allocator, num: anytype, prime: anytype) !FieldElement {
    const big_num = try BigInt.initSet(allocator, num);
    const big_prime = try BigInt.initSet(allocator, prime);

    if (big_num.order(big_prime) != .lt or !big_num.isPositive()) {
        return Error.NumNotInFieldRange;
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

pub fn eql(self: FieldElement, other: FieldElement) bool {
    return self.num.eql(other.num) and self.prime.eql(other.prime);
}

pub fn neql(self: FieldElement, other: FieldElement) bool {
    return !self.eql(other);
}

pub fn add(allocator: std.mem.Allocator, a: FieldElement, b: FieldElement) !FieldElement {
    if (!a.prime.eql(b.prime)) {
        return Error.DifferentFields;
    }

    var num = try BigInt.init(allocator);
    try num.add(&a.num, &b.num);
    try mod(allocator, &num, &num, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

pub fn sub(allocator: std.mem.Allocator, a: FieldElement, b: FieldElement) !FieldElement {
    if (!a.prime.eql(b.prime)) {
        return Error.DifferentFields;
    }

    var num = try BigInt.init(allocator);
    try num.sub(&a.num, &b.num);
    try mod(allocator, &num, &num, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

pub fn mul(allocator: std.mem.Allocator, a: FieldElement, b: FieldElement) !FieldElement {
    if (!a.prime.eql(b.prime)) {
        return Error.DifferentFields;
    }

    var num = try BigInt.init(allocator);
    try num.mul(&a.num, &b.num);
    try mod(allocator, &num, &num, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

pub fn pow(allocator: std.mem.Allocator, a: FieldElement, b: anytype) !FieldElement {
    var exponent = try BigInt.initSet(allocator, b);
    defer exponent.deinit();

    var tmp = try BigInt.initSet(allocator, 1);
    defer tmp.deinit();

    // tmp = prime - 1
    try tmp.sub(&a.prime, &tmp);

    // exponent = exponent % (prime - 1)
    try mod(allocator, &exponent, &exponent, &tmp);

    const num = try modularPow(allocator, &a.num, &exponent, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

pub fn div(allocator: std.mem.Allocator, a: FieldElement, b: FieldElement) !FieldElement {
    if (!a.prime.eql(b.prime)) {
        return Error.DifferentFields;
    }

    var exponent = try BigInt.initSet(allocator, 2);
    defer exponent.deinit();

    // exponent = prime - 2
    try exponent.sub(&b.prime, &exponent);

    // 1 / b = b ** (prime - 2)
    var r = try modularPow(allocator, &b.num, &exponent, &b.prime);
    defer r.deinit();

    var num = try BigInt.init(allocator);
    try num.mul(&a.num, &r);

    // num = a * 1/b % prime
    try mod(allocator, &num, &num, &a.prime);
    const prime = try a.prime.cloneWithDifferentAllocator(allocator);

    return FieldElement{ .allocator = allocator, .num = num, .prime = prime };
}

fn mod(allocator: std.mem.Allocator, rem: *BigInt, a: *const BigInt, b: *const BigInt) !void {
    var q = try BigInt.init(allocator);
    defer q.deinit();

    try BigInt.divFloor(&q, rem, a, b);
}

fn modularPow(allocator: std.mem.Allocator, base: *const BigInt, exponent: *const BigInt, modules: *const BigInt) !BigInt {
    var result = try BigInt.initSet(allocator, 1);

    var b = try base.cloneWithDifferentAllocator(allocator);
    defer b.deinit();

    var e = try exponent.cloneWithDifferentAllocator(allocator);
    defer e.deinit();

    while (e.isPositive() and !e.eqlZero()) : (try e.shiftRight(&e, 1)) {
        if (e.isOdd()) {
            try result.mul(&result, &b);
            try mod(allocator, &result, &result, modules);
        }

        try b.sqr(&b);
        try mod(allocator, &b, &b, modules);
    }

    return result;
}

const testing = std.testing;
const testing_alloc = testing.allocator;

test "FieldElement: equality" {
    var a = try FieldElement.init(testing_alloc, 2, 31);
    defer a.deinit();
    var b = try FieldElement.init(testing_alloc, 2, 31);
    defer b.deinit();
    var c = try FieldElement.init(testing_alloc, 15, 31);
    defer c.deinit();

    try testing.expect(a.eql(b));
    try testing.expect(!a.neql(b));
    try testing.expect(a.neql(c));
}

test "FieldElement: add" {
    var a1 = try FieldElement.init(testing_alloc, 2, 31);
    defer a1.deinit();
    var b1 = try FieldElement.init(testing_alloc, 15, 31);
    defer b1.deinit();
    var result1 = try FieldElement.add(testing_alloc, a1, b1);
    defer result1.deinit();
    var expected1 = try FieldElement.init(testing_alloc, 17, 31);
    defer expected1.deinit();
    try testing.expect(result1.eql(expected1));

    var a2 = try FieldElement.init(testing_alloc, 17, 31);
    defer a2.deinit();
    var b2 = try FieldElement.init(testing_alloc, 21, 31);
    defer b2.deinit();
    var result2 = try FieldElement.add(testing_alloc, a2, b2);
    defer result2.deinit();
    var expected2 = try FieldElement.init(testing_alloc, 7, 31);
    defer expected2.deinit();
    try testing.expect(result2.eql(expected2));
}

test "FieldElement: sub" {
    var a1 = try FieldElement.init(testing_alloc, 29, 31);
    defer a1.deinit();
    var b1 = try FieldElement.init(testing_alloc, 4, 31);
    defer b1.deinit();
    var result1 = try FieldElement.sub(testing_alloc, a1, b1);
    defer result1.deinit();
    var expected1 = try FieldElement.init(testing_alloc, 25, 31);
    defer expected1.deinit();
    try testing.expect(result1.eql(expected1));

    var a2 = try FieldElement.init(testing_alloc, 15, 31);
    defer a2.deinit();
    var b2 = try FieldElement.init(testing_alloc, 30, 31);
    defer b2.deinit();
    var result2 = try FieldElement.sub(testing_alloc, a2, b2);
    defer result2.deinit();
    var expected2 = try FieldElement.init(testing_alloc, 16, 31);
    defer expected2.deinit();
    try testing.expect(result2.eql(expected2));
}

test "FieldElement: mul" {
    var a = try FieldElement.init(testing_alloc, 24, 31);
    defer a.deinit();
    var b = try FieldElement.init(testing_alloc, 19, 31);
    defer b.deinit();

    var result = try FieldElement.mul(testing_alloc, a, b);
    defer result.deinit();

    var expected = try FieldElement.init(testing_alloc, 22, 31);
    defer expected.deinit();

    try testing.expect(result.eql(expected));
}

test "FieldElement: pow" {
    var a1 = try FieldElement.init(testing_alloc, 17, 31);
    defer a1.deinit();
    var result1 = try FieldElement.pow(testing_alloc, a1, 3);
    defer result1.deinit();
    var expected1 = try FieldElement.init(testing_alloc, 15, 31);
    defer expected1.deinit();
    try testing.expect(result1.eql(expected1));

    var a2 = try FieldElement.init(testing_alloc, 5, 31);
    defer a2.deinit();
    var b2 = try FieldElement.init(testing_alloc, 18, 31);
    defer b2.deinit();
    var c2 = try FieldElement.pow(testing_alloc, a2, 5);
    defer c2.deinit();
    var result2 = try FieldElement.mul(testing_alloc, b2, c2);
    defer result2.deinit();
    var expected2 = try FieldElement.init(testing_alloc, 16, 31);
    defer expected2.deinit();
    try testing.expect(result2.eql(expected2));
}

test "FieldElement: div" {
    var a1 = try FieldElement.init(testing_alloc, 3, 31);
    defer a1.deinit();
    var b1 = try FieldElement.init(testing_alloc, 24, 31);
    defer b1.deinit();
    var result1 = try FieldElement.div(testing_alloc, a1, b1);
    defer result1.deinit();
    var expected1 = try FieldElement.init(testing_alloc, 4, 31);
    defer expected1.deinit();
    try testing.expect(result1.eql(expected1));

    var a2 = try FieldElement.init(testing_alloc, 17, 31);
    defer a2.deinit();
    var result2 = try FieldElement.pow(testing_alloc, a2, -3);
    defer result2.deinit();
    var expected2 = try FieldElement.init(testing_alloc, 29, 31);
    defer expected2.deinit();
    try testing.expect(result2.eql(expected2));

    var a3 = try FieldElement.init(testing_alloc, 4, 31);
    defer a3.deinit();
    var b3 = try FieldElement.init(testing_alloc, 11, 31);
    defer b3.deinit();
    var tmp = try FieldElement.pow(testing_alloc, a3, -4);
    defer tmp.deinit();
    var result3 = try FieldElement.mul(testing_alloc, tmp, b3);
    defer result3.deinit();
    var expected3 = try FieldElement.init(testing_alloc, 13, 31);
    defer expected3.deinit();
    try testing.expect(result3.eql(expected3));
}
