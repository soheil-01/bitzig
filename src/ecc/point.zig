const std = @import("std");
const FieldElement = @import("field_element.zig");
const assert = std.debug.assert;

const Point = @This();

pub const Error = error{NotOnTheCurve};

x: ?FieldElement,
y: ?FieldElement,
a: FieldElement,
b: FieldElement,

pub fn init(x: ?FieldElement, y: ?FieldElement, a: FieldElement, b: FieldElement) !Point {
    if (x == null or y == null) {
        assert(x == null and y == null);
    } else {
        const left_side = y.?.pow(2);
        const right_side = x.?.pow(3).add(a.mul(x.?)).add(b);

        if (left_side.neql(right_side)) {
            return Error.NotOnTheCurve;
        }
    }

    return .{ .x = x, .y = y, .a = a, .b = b };
}

pub fn toString(self: Point, allocator: std.mem.Allocator) ![]u8 {
    if (self.x == null) {
        return std.fmt.allocPrint(allocator, "Point(infinity)", .{});
    }

    const x_string = try self.x.?.toString(allocator);
    defer allocator.free(x_string);

    const y_string = try self.y.?.toString(allocator);
    defer allocator.free(y_string);

    const a_string = try self.a.toString(allocator);
    defer allocator.free(a_string);

    const b_string = try self.b.toString(allocator);
    defer allocator.free(b_string);

    return std.fmt.allocPrint(allocator, "Point({s},{s})_{s}_{s}", .{ x_string, y_string, a_string, b_string });
}

pub fn eql(self: Point, other: Point) bool {
    if (self.x == null) {
        return other.x == null;
    }

    return self.x.?.eql(other.x.?) and self.y.?.eql(other.y.?) and self.a.eql(other.a) and self.b.eql(other.b);
}

pub fn neql(self: Point, other: Point) bool {
    return !self.eql(other);
}

pub fn atInfinity(self: Point) bool {
    return self.x == null;
}

pub fn add(self: Point, other: Point) Point {
    assert(self.a.eql(other.a) and self.b.eql(other.b));

    if (self.x == null) {
        return other;
    }

    if (other.x == null) {
        return self;
    }

    const x1 = self.x.?;
    const y1 = self.y.?;
    const x2 = other.x.?;
    const y2 = other.y.?;
    const a = self.a;
    const b = self.b;

    if (x1.eql(x2)) {
        if (y1.neql(y2) or y1.eqlZero()) {
            return .{ .x = null, .y = null, .a = a, .b = b };
        }

        // y1 == y2

        // s = (3 * x1 ** 2 + a) / (2 * y1)
        const s = x1.pow(2).rmul(3).add(a).div(y1.rmul(2));

        // x3 = s ** 2 - 2 * x1
        const x3 = s.pow(2).sub(x1.rmul(2));

        // y3 = s * (x1 - x3) - y1
        const y3 = s.mul(x1.sub(x3)).sub(y1);

        return .{ .x = x3, .y = y3, .a = a, .b = b };
    }

    // x1 != x2

    // s = (y2 - y1)/(x2 - x1)
    const s = y2.sub(y1).div(x2.sub(x1));

    // x3 = s ** 2 - x1 - x2
    const x3 = s.pow(2).sub(x1).sub(x2);

    // y3 = s * (x1 - x3) - y1
    const y3 = s.mul(x1.sub(x3)).sub(y1);

    return .{ .x = x3, .y = y3, .a = a, .b = b };
}

pub fn rmul(self: Point, coefficient: u256) Point {
    var coef = coefficient;

    var current = self;
    var result = Point{ .x = null, .y = null, .a = self.a, .b = self.b };

    while (coef > 0) : (coef >>= 1) {
        if (coef & 1 == 1) {
            result = result.add(current);
        }

        current = current.add(current);
    }

    return result;
}

const testing = std.testing;

test "Point: on the curve" {
    const prime = 223;
    const a = try FieldElement.init(0, prime);
    const b = try FieldElement.init(7, prime);

    const valid_points = .{ .{ .x = 192, .y = 105 }, .{ .x = 17, .y = 56 }, .{ .x = 1, .y = 193 } };
    const invalid_points = .{ .{ .x = 200, .y = 119 }, .{ .x = 42, .y = 99 } };

    inline for (valid_points) |p| {
        const x = try FieldElement.init(p.x, prime);
        const y = try FieldElement.init(p.y, prime);

        _ = try Point.init(x, y, a, b);
    }

    inline for (invalid_points) |p| {
        const x = try FieldElement.init(p.x, prime);
        const y = try FieldElement.init(p.y, prime);

        const point = Point.init(x, y, a, b);
        try testing.expectError(Error.NotOnTheCurve, point);
    }
}

test "Point: add" {
    const prime = 223;
    const a = try FieldElement.init(0, prime);
    const b = try FieldElement.init(7, prime);

    const additions = .{
        .{ .x1 = 192, .y1 = 105, .x2 = 17, .y2 = 56, .x3 = 170, .y3 = 142 },
        .{ .x1 = 47, .y1 = 71, .x2 = 117, .y2 = 141, .x3 = 60, .y3 = 139 },
        .{ .x1 = 143, .y1 = 98, .x2 = 76, .y2 = 66, .x3 = 47, .y3 = 71 },
    };

    inline for (additions) |addition| {
        const x1 = try FieldElement.init(addition.x1, prime);
        const y1 = try FieldElement.init(addition.y1, prime);
        const p1 = try Point.init(x1, y1, a, b);

        const x2 = try FieldElement.init(addition.x2, prime);
        const y2 = try FieldElement.init(addition.y2, prime);
        const p2 = try Point.init(x2, y2, a, b);

        const x3 = try FieldElement.init(addition.x3, prime);
        const y3 = try FieldElement.init(addition.y3, prime);
        const p3 = try Point.init(x3, y3, a, b);

        try testing.expect(p1.add(p2).eql(p3));
    }
}

test "Point: rmul" {
    const prime = 223;
    const a = try FieldElement.init(0, prime);
    const b = try FieldElement.init(7, prime);

    const multiplications = .{
        .{ .coefficient = 2, .x1 = 192, .y1 = 105, .x2 = 49, .y2 = 71 },
        .{ .coefficient = 2, .x1 = 143, .y1 = 98, .x2 = 64, .y2 = 168 },
        .{ .coefficient = 2, .x1 = 47, .y1 = 71, .x2 = 36, .y2 = 111 },
        .{ .coefficient = 4, .x1 = 47, .y1 = 71, .x2 = 194, .y2 = 51 },
        .{ .coefficient = 8, .x1 = 47, .y1 = 71, .x2 = 116, .y2 = 55 },
        .{ .coefficient = 21, .x1 = 47, .y1 = 71, .x2 = null, .y2 = null },
    };

    inline for (multiplications) |multiplication| {
        const x1 = try FieldElement.init(multiplication.x1, prime);
        const y1 = try FieldElement.init(multiplication.y1, prime);
        const p1 = try Point.init(x1, y1, a, b);

        if (@TypeOf(multiplication.x2) != @TypeOf(null)) {
            const x2 = try FieldElement.init(multiplication.x2, prime);
            const y2 = try FieldElement.init(multiplication.y2, prime);
            const p2 = p1.rmul(multiplication.coefficient);
            const p2_expected = try Point.init(x2, y2, a, b);

            try testing.expect(p2.eql(p2_expected));
        } else {
            const p2 = p1.rmul(multiplication.coefficient);

            try testing.expect(p2.atInfinity());
        }
    }
}
