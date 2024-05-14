const std = @import("std");

const Point = @This();

pub const Error = error{ NotOnTheCurve, PointsAreNotOnTheSameCurve };

x: ?i64,
y: ?i64,
a: i64,
b: i64,

pub fn init(x: ?i64, y: ?i64, a: i64, b: i64) !Point {
    const point = Point{ .x = x, .y = y, .a = a, .b = b };

    if (x == null and y == null) {
        return point;
    }

    if (std.math.pow(i64, y.?, 2) != std.math.pow(i64, x.?, 3) + a * x.? + b) {
        return Error.NotOnTheCurve;
    }

    return point;
}

pub fn eql(self: Point, other: Point) bool {
    return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b;
}

pub fn neql(self: Point, other: Point) bool {
    return !self.eql(other);
}

pub fn add(self: Point, other: Point) !Point {
    if (self.a != other.a and self.b != other.b) {
        return Error.PointsAreNotOnTheSameCurve;
    }

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

    if (x1 == x2) {
        if (y1 != y2) {
            return .{ .x = null, .y = null, .a = self.a, .b = self.b };
        }

        // y1 == y2

        if (y1 == 0) {
            return .{ .x = null, .y = null, .a = self.a, .b = self.b };
        }

        const s = @divFloor((3 * std.math.pow(i64, x1, 2) + self.a), 2 * y1);
        const x3 = std.math.pow(i64, s, 2) - 2 * x1;
        const y3 = s * (x1 - x3) - y1;

        return .{ .x = x3, .y = y3, .a = self.a, .b = self.b };
    }

    // x1 != x2

    const s = @divFloor(y2 - y1, x2 - x1);
    const x3 = std.math.pow(i64, s, 2) - x1 - x2;
    const y3 = s * (x1 - x3) - y1;

    return .{ .x = x3, .y = y3, .a = self.a, .b = self.b };
}

const testing = std.testing;

test "Point: equality" {
    const a = try Point.init(3, -7, 5, 7);
    const b = try Point.init(18, 77, 5, 7);

    try testing.expect(a.neql(b));
    try testing.expect(!a.neql(a));
}

test "Point: add0" {
    const a = try Point.init(null, null, 5, 7);
    const b = try Point.init(2, 5, 5, 7);
    const c = try Point.init(2, -5, 5, 7);

    const a_plus_b = try a.add(b);
    const b_plus_a = try b.add(a);
    const b_plus_c = try b.add(c);

    try testing.expect(a_plus_b.eql(b));
    try testing.expect(b_plus_a.eql(b));
    try testing.expect(b_plus_c.eql(a));
}

test "Point: add1" {
    const a = try Point.init(3, 7, 5, 7);
    const b = try Point.init(-1, -1, 5, 7);
    const c = try a.add(b);

    const expected = try Point.init(2, -5, 5, 7);

    try testing.expect(c.eql(expected));
}

test "Point: add2" {
    const a = try Point.init(-1, -1, 5, 7);
    const b = try a.add(a);

    const expected = try Point.init(18, 77, 5, 7);

    try testing.expect(b.eql(expected));
}
