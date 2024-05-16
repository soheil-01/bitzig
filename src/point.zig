const std = @import("std");
const FieldElement = @import("field_element.zig");
const BigInt = std.math.big.int.Managed;

const Point = @This();

pub const Error = error{ NotOnTheCurve, PointsAreNotOnTheSameCurve };

allocator: std.mem.Allocator,
x: ?FieldElement,
y: ?FieldElement,
a: FieldElement,
b: FieldElement,

pub fn init(allocator: std.mem.Allocator, x: ?FieldElement, y: ?FieldElement, a: FieldElement, b: FieldElement) !Point {
    if (x == null or y == null) {
        return .{ .allocator = allocator, .x = null, .y = null, .a = try a.clone(allocator), .b = try b.clone(allocator) };
    }

    // left_side = y ** 2
    var left_side = try FieldElement.pow(allocator, y.?, 2);
    defer left_side.deinit();

    // right = x ** 3 + a * x + b
    var x_cubed = try FieldElement.pow(allocator, x.?, 3);
    defer x_cubed.deinit();

    var a_times_x = try FieldElement.mul(allocator, a, x.?);
    defer a_times_x.deinit();

    var a_times_x_plus_b = try FieldElement.add(allocator, a_times_x, b);
    defer a_times_x_plus_b.deinit();

    var right_side = try FieldElement.add(allocator, x_cubed, a_times_x_plus_b);
    defer right_side.deinit();

    if (left_side.neql(right_side)) {
        return Error.NotOnTheCurve;
    }

    return .{ .allocator = allocator, .x = try x.?.clone(allocator), .y = try y.?.clone(allocator), .a = try a.clone(allocator), .b = try b.clone(allocator) };
}

pub fn deinit(self: *Point) void {
    if (self.x != null) {
        self.x.?.deinit();
    }

    if (self.y != null) {
        self.y.?.deinit();
    }

    self.a.deinit();
    self.b.deinit();
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

pub fn eql(self: Point, other: Point) !bool {
    if (self.a.neql(other.a) or self.b.neql(other.b)) {
        return Error.PointsAreNotOnTheSameCurve;
    }

    if (self.x == null) {
        return other.x == null;
    }

    return self.x.?.eql(other.x.?) and self.y.?.eql(other.y.?);
}

pub fn neql(self: Point, other: Point) !bool {
    return !self.eql(other);
}

pub fn clone(self: Point, allocator: std.mem.Allocator) !Point {
    const a = try self.a.clone(allocator);
    const b = try self.b.clone(allocator);

    if (self.x == null) {
        return .{ .allocator = allocator, .x = null, .y = null, .a = a, .b = b };
    }

    return .{ .allocator = allocator, .x = try self.x.?.clone(allocator), .y = try self.y.?.clone(allocator), .a = a, .b = b };
}

pub fn add(allocator: std.mem.Allocator, self: Point, other: Point) !Point {
    if (self.a.neql(other.a) or self.b.neql(other.b)) {
        return Error.PointsAreNotOnTheSameCurve;
    }

    if (self.x == null) {
        return other.clone(allocator);
    }

    if (other.x == null) {
        return self.clone(allocator);
    }

    const x1 = self.x.?;
    const y1 = self.y.?;
    const x2 = other.x.?;
    const y2 = other.y.?;
    const a = try self.a.clone(allocator);
    const b = try self.b.clone(allocator);

    if (x1.eql(x2)) {
        if (y1.neql(y2) or y1.eqlZero()) {
            return .{ .allocator = allocator, .x = null, .y = null, .a = a, .b = b };
        }

        // y1 == y2

        // s = (3 * x1 ** 2 + a) / (2 * y1)
        var x1_squared = try FieldElement.pow(allocator, x1, 2);
        defer x1_squared.deinit();

        var x1_squared_times_three = try FieldElement.rmul(allocator, x1_squared, 3);
        defer x1_squared_times_three.deinit();

        var numerator = try FieldElement.add(allocator, x1_squared_times_three, a);
        defer numerator.deinit();

        var denominator = try FieldElement.rmul(allocator, y1, 2);
        defer denominator.deinit();

        var s = try FieldElement.div(allocator, numerator, denominator);
        defer s.deinit();

        // x3 = s ** 2 - 2 * x1
        var s_squared = try FieldElement.pow(allocator, s, 2);
        defer s_squared.deinit();

        var two_times_x1 = try FieldElement.rmul(allocator, x1, 2);
        defer two_times_x1.deinit();

        const x3 = try FieldElement.sub(allocator, s_squared, two_times_x1);

        // y3 = s * (x1 - x3) - y1
        var x1_minus_x3 = try FieldElement.sub(allocator, x1, x3);
        defer x1_minus_x3.deinit();

        var s_times_x1_minus_x3 = try FieldElement.mul(allocator, s, x1_minus_x3);
        defer s_times_x1_minus_x3.deinit();

        const y3 = try FieldElement.sub(allocator, s_times_x1_minus_x3, y1);

        return .{ .allocator = allocator, .x = x3, .y = y3, .a = a, .b = b };
    }

    // x1 != x2

    // s = (y2 - y1)/(x2 - x1)
    var delta_y = try FieldElement.sub(allocator, y2, y1);
    defer delta_y.deinit();

    var delta_x = try FieldElement.sub(allocator, x2, x1);
    defer delta_x.deinit();

    var s = try FieldElement.div(allocator, delta_y, delta_x);
    defer s.deinit();

    // x3 = s ** 2 - x1 - x2
    var s_squared = try FieldElement.pow(allocator, s, 2);
    defer s_squared.deinit();

    var s_squared_minus_x1 = try FieldElement.sub(allocator, s_squared, x1);
    defer s_squared_minus_x1.deinit();

    const x3 = try FieldElement.sub(allocator, s_squared_minus_x1, x2);

    // y3 = s * (x1 - x3) - y1
    var x1_minus_x3 = try FieldElement.sub(allocator, x1, x3);
    defer x1_minus_x3.deinit();

    var s_times_x1_minus_x3 = try FieldElement.mul(allocator, s, x1_minus_x3);
    defer s_times_x1_minus_x3.deinit();

    const y3 = try FieldElement.sub(allocator, s_times_x1_minus_x3, y1);

    return .{ .allocator = allocator, .x = x3, .y = y3, .a = a, .b = b };
}

pub fn rmul(allocator: std.mem.Allocator, self: Point, coefficient: anytype) !Point {
    var coef = try BigInt.initSet(allocator, coefficient);
    defer coef.deinit();

    var current = try self.clone(allocator);
    defer current.deinit();

    var result = try init(allocator, null, null, self.a, self.b);

    while (coef.isPositive() and !coef.eqlZero()) : (try coef.shiftRight(&coef, 1)) {
        if (coef.isOdd()) {
            var tmp = try add(allocator, result, current);
            defer tmp.deinit();
            result.deinit();

            result = try tmp.clone(allocator);
        }

        var tmp = try add(allocator, current, current);
        defer tmp.deinit();
        current.deinit();

        current = try tmp.clone(allocator);
    }

    return result;
}

const testing = std.testing;
const testing_alloc = testing.allocator;

test "Point: on the curve" {
    const prime = 223;
    var a = try FieldElement.init(testing_alloc, 0, prime);
    defer a.deinit();
    var b = try FieldElement.init(testing_alloc, 7, prime);
    defer b.deinit();

    const valid_points = .{ .{ .x = 192, .y = 105 }, .{ .x = 17, .y = 56 }, .{ .x = 1, .y = 193 } };
    const invalid_points = .{ .{ .x = 200, .y = 119 }, .{ .x = 42, .y = 99 } };

    inline for (valid_points) |p| {
        var x = try FieldElement.init(testing_alloc, p.x, prime);
        defer x.deinit();
        var y = try FieldElement.init(testing_alloc, p.y, prime);
        defer y.deinit();

        var point = try Point.init(testing_alloc, x, y, a, b);
        point.deinit();
    }

    inline for (invalid_points) |p| {
        var x = try FieldElement.init(testing_alloc, p.x, prime);
        defer x.deinit();
        var y = try FieldElement.init(testing_alloc, p.y, prime);
        defer y.deinit();

        const point = Point.init(testing_alloc, x, y, a, b);
        try testing.expectError(Error.NotOnTheCurve, point);
    }
}

test "Point: add" {
    const prime = 223;
    var a = try FieldElement.init(testing_alloc, 0, prime);
    defer a.deinit();
    var b = try FieldElement.init(testing_alloc, 7, prime);
    defer b.deinit();

    const additions = .{
        .{ .x1 = 192, .y1 = 105, .x2 = 17, .y2 = 56, .x3 = 170, .y3 = 142 },
        .{ .x1 = 47, .y1 = 71, .x2 = 117, .y2 = 141, .x3 = 60, .y3 = 139 },
        .{ .x1 = 143, .y1 = 98, .x2 = 76, .y2 = 66, .x3 = 47, .y3 = 71 },
    };

    inline for (additions) |addition| {
        var x1 = try FieldElement.init(testing_alloc, addition.x1, prime);
        defer x1.deinit();
        var y1 = try FieldElement.init(testing_alloc, addition.y1, prime);
        defer y1.deinit();
        var p1 = try Point.init(testing_alloc, x1, y1, a, b);
        defer p1.deinit();

        var x2 = try FieldElement.init(testing_alloc, addition.x2, prime);
        defer x2.deinit();
        var y2 = try FieldElement.init(testing_alloc, addition.y2, prime);
        defer y2.deinit();
        var p2 = try Point.init(testing_alloc, x2, y2, a, b);
        defer p2.deinit();

        var x3 = try FieldElement.init(testing_alloc, addition.x3, prime);
        defer x3.deinit();
        var y3 = try FieldElement.init(testing_alloc, addition.y3, prime);
        defer y3.deinit();
        var p3 = try Point.init(testing_alloc, x3, y3, a, b);
        defer p3.deinit();

        var p1_plus_p2 = try Point.add(testing_alloc, p1, p2);
        defer p1_plus_p2.deinit();

        const string = try p1_plus_p2.toString(testing_alloc);
        defer testing_alloc.free(string);

        try testing.expect(try p1_plus_p2.eql(p3));
    }
}

test "Point: rmul" {
    const prime = 223;
    var a = try FieldElement.init(testing_alloc, 0, prime);
    defer a.deinit();
    var b = try FieldElement.init(testing_alloc, 7, prime);
    defer b.deinit();

    const multiplications = .{
        .{ .coefficient = 2, .x1 = 192, .y1 = 105, .x2 = 49, .y2 = 71 },
        .{ .coefficient = 2, .x1 = 143, .y1 = 98, .x2 = 64, .y2 = 168 },
        .{ .coefficient = 2, .x1 = 47, .y1 = 71, .x2 = 36, .y2 = 111 },
        .{ .coefficient = 4, .x1 = 47, .y1 = 71, .x2 = 194, .y2 = 51 },
        .{ .coefficient = 8, .x1 = 47, .y1 = 71, .x2 = 116, .y2 = 55 },
        .{ .coefficient = 21, .x1 = 47, .y1 = 71, .x2 = null, .y2 = null },
    };

    inline for (multiplications) |multiplication| {
        var x1 = try FieldElement.init(testing_alloc, multiplication.x1, prime);
        defer x1.deinit();
        var y1 = try FieldElement.init(testing_alloc, multiplication.y1, prime);
        defer y1.deinit();
        var p1 = try Point.init(testing_alloc, x1, y1, a, b);
        defer p1.deinit();

        if (@TypeOf(multiplication.x2) != @TypeOf(null)) {
            var x2 = try FieldElement.init(testing_alloc, multiplication.x2, prime);
            defer x2.deinit();
            var y2 = try FieldElement.init(testing_alloc, multiplication.y2, prime);
            defer y2.deinit();
            var p2 = try Point.rmul(testing_alloc, p1, multiplication.coefficient);
            defer p2.deinit();

            var p2_expected = try Point.init(testing_alloc, x2, y2, a, b);
            defer p2_expected.deinit();

            try testing.expect(try p2.eql(p2_expected));
        } else {
            var p2 = try Point.rmul(testing_alloc, p1, multiplication.coefficient);
            defer p2.deinit();

            const p2_expected = Point{ .allocator = testing_alloc, .x = null, .y = null, .a = a, .b = b };

            try testing.expect(try p2.eql(p2_expected));
        }
    }
}
