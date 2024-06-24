const std = @import("std");
const utils = @import("../utils.zig");

const Signature = @This();

r: u256,
s: u256,

pub const der_encoded_max_length = 72;

pub fn init(r: u256, s: u256) Signature {
    return .{ .r = r, .s = s };
}

pub fn toString(self: Signature, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "Signature(0x{x},0x{x})", .{ self.r, self.s });
}

pub fn toDer(self: Signature, buf: *[der_encoded_max_length]u8) []u8 {
    var fb = std.io.fixedBufferStream(buf);
    const w = fb.writer();

    const r_bytes = utils.encodeInt(u256, self.r, .big);
    const s_bytes = utils.encodeInt(u256, self.s, .big);

    const r_len = 32 + (r_bytes[0] >> 7);
    const s_len = 32 + (s_bytes[0] >> 7);
    const sig_len = 2 + r_len + 2 + s_len;

    w.writeAll(&[_]u8{ 0x30, sig_len }) catch unreachable;

    w.writeAll(&[_]u8{ 0x02, r_len }) catch unreachable;
    if (r_bytes[0] >> 7 != 0) {
        w.writeByte(0x00) catch unreachable;
    }
    w.writeAll(&r_bytes) catch unreachable;

    w.writeAll(&[_]u8{ 0x02, s_len }) catch unreachable;
    if (s_bytes[0] >> 7 != 0) {
        w.writeByte(0x00) catch unreachable;
    }
    w.writeAll(&s_bytes) catch unreachable;

    return fb.getWritten();
}

pub fn fromDer(der: []const u8) !Signature {
    var fb = std.io.fixedBufferStream(der);
    const reader = fb.reader();

    const compound = reader.readByte() catch return error.InvalidEncoding;
    if (compound != 0x30) {
        return error.InvalidEncoding;
    }

    const sig_len = reader.readByte() catch return error.InvalidEncoding;
    if (sig_len + 2 != der.len) {
        return error.InvalidEncoding;
    }

    const r = try readDerInt(reader);
    const s = try readDerInt(reader);

    if (fb.getPos() catch unreachable != der.len) {
        return error.InvalidEncoding;
    }

    return init(r, s);
}

fn readDerInt(reader: anytype) !u256 {
    const marker = reader.readByte() catch return error.InvalidEncoding;
    if (marker != 0x02) {
        return error.InvalidEncoding;
    }

    var len = reader.readByte() catch return error.InvalidEncoding;
    if (len == 0 or len > 33) {
        return error.InvalidEncoding;
    }

    if (len == 33) {
        if ((reader.readByte() catch return error.InvalidEncoding) != 0) {
            return error.InvalidEncoding;
        }
        len -= 1;
    }

    return reader.readInt(u256, .big) catch return error.InvalidEncoding;
}

const testing = std.testing;

test "Signature: der" {
    const rand = std.crypto.random;

    const test_cases = .{ .{ .r = 1, .s = 2 }, .{ .r = rand.int(u256), .s = rand.int(u256) }, .{ .r = rand.int(u256), .s = rand.int(u256) } };

    inline for (test_cases) |case| {
        const sig = Signature.init(case.r, case.s);

        var buf: [72]u8 = undefined;
        const der = sig.toDer(&buf);

        const sig2 = try fromDer(der);

        try testing.expectEqual(sig.r, sig2.r);
        try testing.expectEqual(sig.s, sig2.s);
    }
}
