const std = @import("std");

const Signature = @This();

r: u256,
s: u256,

pub const der_encoded_max_length = 72;

pub fn init(r: u256, s: u256) Signature {
    return .{ .r = r, .s = s };
}

pub fn toString(self: Signature, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "Signature({x},{x})", .{ self.r, self.s });
}

pub fn toDer(self: Signature) []u8 {
    var buf: [der_encoded_max_length]u8 = undefined;
    var fb = std.io.fixedBufferStream(&buf);
    const w = fb.writer();

    var r_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &r_bytes, self.r, .big);

    var s_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &s_bytes, self.s, .big);

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
