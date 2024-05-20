const std = @import("std");

const Signature = @This();

r: u256,
s: u256,

pub fn init(r: u256, s: u256) Signature {
    return .{ .r = r, .s = s };
}

pub fn toString(self: Signature, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "Signature({x},{x})", .{ self.r, self.s });
}
