const std = @import("std");

const PongMessage = @This();

pub const command = "pong";

nonce: [8]u8,

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !PongMessage {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(_: std.mem.Allocator, reader: anytype) !PongMessage {
    const nonce = reader.readBytesNoEof(8) catch return error.InvalidEncoding;

    return .{ .nonce = nonce };
}

pub fn serialize(self: PongMessage, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    try result.appendSlice(&self.nonce);

    return result.toOwnedSlice();
}
