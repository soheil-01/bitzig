const std = @import("std");
const utils = @import("../utils.zig");

const Script = @This();

const Error = error{InvalidEncoding};

allocator: std.mem.Allocator,
bytes: []u8,

pub fn init(allocator: std.mem.Allocator, bytes: []u8) Script {
    return .{ .allocator = allocator, .bytes = bytes };
}

pub fn deinit(self: Script) void {
    self.allocator.free(self.bytes);
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !Script {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(allocator: std.mem.Allocator, reader: anytype) !Script {
    const script_len = utils.readVarintFromReader(reader) catch return Error.InvalidEncoding;
    const script_bytes = try allocator.alloc(u8, script_len);
    reader.readNoEof(script_bytes) catch return Error.InvalidEncoding;

    return init(allocator, script_bytes);
}

pub fn toString(_: Script, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "script", .{});
}

pub fn serialize(self: Script, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    const script_len = try utils.encodeVarint(allocator, self.bytes.len);

    try result.appendSlice(script_len);
    try result.appendSlice(self.bytes);

    return result.toOwnedSlice();
}
