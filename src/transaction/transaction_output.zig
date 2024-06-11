const std = @import("std");
const utils = @import("../utils.zig");
const Script = @import("../script/script.zig");

const TransactionOutput = @This();

allocator: std.mem.Allocator,
amount: u64,
script_pubkey: Script,

pub fn init(allocator: std.mem.Allocator, amount: u64, script_pubkey: Script) TransactionOutput {
    return .{ .allocator = allocator, .amount = amount, .script_pubkey = script_pubkey };
}

pub fn deinit(self: TransactionOutput) void {
    self.script_pubkey.deinit();
}

pub fn toString(self: TransactionOutput, allocator: std.mem.Allocator) ![]u8 {
    const script_pubkey_string = try self.script_pubkey.toString(allocator);
    defer allocator.free(script_pubkey_string);

    return std.fmt.allocPrint(allocator, "{d}:{{{s}}}", .{ self.amount, script_pubkey_string });
}

pub fn serialize(self: TransactionOutput, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    const amount_bytes = utils.encodeInt(u64, self.amount, .little);
    try result.appendSlice(&amount_bytes);

    const serialized_script_pubkey = try self.script_pubkey.serialize(allocator);
    defer allocator.free(serialized_script_pubkey);
    try result.appendSlice(serialized_script_pubkey);

    return result.toOwnedSlice();
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !TransactionOutput {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(allocator: std.mem.Allocator, reader: anytype) !TransactionOutput {
    const amount = utils.readIntFromReader(u64, reader, .little) catch return error.InvalidEncoding;
    const script_pubkey = try Script.parseFromReader(allocator, reader);

    return init(allocator, amount, script_pubkey);
}
