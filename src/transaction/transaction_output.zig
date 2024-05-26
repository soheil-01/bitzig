const std = @import("std");
const utils = @import("../utils.zig");
const Script = @import("../script/script.zig");

const TransactionOutput = @This();

const Error = error{InvalidEncoding};

amount: u64,
script_pubkey: Script,

pub fn init(amount: u64, script_pubkey: Script) TransactionOutput {
    return .{ .amount = amount, .script_pubkey = script_pubkey };
}

pub fn toString(self: TransactionOutput, allocator: std.mem.Allocator) ![]u8 {
    const script_pubkey_string = self.script_pubkey.toString(allocator);
    defer allocator.free(script_pubkey_string);
    return std.fmt.allocPrint(allocator, "{d}:{s}", .{ self.amount, script_pubkey_string });
}

pub fn serialize(self: TransactionOutput, allocator: std.mem.Allocator) ![]u8 {
    const result = std.ArrayList(u8).init(allocator);

    const amount_bytes = utils.encodeInt(u64, self.amount, .little);
    try result.appendSlice(amount_bytes);

    try result.appendSlice(self.script_pubkey.serialize());

    return result.toOwnedSlice();
}

pub fn parse(reader: std.io.AnyReader) !TransactionOutput {
    const amount = utils.readInt(u64, reader, .little) catch return Error.InvalidEncoding;
    const script_pubkey = Script.parse(reader);
    return init(amount, script_pubkey);
}
