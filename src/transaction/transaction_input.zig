const std = @import("std");
const utils = @import("../utils.zig");
const Script = @import("../script/script.zig");
const Transaction = @import("transaction.zig");
const TransactionFetcher = @import("transaction_fetcher.zig");

const TransactionInput = @This();

const Error = error{InvalidEncoding};

allocator: std.mem.Allocator,
prev_tx: [32]u8,
prev_index: u32,
script_sig: Script,
sequence: u32,

pub fn init(allocator: std.mem.Allocator, prev_tx: [32]u8, prev_index: u32, script_sig: Script, sequence: ?u32) TransactionInput {
    return .{ .allocator = allocator, .prev_tx = prev_tx, .prev_index = prev_index, .script_sig = script_sig, .sequence = sequence orelse 0xffffffff };
}

pub fn toString(self: TransactionInput, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}:{d}", .{ std.fmt.fmtSliceHexLower(&self.prev_tx), self.prev_index });
}

// TODO: Since the cache is currentlly tied to the lifetime of the TransactionFetcher instance,
// it becomes ineffective if only used for fetching a single transaction.
pub fn fetchTransaction(self: TransactionInput, testnet: bool, fresh: bool) !Transaction {
    var transaction_fetcher = TransactionFetcher.init(self.allocator);
    defer transaction_fetcher.deinit();

    return transaction_fetcher.fetchAndParse(&self.prev_tx, testnet, fresh);
}

pub fn value(self: TransactionInput, testnet: bool, fresh: bool) !u64 {
    const transaction = try self.fetchTransaction(testnet, fresh);
    return transaction.tx_outs[self.prev_index].amount;
}

pub fn serialize(self: TransactionInput, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    var prev_tx = self.prev_tx;
    std.mem.reverse(u8, &prev_tx);
    try result.appendSlice(&prev_tx);

    const prev_index_bytes = utils.encodeInt(u32, self.prev_index, .little);
    try result.appendSlice(&prev_index_bytes);

    try result.appendSlice(try self.script_sig.serialize(allocator));

    const sequence_bytes = utils.encodeInt(u32, self.sequence, .little);
    try result.appendSlice(&sequence_bytes);

    return result.toOwnedSlice();
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !TransactionInput {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(allocator: std.mem.Allocator, reader: anytype) !TransactionInput {
    var prev_tx: [32]u8 = undefined;
    reader.readNoEof(&prev_tx) catch return Error.InvalidEncoding;
    std.mem.reverse(u8, &prev_tx);

    const prev_index = utils.readIntFromReader(u32, reader, .little) catch return Error.InvalidEncoding;
    const script = try Script.parseFromReader(allocator, reader);
    const sequence = utils.readIntFromReader(u32, reader, .little) catch return Error.InvalidEncoding;

    return init(allocator, prev_tx, prev_index, script, sequence);
}
