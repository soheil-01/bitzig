const std = @import("std");
const utils = @import("../utils.zig");
const TransactionInput = @import("transaction_input.zig");
const TransactionOutput = @import("transaction_output.zig");

const Transaction = @This();

const Error = error{InvalidEncoding};

allocator: std.mem.Allocator,
version: u32,
tx_ins: []TransactionInput,
tx_outs: []TransactionOutput,
locktime: u32,
testnet: bool,

pub fn init(allocator: std.mem.Allocator, version: u32, tx_ins: []TransactionInput, tx_outs: []TransactionOutput, locktime: ?u32, testnet: bool) Transaction {
    return .{ .allocator = allocator, .version = version, .tx_ins = tx_ins, .tx_outs = tx_outs, .locktime = locktime orelse 0xffffffff, .testnet = testnet };
}

pub fn deinit(self: Transaction) void {
    self.allocator.free(self.tx_ins);
    self.allocator.free(self.tx_outs);
}

pub fn toString(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
    const tx_ins = std.ArrayList(u8).init(allocator);
    for (self.tx_ins) |tx_in| {
        const tx_in_string = try tx_in.toString(allocator);
        defer allocator.free(tx_in_string);
        tx_ins.appendSlice(tx_in_string);
    }

    const tx_outs = std.ArrayList(u8).init(allocator);
    for (self.tx_outs) |tx_out| {
        const tx_out_string = try tx_out.toString(allocator);
        defer allocator.free(tx_out_string);
        tx_outs.appendSlice(tx_out_string);
    }

    return std.fmt.allocPrint(allocator, "tx: {s}\nversion: {s}\ntx_ins: {s}\ntx_outs: {s}\nlocktime: {s}", .{ self.id(), self.version, try tx_ins.toOwnedSlice(), try tx_outs.toOwnedSlice(), self.locktime });
}

pub fn id(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(self.hash())});
}

pub fn hash(self: Transaction) [32]u8 {
    const result = utils.hash256(self.serialize());
    std.mem.reverse(u8, &result);

    return result;
}

pub fn fee(self: Transaction, fresh: bool) u64 {
    var input_sum: u64 = 0;
    for (self.tx_ins) |tx| {
        input_sum += tx.value(self.testnet, fresh);
    }

    var output_sum: u64 = 0;
    for (self.tx_outs) |tx| {
        output_sum += tx.amount;
    }

    return input_sum - output_sum;
}

pub fn serialize(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
    const result = std.ArrayList(u8).init(allocator);

    const version_bytes = utils.encodeInt(u32, self.version, .little);
    try result.appendSlice(version_bytes);

    const num_inputs = try utils.encodeVarint(allocator, self.tx_ins.len);
    try result.appendSlice(num_inputs);
    for (self.tx_ins) |tx_in| {
        try result.appendSlice(try tx_in.serialize(allocator));
    }

    const num_outputs = try utils.encodeVarint(allocator, self.tx_outs.len);
    try result.appendSlice(num_outputs);
    for (self.tx_outs) |tx_out| {
        try result.appendSlice(try tx_out.serialize(allocator));
    }

    const locktime_bytes = utils.encodeInt(u32, self.locktime, .little);
    try result.appendSlice(locktime_bytes);

    return result.toOwnedSlice();
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8, testnet: bool) !Transaction {
    const fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    const version = utils.readInt(u32, reader, .little) catch return Error.InvalidEncoding;

    const num_inputs = utils.readVarint(reader) catch return Error.InvalidEncoding;
    const inputs = try allocator.alloc(TransactionInput, num_inputs);
    for (0..num_inputs) |i| {
        inputs[i] = TransactionInput.parse(reader);
    }

    const num_outputs = utils.readVarint(reader) catch return Error.InvalidEncoding;
    const outputs = try allocator.alloc(TransactionOutput, num_outputs);
    for (0..num_outputs) |i| {
        outputs[i] = TransactionOutput.parse(reader);
    }

    const locktime = utils.readInt(u32, reader, .little) catch return Error.InvalidEncoding;

    return init(allocator, version, inputs, outputs, locktime, testnet);
}
