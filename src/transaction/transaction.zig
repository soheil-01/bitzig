const std = @import("std");
const utils = @import("../utils.zig");
const TransactionInput = @import("transaction_input.zig");
const TransactionOutput = @import("transaction_output.zig");
const TransactionFetcher = @import("transaction_fetcher.zig");

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
    for (self.tx_ins) |tx_in| {
        tx_in.deinit();
    }

    for (self.tx_outs) |tx_out| {
        tx_out.deinit();
    }

    self.allocator.free(self.tx_ins);
    self.allocator.free(self.tx_outs);
}

pub fn toString(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
    var tx_ins = std.ArrayList(u8).init(allocator);
    for (self.tx_ins) |tx_in| {
        const tx_in_string = try tx_in.toString(allocator);
        defer allocator.free(tx_in_string);
        try tx_ins.appendSlice(tx_in_string);
    }

    var tx_outs = std.ArrayList(u8).init(allocator);
    for (self.tx_outs) |tx_out| {
        const tx_out_string = try tx_out.toString(allocator);
        defer allocator.free(tx_out_string);
        try tx_outs.appendSlice(tx_out_string);
    }

    const tx_id = try self.id(allocator);
    defer allocator.free(tx_id);

    return std.fmt.allocPrint(allocator, "tx: {s}\nversion: {d}\ntx_ins: {s}\ntx_outs: {s}\nlocktime: {d}", .{ tx_id, self.version, try tx_ins.toOwnedSlice(), try tx_outs.toOwnedSlice(), self.locktime });
}

pub fn id(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
    const tx_hash = try self.hash(allocator);

    return std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&tx_hash)});
}

pub fn hash(self: Transaction, allocator: std.mem.Allocator) ![32]u8 {
    const serialized = try self.serialize(allocator);
    defer allocator.free(serialized);
    var result = utils.hash256(serialized);
    std.mem.reverse(u8, &result);

    return result;
}

pub fn fee(self: Transaction, fetcher: *TransactionFetcher, fresh: bool) !u64 {
    var input_sum: u64 = 0;
    for (self.tx_ins) |tx| {
        input_sum += try tx.value(fetcher, self.testnet, fresh);
    }

    var output_sum: u64 = 0;
    for (self.tx_outs) |tx| {
        output_sum += tx.amount;
    }

    return input_sum - output_sum;
}

pub fn serialize(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    const version_bytes = utils.encodeInt(u32, self.version, .little);
    try result.appendSlice(&version_bytes);

    const num_inputs = try utils.encodeVarint(allocator, self.tx_ins.len);
    defer allocator.free(num_inputs);
    try result.appendSlice(num_inputs);
    for (self.tx_ins) |tx_in| {
        const serialized_tx_in = try tx_in.serialize(allocator);
        defer allocator.free(serialized_tx_in);
        try result.appendSlice(serialized_tx_in);
    }

    const num_outputs = try utils.encodeVarint(allocator, self.tx_outs.len);
    defer allocator.free(num_outputs);
    try result.appendSlice(num_outputs);
    for (self.tx_outs) |tx_out| {
        const serialized_tx_out = try tx_out.serialize(allocator);
        defer allocator.free(serialized_tx_out);
        try result.appendSlice(serialized_tx_out);
    }

    const locktime_bytes = utils.encodeInt(u32, self.locktime, .little);
    try result.appendSlice(&locktime_bytes);

    return result.toOwnedSlice();
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8, testnet: bool) !Transaction {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    const version = utils.readIntFromReader(u32, reader, .little) catch return Error.InvalidEncoding;

    const num_inputs = utils.readVarintFromReader(reader) catch return Error.InvalidEncoding;
    const inputs = try allocator.alloc(TransactionInput, num_inputs);
    for (0..num_inputs) |i| {
        inputs[i] = try TransactionInput.parseFromReader(allocator, reader);
    }

    const num_outputs = utils.readVarintFromReader(reader) catch return Error.InvalidEncoding;
    const outputs = try allocator.alloc(TransactionOutput, num_outputs);
    for (0..num_outputs) |i| {
        outputs[i] = try TransactionOutput.parseFromReader(allocator, reader);
    }

    const locktime = utils.readIntFromReader(u32, reader, .little) catch return Error.InvalidEncoding;

    return init(allocator, version, inputs, outputs, locktime, testnet);
}

const testing = std.testing;
const testing_alloc = testing.allocator;

test "Transaction" {
    const cache_file = "tx.cache";
    var transactionFetcher = TransactionFetcher.init(testing_alloc);
    defer transactionFetcher.deinit();
    try transactionFetcher.loadCache(cache_file);

    // parse version
    {
        const tx_bytes = try utils.hexToBytes(testing_alloc, "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600");
        defer testing_alloc.free(tx_bytes);

        const tx = try Transaction.parse(testing_alloc, tx_bytes, false);
        defer tx.deinit();

        try testing.expect(tx.version == 1);
    }

    //parse inputs
    {
        const tx_bytes = try utils.hexToBytes(testing_alloc, "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600");
        defer testing_alloc.free(tx_bytes);

        const tx = try Transaction.parse(testing_alloc, tx_bytes, false);
        defer tx.deinit();

        try testing.expect(tx.tx_ins.len == 1);

        const want_prev_tx = try utils.hexToBytes(testing_alloc, "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81");
        defer testing_alloc.free(want_prev_tx);

        try testing.expectEqualStrings(want_prev_tx, &tx.tx_ins[0].prev_tx);
        try testing.expect(tx.tx_ins[0].prev_index == 0);

        const want_script_sig = try utils.hexToBytes(testing_alloc, "6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a");
        defer testing_alloc.free(want_script_sig);

        const script_sig_serialized = try tx.tx_ins[0].script_sig.serialize(testing_alloc);
        defer testing_alloc.free(script_sig_serialized);

        try testing.expectEqualSlices(u8, want_script_sig, script_sig_serialized);
        try testing.expect(tx.tx_ins[0].sequence == 0xfffffffe);
    }

    // parse outputs
    {
        const tx_bytes = try utils.hexToBytes(testing_alloc, "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600");
        defer testing_alloc.free(tx_bytes);

        const tx = try Transaction.parse(testing_alloc, tx_bytes, false);
        defer tx.deinit();

        try testing.expect(tx.tx_outs.len == 2);

        try testing.expect(tx.tx_outs[0].amount == 32454049);

        const want_script_pubkey_0 = try utils.hexToBytes(testing_alloc, "1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac");
        defer testing_alloc.free(want_script_pubkey_0);

        const script_pubkey_serialized_0 = try tx.tx_outs[0].script_pubkey.serialize(testing_alloc);
        defer testing_alloc.free(script_pubkey_serialized_0);

        try testing.expectEqualStrings(want_script_pubkey_0, script_pubkey_serialized_0);

        try testing.expect(tx.tx_outs[1].amount == 10011545);

        const want_script_pubkey_1 = try utils.hexToBytes(testing_alloc, "1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac");
        defer testing_alloc.free(want_script_pubkey_1);

        const script_pubkey_serialized_1 = try tx.tx_outs[1].script_pubkey.serialize(testing_alloc);
        defer testing_alloc.free(script_pubkey_serialized_1);

        try testing.expectEqualStrings(want_script_pubkey_1, script_pubkey_serialized_1);
    }

    // parse locktime
    {
        const tx_bytes = try utils.hexToBytes(testing_alloc, "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600");
        defer testing_alloc.free(tx_bytes);

        const tx = try Transaction.parse(testing_alloc, tx_bytes, false);
        defer tx.deinit();

        try testing.expect(tx.locktime == 410393);
    }

    // serialize
    {
        const tx_bytes = try utils.hexToBytes(testing_alloc, "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600");
        defer testing_alloc.free(tx_bytes);

        const tx = try Transaction.parse(testing_alloc, tx_bytes, false);
        defer tx.deinit();

        const serialized_tx = try tx.serialize(testing_alloc);
        defer testing_alloc.free(serialized_tx);

        try testing.expectEqualStrings(tx_bytes, serialized_tx);
    }

    // input value
    {
        const tx_hash = try utils.hexToBytes(testing_alloc, "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81");
        defer testing_alloc.free(tx_hash);

        const index: u32 = 0;
        const want_value: u64 = 42505594;

        const tx_in = TransactionInput.init(testing_alloc, tx_hash[0..32].*, index, null, null);
        defer tx_in.deinit();

        const input_value = try tx_in.value(&transactionFetcher, false, false);
        try testing.expect(input_value == want_value);
    }

    // fee
    {
        {
            const tx_bytes = try utils.hexToBytes(testing_alloc, "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600");
            defer testing_alloc.free(tx_bytes);
            const tx = try Transaction.parse(testing_alloc, tx_bytes, false);
            defer tx.deinit();
            const tx_fee = try tx.fee(&transactionFetcher, false);
            try testing.expect(tx_fee == 40000);
        }

        {
            const tx_bytes = try utils.hexToBytes(testing_alloc, "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600");
            defer testing_alloc.free(tx_bytes);
            const tx = try Transaction.parse(testing_alloc, tx_bytes, false);
            defer tx.deinit();
            const tx_fee = try tx.fee(&transactionFetcher, false);
            try testing.expect(tx_fee == 140500);
        }
    }
}
