const std = @import("std");
const bitzig = @import("bitzig.zig");

const utils = bitzig.utils;
const ecc = bitzig.ecc;
const transaction = bitzig.transaction;
const script = bitzig.script;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const private_key = ecc.PrivateKey.init(8675309);

    var transactionFetcher = transaction.TransactionFetcher.init(allocator);
    try transactionFetcher.loadCache("tx.cache");
    defer transactionFetcher.deinit();

    const prev_tx = try utils.hexToBytes(allocator, "0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299");
    defer allocator.free(prev_tx);
    const prev_index = 13;

    const tx_in = try transaction.TransactionInput.init(allocator, std.mem.bytesToValue([32]u8, prev_tx), prev_index, null, null);

    const change_amount = @as(u64, 0.33 * 100000000);
    const change_h160 = try utils.decodeBase58Address("mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2");
    const change_script = try script.Script.p2pkhScript(allocator, std.mem.bytesToValue([20]u8, change_h160));
    const change_output = transaction.TransactionOutput.init(allocator, change_amount, change_script);

    const target_amount = @as(u64, 0.1 * 100000000);
    const target_h160 = try utils.decodeBase58Address("mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf");
    const target_script = try script.Script.p2pkhScript(allocator, std.mem.bytesToValue([20]u8, target_h160));
    const target_output = transaction.TransactionOutput.init(allocator, target_amount, target_script);

    var tx_ins = [_]transaction.TransactionInput{tx_in};
    var tx_outs = [_]transaction.TransactionOutput{ change_output, target_output };

    const tx = try transaction.Transaction.init(allocator, 1, &tx_ins, &tx_outs, 0, true);
    defer tx.deinit(false);

    _ = try tx.signInput(&transactionFetcher, 0, private_key);

    const tx_bytes = try tx.serialize(allocator);
    defer allocator.free(tx_bytes);

    std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(tx_bytes)});
}
