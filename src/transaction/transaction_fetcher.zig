const std = @import("std");
const utils = @import("../utils.zig");
const Transaction = @import("transaction.zig");

const TransactionFetcher = @This();

const Error = error{ HttpFailed, NotTheSameTransactionId };

allocator: std.mem.Allocator,
cache: std.StringHashMap([]const u8),
buf: std.ArrayList(u8),

const mainnet_host = "https://bitcoin-mainnet.public.blastapi.io";
const testnet_host = "https://bitcoin-testnet.public.blastapi.io";

pub fn init(allocator: std.mem.Allocator) TransactionFetcher {
    return .{ .allocator = allocator, .cache = std.StringHashMap([]const u8).init(allocator), .buf = std.ArrayList(u8).init(allocator) };
}

pub fn deinit(self: *TransactionFetcher) void {
    self.cache.deinit();
    self.buf.deinit();
}

pub fn fetchAndParse(self: *TransactionFetcher, tx_id: []const u8, testnet: bool, fresh: bool) !Transaction {
    const transaction_bytes = try self.fetch(tx_id, testnet, fresh);

    var transaction: Transaction = undefined;
    if (transaction_bytes[4] == 0) {
        const raw_transaction = try std.mem.concat(self.allocator, u8, &.{ transaction_bytes[0..4], transaction_bytes[6..] });
        transaction = try Transaction.parse(self.allocator, raw_transaction, testnet);

        var locktime_bytes: [4]u8 = undefined;
        std.mem.copyForwards(u8, &locktime_bytes, raw_transaction[raw_transaction.len - 4 ..]);

        transaction.locktime = std.mem.readInt(u32, &locktime_bytes, .little);
    } else {
        transaction = try Transaction.parse(self.allocator, transaction_bytes, testnet);
    }

    const fetched_tx_id = try transaction.id(self.allocator);
    if (std.mem.eql(u8, tx_id, fetched_tx_id)) {
        return Error.NotTheSameTransactionId;
    }

    return transaction;
}

pub fn fetch(self: *TransactionFetcher, tx_id: []const u8, testnet: bool, fresh: bool) ![]const u8 {
    if (!fresh and self.cache.contains(tx_id)) {
        return self.cache.get(tx_id).?;
    }

    var client = std.http.Client{ .allocator = self.allocator };
    defer client.deinit();

    self.buf.clearRetainingCapacity();

    const payload = try std.fmt.allocPrint(self.allocator, "{{\"jsonrpc\":\"1.0\",\"id\":0,\"method\":\"getrawtransaction\",\"params\":[\"{s}\",false]}}", .{tx_id});
    defer self.allocator.free(payload);

    const url = if (testnet) testnet_host else mainnet_host;
    const res = try client.fetch(.{ .location = .{ .url = url }, .payload = payload, .response_storage = .{ .dynamic = &self.buf } });

    if (res.status != .ok) {
        return Error.HttpFailed;
    }

    const T = struct { result: ?[]const u8, @"error": ?[]const u8, id: u8 };
    const response_parsed = try std.json.parseFromSlice(T, self.allocator, self.buf.items, .{});
    defer response_parsed.deinit();

    if (response_parsed.value.result == null) {
        return Error.HttpFailed;
    }

    const transaction_hex = response_parsed.value.result.?;
    const transaction_bytes = try self.allocator.alloc(u8, transaction_hex.len / 2);
    defer self.allocator.free(transaction_bytes);
    _ = try std.fmt.hexToBytes(transaction_bytes, transaction_hex);

    try self.cache.put(tx_id, transaction_bytes);

    return transaction_bytes;
}
