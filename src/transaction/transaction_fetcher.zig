const std = @import("std");
const json = @import("json");
const utils = @import("../utils.zig");
const Transaction = @import("transaction.zig");

const TransactionFetcher = @This();

allocator: std.mem.Allocator,
cache: std.StringHashMap([]const u8),
buf: std.ArrayList(u8),

const mainnet_host = "https://bitcoin-mainnet.public.blastapi.io";
const testnet_host = "https://bitcoin-testnet.public.blastapi.io";

pub fn init(allocator: std.mem.Allocator) TransactionFetcher {
    return .{
        .allocator = allocator,
        .cache = std.StringHashMap([]const u8).init(allocator),
        .buf = std.ArrayList(u8).init(allocator),
    };
}

pub fn deinit(self: *TransactionFetcher) void {
    var iter = self.cache.iterator();
    while (iter.next()) |entry| {
        self.allocator.free(entry.key_ptr.*);
        self.allocator.free(entry.value_ptr.*);
    }
    self.cache.deinit();

    self.buf.deinit();
}

pub fn fetchAndParse(self: *TransactionFetcher, allocator: std.mem.Allocator, tx_id: []const u8, testnet: bool, fresh: bool) !Transaction {
    const transaction_hex = try self.fetchTransactionHex(tx_id, testnet, fresh);

    const transaction_bytes = try utils.hexToBytes(self.allocator, transaction_hex);
    defer self.allocator.free(transaction_bytes);

    var transaction: Transaction = undefined;
    errdefer transaction.deinit(true);

    if (transaction_bytes[4] == 0) {
        const raw_transaction = try std.mem.concat(self.allocator, u8, &.{ transaction_bytes[0..4], transaction_bytes[6..] });
        defer self.allocator.free(raw_transaction);

        transaction = try Transaction.parse(allocator, raw_transaction, testnet);

        var locktime_bytes: [4]u8 = undefined;
        std.mem.copyForwards(u8, &locktime_bytes, raw_transaction[raw_transaction.len - 4 ..]);

        transaction.locktime = std.mem.readInt(u32, &locktime_bytes, .little);
    } else {
        transaction = try Transaction.parse(allocator, transaction_bytes, testnet);
    }

    const fetched_tx_id = try transaction.id();

    if (!std.mem.eql(u8, tx_id, &fetched_tx_id)) {
        return error.NotTheSameTransactionId;
    }

    return transaction;
}

pub fn fetchTransactionHex(self: *TransactionFetcher, tx_id: []const u8, testnet: bool, fresh: bool) ![]const u8 {
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
        return error.HttpFailed;
    }

    const T = struct { result: ?[]const u8, @"error": ?[]const u8, id: u8 };
    const response_parsed = try std.json.parseFromSlice(T, self.allocator, self.buf.items, .{});
    defer response_parsed.deinit();

    if (response_parsed.value.result == null) {
        return error.HttpFailed;
    }

    const transaction_hex = response_parsed.value.result.?;

    try self.put(tx_id, transaction_hex);

    return transaction_hex;
}

pub fn put(self: *TransactionFetcher, tx_id: []const u8, tx_hex: []const u8) !void {
    try self.cache.put(try self.allocator.dupe(u8, tx_id), try self.allocator.dupe(u8, tx_hex));
}

pub fn loadCache(self: *TransactionFetcher, file_path: []const u8) !void {
    const file = try std.fs.cwd().readFileAlloc(self.allocator, file_path, std.math.maxInt(usize));
    defer self.allocator.free(file);

    const file_json = try json.fromSlice(self.allocator, std.StringHashMap([]const u8), file);
    defer file_json.deinit();

    var iter = file_json.value.iterator();
    while (iter.next()) |entry| {
        try self.put(entry.key_ptr.*, entry.value_ptr.*);
    }
}

pub fn dumpCache(self: TransactionFetcher, file_path: []const u8) !void {
    const json_string = try json.toSlice(self.allocator, self.cache);
    defer self.allocator.free(json_string);

    try std.fs.cwd().writeFile2(.{ .sub_path = file_path, .data = json_string });
}
