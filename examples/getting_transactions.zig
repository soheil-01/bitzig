const std = @import("std");
const bitzig = @import("bitzig");

const network = bitzig.network;
const utils = bitzig.utils;
const bloom_filter = bitzig.bloom_filter;
const transaction = bitzig.transaction;
const merkle = bitzig.merkle;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const start_block = try utils.hexToBytes(allocator, "0000000000000000000239383668be43156d494d1a47e83649c8e1ae6710d2c5");
    defer allocator.free(start_block);

    const address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    const h160 = try utils.decodeBase58Address(address);

    const node = try network.SimpleNode.init(allocator, "172.65.15.46", null, false, true);
    defer node.deinit();

    try node.handshake();

    const bf = try bloom_filter.BloomFilter.init(allocator, 30, 5, 90210);
    defer bf.deinit(allocator);

    bf.add(h160);
    try node.send(bf);

    const getheaders = network.message.GetHeadersMessage{ .start_block = std.mem.bytesToValue([32]u8, start_block) };
    try node.send(getheaders);

    const headers = try node.waitFor(network.message.HeadersMessage);
    defer headers.deinit(allocator);

    var getdata = network.message.GetDataMessage.init(allocator);
    defer getdata.deinit();

    for (headers.blocks) |block| {
        if (!try block.checkPow()) return error.POWIsInvalid;
        try getdata.addData(.filtered_block, try block.hash());
    }
    try node.send(getdata);

    var found = false;
    while (!found) {
        const message = try node.waitFor(transaction.Transaction);

        for (message.tx_outs, 0..) |tx_out, i| {
            var address_buf: [34]u8 = undefined;
            const script_address = try tx_out.script_pubkey.address(&address_buf, false);
            if (std.mem.eql(u8, script_address, address)) {
                std.debug.print("found: {s}: {d}\n", .{ try message.id(), i });
                found = true;
                break;
            }
        }
    }
}
