const std = @import("std");
const bitzig = @import("bitzig");

const utils = bitzig.utils;
const network = bitzig.network;
const block = bitzig.block;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const node = try network.SimpleNode.init(allocator, "172.65.15.46", null, false, false);
    defer node.deinit();

    try node.handshake();

    var previous = try block.Block.parse(&block.constants.GENESIS_BLOCK);
    var first_epoch_timestamp = previous.timestamp;
    var expected_bits = block.constants.LOWEST_BITS;
    var count: usize = 1;

    for (0..19) |_| {
        const getheaders = network.message.GetHeadersMessage{ .start_block = try previous.hash() };
        try node.send(getheaders);

        const headers = try node.waitFor(network.message.HeadersMessage);
        defer headers.deinit(allocator);

        for (headers.blocks) |header| {
            if (!try header.checkPow()) {
                return error.BadPOW;
            }

            if (!std.mem.eql(u8, &header.prev_block, &try previous.hash())) {
                return error.DiscontinuousBlock;
            }

            if (count % 2016 == 0) {
                const time_diff = previous.timestamp - first_epoch_timestamp;
                expected_bits = utils.calculateNewBits(previous.bits, time_diff);

                std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(&expected_bits)});

                first_epoch_timestamp = header.timestamp;
            }

            if (!std.mem.eql(u8, &header.bits, &expected_bits)) {
                return error.BadBits;
            }

            previous = header;
            count += 1;
        }
    }
}
