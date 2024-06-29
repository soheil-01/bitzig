const std = @import("std");
const utils = @import("../../utils.zig");

const VersionMessage = @This();

pub const command = "version";

version: u32,
services: u64,
timestamp: u64,
receiver_services: u64,
receiver_ip: [4]u8,
receiver_port: u16,
sender_services: u64,
sender_ip: [4]u8,
sender_port: u16,
nonce: [8]u8,
user_agent: []const u8,
latest_block: u32,
relay: bool,

pub const Options = struct {
    version: u32 = 70015,
    services: u64 = 0,
    timestamp: ?u64 = null,
    receiver_services: u64 = 0,
    receiver_ip: [4]u8 = [_]u8{0} ** 4,
    receiver_port: u16 = 8333,
    sender_services: u64 = 0,
    sender_ip: [4]u8 = [_]u8{0} ** 4,
    sender_port: u16 = 8333,
    nonce: ?[8]u8 = null,
    user_agent: []const u8 = "/bitzig:0.0.1/",
    latest_block: u32 = 0,
    relay: bool = false,
};

pub fn init(options: Options) VersionMessage {
    return .{
        .version = options.version,
        .services = options.services,
        .timestamp = options.timestamp orelse @intCast(std.time.timestamp()),
        .receiver_services = options.receiver_services,
        .receiver_ip = options.receiver_ip,
        .receiver_port = options.receiver_port,
        .sender_services = options.sender_services,
        .sender_ip = options.sender_ip,
        .sender_port = options.sender_port,
        .nonce = options.nonce orelse blk: {
            var nonce: [8]u8 = undefined;
            std.crypto.random.bytes(&nonce);
            break :blk nonce;
        },
        .user_agent = options.user_agent,
        .latest_block = options.latest_block,
        .relay = options.relay,
    };
}

pub fn serialize(self: VersionMessage, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    try result.appendSlice(&utils.encodeInt(u32, self.version, .little));
    try result.appendSlice(&utils.encodeInt(u64, self.services, .little));
    try result.appendSlice(&utils.encodeInt(u64, self.timestamp, .little));

    try result.appendSlice(&utils.encodeInt(u64, self.receiver_services, .little));
    const receiver_ip = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ self.receiver_ip;
    try result.appendSlice(&receiver_ip);
    try result.appendSlice(&utils.encodeInt(u16, self.receiver_port, .big));

    try result.appendSlice(&utils.encodeInt(u64, self.sender_services, .little));
    const sender_ip = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff } ++ self.sender_ip;
    try result.appendSlice(&sender_ip);
    try result.appendSlice(&utils.encodeInt(u16, self.sender_port, .big));

    try result.appendSlice(&self.nonce);

    const user_agent_len = try utils.encodeVarint(allocator, self.user_agent.len);
    defer allocator.free(user_agent_len);
    try result.appendSlice(user_agent_len);

    try result.appendSlice(self.user_agent);
    try result.appendSlice(&utils.encodeInt(u32, self.latest_block, .little));
    try result.append(if (self.relay) 1 else 0);

    return result.toOwnedSlice();
}

pub fn parse(_: []const u8, _: std.mem.Allocator) !VersionMessage {
    return .{};
}

const testing = std.testing;
const testing_alloc = testing.allocator;

test "VersionMessage: serialize" {
    const v = VersionMessage.init(.{ .timestamp = 0, .nonce = [_]u8{0} ** 8 });
    const serialized = try v.serialize(testing_alloc);
    defer testing_alloc.free(serialized);

    const expected = try utils.hexToBytes(testing_alloc, "7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d00000000000000000e2f6269747a69673a302e302e312f0000000000");
    defer testing_alloc.free(expected);

    try testing.expectEqualSlices(
        u8,
        expected,
        serialized,
    );
}
