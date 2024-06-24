const std = @import("std");
const utils = @import("../utils.zig");

const NETWORK_MAGIC = [_]u8{ 0xf9, 0xbe, 0xb4, 0xd9 };
const TESTNET_NETWORK_MAGIC = [_]u8{ 0x0b, 0x11, 0x09, 0x07 };

const NetworkEnvelope = @This();

command: []const u8,
payload: []u8,
magic: [4]u8,

pub fn init(command: []const u8, payload: []u8, testnet: bool) !NetworkEnvelope {
    const magic: [4]u8 = if (testnet) TESTNET_NETWORK_MAGIC else NETWORK_MAGIC;

    return .{
        .command = command,
        .payload = payload,
        .magic = magic,
    };
}

pub fn deinit(self: NetworkEnvelope, allocator: std.mem.Allocator) void {
    allocator.free(self.command);
    allocator.free(self.payload);
}

pub fn toString(self: NetworkEnvelope, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}: {s}", .{ self.command, std.fmt.fmtSliceHexLower(self.payload) });
}

pub fn serialize(self: NetworkEnvelope, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    var command: [12]u8 = [_]u8{0} ** 12;
    std.mem.copyForwards(u8, &command, self.command);

    try result.appendSlice(&self.magic);
    try result.appendSlice(&command);
    try result.appendSlice(&utils.encodeInt(u32, @intCast(self.payload.len), .little));
    try result.appendSlice(utils.hash256(self.payload)[0..4]);
    try result.appendSlice(self.payload);

    return result.toOwnedSlice();
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8, testnet: bool) !NetworkEnvelope {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader, testnet);
}

pub fn parseFromReader(allocator: std.mem.Allocator, reader: anytype, testnet: bool) !NetworkEnvelope {
    const magic: [4]u8 = reader.readBytesNoEof(4) catch return error.InvalidEncoding;
    const expected_magic = if (testnet) TESTNET_NETWORK_MAGIC else NETWORK_MAGIC;

    if (!std.mem.eql(u8, &magic, &expected_magic)) {
        return error.MagicIsNotRight;
    }

    const command: [12]u8 = reader.readBytesNoEof(12) catch return error.InvalidEncoding;
    const command_trimmed = std.mem.trim(u8, &command, &.{0});

    const payload_length = reader.readInt(u32, .little) catch return error.InvalidEncoding;

    const checksum: [4]u8 = reader.readBytesNoEof(4) catch return error.InvalidEncoding;

    const payload = try allocator.alloc(u8, payload_length);
    reader.readNoEof(payload) catch return error.InvalidEncoding;

    const calculated_checksum = utils.hash256(payload)[0..4];
    if (!std.mem.eql(u8, calculated_checksum, &checksum)) {
        return error.ChecksumDoesNotMatch;
    }

    return init(try allocator.dupe(u8, command_trimmed), payload, testnet);
}

const testing = std.testing;
const testing_alloc = testing.allocator;

test "NetworkEnvelope: parse" {
    {
        const msg = try utils.hexToBytes(testing_alloc, "f9beb4d976657261636b000000000000000000005df6e0e2");
        defer testing_alloc.free(msg);

        const envelope = try NetworkEnvelope.parse(testing_alloc, msg, false);
        defer envelope.deinit(testing_alloc);

        try testing.expectEqualStrings(envelope.command, "verack");
        try testing.expect(envelope.payload.len == 0);
    }

    {
        const msg = try utils.hexToBytes(testing_alloc, "f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001");
        defer testing_alloc.free(msg);

        const envelope = try NetworkEnvelope.parse(testing_alloc, msg, false);
        defer envelope.deinit(testing_alloc);

        try testing.expectEqualStrings(envelope.command, "version");
        try testing.expectEqualStrings(envelope.payload, msg[24..]);
    }
}

test "NetworkEnvelope: serialize" {
    {
        const msg = try utils.hexToBytes(testing_alloc, "f9beb4d976657261636b000000000000000000005df6e0e2");
        defer testing_alloc.free(msg);

        const envelope = try NetworkEnvelope.parse(testing_alloc, msg, false);
        defer envelope.deinit(testing_alloc);

        const serialized = try envelope.serialize(testing_alloc);
        defer testing_alloc.free(serialized);

        try testing.expectEqualStrings(msg, serialized);
    }

    {
        const msg = try utils.hexToBytes(testing_alloc, "f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001");
        defer testing_alloc.free(msg);

        const envelope = try NetworkEnvelope.parse(testing_alloc, msg, false);
        defer envelope.deinit(testing_alloc);

        const serialized = try envelope.serialize(testing_alloc);
        defer testing_alloc.free(serialized);

        try testing.expectEqualStrings(msg, serialized);
    }
}
