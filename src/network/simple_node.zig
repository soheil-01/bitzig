const std = @import("std");
const network = @import("network");
const NetworkEnvelope = @import("network_envelope.zig");

const VersionMessage = @import("message/version_message.zig");
const VerAckMessage = @import("message/ver_ack_message.zig");
const PingMessage = @import("message/ping_message.zig");
const PongMessage = @import("message/pong_message.zig");

const SimpleNode = @This();

allocator: std.mem.Allocator,
sock: network.Socket,
testnet: bool,
logging: bool,

pub fn init(allocator: std.mem.Allocator, host: []const u8, port: ?u16, testnet: bool, logging: bool) !SimpleNode {
    try network.init();
    const sock = try network.connectToHost(allocator, host, port orelse if (testnet) 18333 else 8333, .tcp);

    return .{ .allocator = allocator, .sock = sock, .testnet = testnet, .logging = logging };
}

pub fn deinit(self: SimpleNode) void {
    network.deinit();
    self.sock.close();
}

pub fn send(self: SimpleNode, message: anytype) !void {
    const message_serialized = try message.serialize(self.allocator);
    defer self.allocator.free(message_serialized);

    const envelope = try NetworkEnvelope.init(
        @TypeOf(message).command,
        message_serialized,
        self.testnet,
    );

    const envelope_serialized = try envelope.serialize(self.allocator);
    defer self.allocator.free(envelope_serialized);

    if (self.logging) {
        const envelope_string = try envelope.toString(self.allocator);
        defer self.allocator.free(envelope_string);

        std.debug.print("sending: {s}\n", .{envelope_string});
    }

    _ = try self.sock.send(envelope_serialized);
}

pub fn read(self: SimpleNode) !NetworkEnvelope {
    const envelope = try NetworkEnvelope.parseFromReader(
        self.allocator,
        self.sock.reader(),
        self.testnet,
    );

    if (self.logging) {
        const envelope_string = try envelope.toString(self.allocator);
        defer self.allocator.free(envelope_string);

        std.debug.print("receiving: {s}\n", .{envelope_string});
    }

    return envelope;
}

pub fn waitFor(self: SimpleNode, comptime MessageType: type) !MessageType {
    while (true) {
        const envelope = try self.read();
        defer envelope.deinit(self.allocator);

        if (std.mem.eql(u8, envelope.command, VersionMessage.command)) {
            try self.send(VerAckMessage{});
        } else if (std.mem.eql(u8, envelope.command, PingMessage.command)) {
            try self.send(PongMessage{ .nonce = std.mem.bytesToValue([8]u8, envelope.payload) });
        } else {
            if (std.mem.eql(u8, MessageType.command, envelope.command)) {
                return MessageType.parse(self.allocator, envelope.payload);
            }
        }
    }
}

pub fn handshake(self: SimpleNode) !void {
    const version = VersionMessage.init(.{});
    try self.send(version);
    _ = try self.waitFor(VerAckMessage);
}
