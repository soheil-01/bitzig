const std = @import("std");
const utils = @import("../../utils.zig");

const GetDataMessage = @This();

pub const command = "getdata";

const DataType = enum(u32) {
    transaction = 1,
    normal_block = 2,
    filtered_block = 3,
    compact_block = 4,
};

const DataItem = struct { data_type: DataType, identifier: [32]u8 };

data: std.ArrayList(DataItem),

pub fn init(allocator: std.mem.Allocator) GetDataMessage {
    return .{ .data = std.ArrayList(DataItem).init(allocator) };
}

pub fn deinit(self: GetDataMessage) void {
    self.data.deinit();
}

pub fn addData(self: *GetDataMessage, data_type: DataType, identifier: [32]u8) !void {
    try self.data.append(.{ .data_type = data_type, .identifier = identifier });
}

pub fn serialize(self: GetDataMessage, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    const data_len = try utils.encodeVarint(allocator, self.data.items.len);
    defer allocator.free(data_len);
    try result.appendSlice(data_len);

    for (self.data.items) |item| {
        const data_type = utils.encodeInt(u32, @intFromEnum(item.data_type), .little);
        try result.appendSlice(&data_type);

        var identifier = item.identifier;
        std.mem.reverse(u8, &identifier);
        try result.appendSlice(&identifier);
    }

    return result.toOwnedSlice();
}
