const std = @import("std");
const utils = @import("../utils.zig");
const Opcode = @import("../interpreter/opcode.zig").Opcode;

const Script = @This();

const Error = error{ InvalidEncoding, TooLongCmd };

const Cmd = union(enum) {
    opcode: Opcode,
    element: []const u8,
};

allocator: std.mem.Allocator,
cmds: []Cmd,

pub fn init(allocator: std.mem.Allocator, cmds: [][]const u8) Script {
    return .{ .allocator = allocator, .cmds = cmds };
}

pub fn deinit(self: Script) void {
    for (self.cmds) |cmd| {
        if (cmd == .element) {
            self.allocator.free(cmd.element);
        }
    }
    self.allocator.free(self.cmds);
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !Script {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(allocator: std.mem.Allocator, reader: anytype) !Script {
    const length = utils.readVarintFromReader(reader) catch return Error.InvalidEncoding;
    const cmds = std.ArrayList([]const u8).init(allocator);
    var count: usize = 0;

    while (count < length) {
        const current_byte = reader.readByte() catch return Error.InvalidEncoding;
        count += 1;

        if (current_byte >= 1 and current_byte <= 75) {
            const buf = try allocator.alloc(u8, current_byte);
            try reader.readNoEof(buf) catch return Error.InvalidEncoding;
            try cmds.append(.{ .element = buf });
            count += current_byte;
        } else if (current_byte == 76) {
            const data_length = reader.readByte() catch return Error.InvalidEncoding;
            const buf = try allocator.alloc(u8, data_length);
            try reader.readNoEof(buf);
            try cmds.append(.{ .element = buf });
            count += data_length + 1;
        } else if (current_byte == 77) {
            const data_length = utils.readIntFromReader(u16, reader, .little) catch return Error.InvalidEncoding;
            const buf = try allocator.alloc(u8, data_length);
            try reader.readNoEof(buf);
            try cmds.append(.{ .element = buf });
            count += data_length + 2;
        } else {
            const opcode: Opcode = @enumFromInt(current_byte);
            try cmds.append(.{ .opcode = opcode });
        }
    }

    if (count != length) {
        return Error.InvalidEncoding;
    }

    return init(allocator, try cmds.toOwnedSlice());
}

pub fn toString(self: Script, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    for (self.cmds, 0..) |cmd, i| {
        switch (cmd) {
            .opcode => |opcode| {
                const name = opcode.name();
                try result.appendSlice(name);
            },
            .element => |element| {
                const element_hex = std.fmt.bytesToHex(element, .lower);
                try result.appendSlice(element_hex);
            },
        }

        if (i != self.cmds.len - 1) {
            try result.append(' ');
        }
    }

    return result.toOwnedSlice();
}

pub fn rawSerialize(self: Script, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    for (self.cmds) |cmd| {
        switch (cmd) {
            .opcode => |opcode| try result.append(opcode),
            .element => |element| {
                const length = element.len;
                if (length < 75) {
                    try result.append(length);
                } else if (length > 75 and length < 0x100) {
                    try result.append(76);
                    try result.append(length);
                } else if (length >= 0x100 and length <= 520) {
                    try result.append(77);
                    const length_bytes = utils.encodeInt(u16, length, .little);
                    try result.appendSlice(&length_bytes);
                } else {
                    return Error.TooLongCmd;
                }
                try result.appendSlice(element);
            },
        }
    }

    return result.toOwnedSlice();
}

pub fn serialize(self: Script, allocator: std.mem.Allocator) ![]u8 {
    const result = try self.rawSerialize(allocator);
    defer allocator.free(result);

    const length = try utils.encodeVarint(allocator, result.len);
    defer allocator.free(length);

    return std.mem.concat(allocator, u8, &.{ length, result });
}
