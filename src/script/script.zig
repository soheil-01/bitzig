const std = @import("std");
const utils = @import("../utils.zig");
const Opcode = @import("../interpreter/opcode.zig").Opcode;
const Interpreter = @import("../interpreter/interpreter.zig");

const Script = @This();

const Error = error{ InvalidEncoding, TooLongCmd };

pub const Cmd = union(enum) {
    opcode: Opcode,
    element: []const u8,

    pub fn free(self: Cmd, allocator: std.mem.Allocator) void {
        switch (self) {
            .element => |element| allocator.free(element),
            else => {},
        }
    }

    pub fn clone(self: Cmd, allocator: std.mem.Allocator) !Cmd {
        switch (self) {
            .opcode => return self,
            .element => |element| {
                const element_copy = try allocator.dupe(u8, element);
                return .{ .element = element_copy };
            },
        }
    }
};

allocator: std.mem.Allocator,
cmds: std.ArrayList(Cmd),

pub fn init(allocator: std.mem.Allocator, cmds: ?[]const Cmd) !Script {
    var commands = std.ArrayList(Cmd).init(allocator);

    if (cmds != null) {
        try commands.appendSlice(cmds.?);
    }

    return .{ .allocator = allocator, .cmds = commands };
}

pub fn p2pkhScript(allocator: std.mem.Allocator, h160: [20]u8) !Script {
    const h160_element = try allocator.dupe(u8, &h160);

    return Script.init(allocator, &.{ Cmd{ .opcode = .OP_DUP }, Cmd{ .opcode = .OP_HASH160 }, Cmd{ .element = h160_element }, Cmd{ .opcode = .OP_EQUALVERIFY }, Cmd{ .opcode = .OP_CHECKSIG } });
}

pub fn deinit(self: Script) void {
    for (self.cmds.items) |cmd| {
        if (cmd == .element) {
            self.allocator.free(cmd.element);
        }
    }
    self.cmds.deinit();
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !Script {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(allocator: std.mem.Allocator, reader: anytype) !Script {
    const length = utils.readVarintFromReader(reader) catch return Error.InvalidEncoding;
    var cmds = std.ArrayList(Cmd).init(allocator);
    var count: usize = 0;

    while (count < length) {
        const current_byte = reader.readByte() catch return Error.InvalidEncoding;
        count += 1;

        if (current_byte >= 1 and current_byte <= 75) {
            const buf = try allocator.alloc(u8, current_byte);
            reader.readNoEof(buf) catch return Error.InvalidEncoding;
            try cmds.append(.{ .element = buf });
            count += current_byte;
        } else if (current_byte == 76) {
            const data_length = reader.readByte() catch return Error.InvalidEncoding;
            const buf = try allocator.alloc(u8, data_length);
            reader.readNoEof(buf) catch return Error.InvalidEncoding;
            try cmds.append(.{ .element = buf });
            count += data_length + 1;
        } else if (current_byte == 77) {
            const data_length = utils.readIntFromReader(u16, reader, .little) catch return Error.InvalidEncoding;
            const buf = try allocator.alloc(u8, data_length);
            reader.readNoEof(buf) catch return Error.InvalidEncoding;
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

    return .{ .allocator = allocator, .cmds = cmds };
}

pub fn toString(self: Script, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    for (self.cmds.items, 0..) |cmd, i| {
        switch (cmd) {
            .opcode => |opcode| {
                const name = opcode.name();
                try result.appendSlice(name);
            },
            .element => |element| {
                const element_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(element)});
                try result.appendSlice(element_hex);
                allocator.free(element_hex);
            },
        }

        if (i != self.cmds.items.len - 1) {
            try result.append(' ');
        }
    }

    return result.toOwnedSlice();
}

pub fn evaluate(self: Script, z: u256) !bool {
    var cmds = try self.cmds.clone();
    defer cmds.deinit();

    var stack = std.ArrayList([]const u8).init(self.allocator);
    defer stack.deinit();

    defer for (stack.items) |item| {
        self.allocator.free(item);
    };

    var alt_stack = std.ArrayList([]const u8).init(self.allocator);
    defer alt_stack.deinit();

    defer for (alt_stack.items) |item| {
        self.allocator.free(item);
    };

    const interpreter = Interpreter.init(self.allocator);

    while (cmds.popOrNull()) |cmd| {
        switch (cmd) {
            .opcode => |opcode| {
                const operation = Interpreter.table[@intFromEnum(opcode)];

                switch (opcode) {
                    .OP_IF, .OP_NOTIF => {
                        if (!try operation(interpreter, .{ .stack = &stack, .cmds = &cmds })) {
                            // TODO: log error
                            return false;
                        }
                    },
                    .OP_TOALTSTACK, .OP_FROMALTSTACK => {
                        if (!try operation(interpreter, .{ .stack = &stack, .alt_stack = &alt_stack })) {
                            // TODO: log error
                            return false;
                        }
                    },
                    .OP_CHECKSIG, .OP_CHECKSIGVERIFY, .OP_CHECKMULTISIG, .OP_CHECKMULTISIGVERIFY => {
                        if (!try operation(interpreter, .{ .stack = &stack, .z = z })) {
                            // TODO: log error
                            return false;
                        }
                    },
                    else => {
                        if (!try operation(interpreter, .{ .stack = &stack })) {
                            // TODO: log error
                            return false;
                        }
                    },
                }
            },
            .element => |element| {
                try stack.append(element);
            },
        }
    }

    if (stack.items.len == 0) {
        return false;
    }

    const last = stack.pop();
    defer self.allocator.free(last);

    if (last.len == 0) {
        return false;
    }

    return true;
}

pub fn add(self: Script, other: Script, allocator: std.mem.Allocator) !Script {
    var cmds = std.ArrayList(Cmd).init(allocator);
    errdefer cmds.deinit();

    for (self.cmds.items) |cmd| {
        try cmds.append(try cmd.clone(allocator));
    }

    for (other.cmds.items) |cmd| {
        try cmds.append(try cmd.clone(allocator));
    }

    return .{ .allocator = allocator, .cmds = cmds };
}

pub fn rawSerialize(self: Script, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    for (self.cmds.items) |cmd| {
        switch (cmd) {
            .opcode => |opcode| try result.append(@intFromEnum(opcode)),
            .element => |element| {
                const length = element.len;
                if (length < 75) {
                    try result.append(@intCast(length));
                } else if (length > 75 and length < 0x100) {
                    try result.append(76);
                    try result.append(@intCast(length));
                } else if (length >= 0x100 and length <= 520) {
                    try result.append(77);
                    const length_bytes = utils.encodeInt(u16, @intCast(length), .little);
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
