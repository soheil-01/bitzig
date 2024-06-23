const std = @import("std");
const utils = @import("../utils.zig");
const Interpreter = @import("../interpreter/interpreter.zig");
const Opcode = @import("../interpreter/opcode.zig").Opcode;

const Script = @This();

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
            .opcode => |opcode| return .{ .opcode = opcode },
            .element => |element| {
                const element_copy = try allocator.dupe(u8, element);
                return .{ .element = element_copy };
            },
        }
    }
};

allocator: std.mem.Allocator,
cmds: std.ArrayList(Cmd),

pub fn init(allocator: std.mem.Allocator) !Script {
    return .{ .allocator = allocator, .cmds = std.ArrayList(Cmd).init(allocator) };
}

pub fn push(self: *Script, cmd: Cmd) !void {
    try self.cmds.append(try cmd.clone(self.allocator));
}

pub fn p2pkhScript(allocator: std.mem.Allocator, h160: [20]u8) !Script {
    var cmds = std.ArrayList(Cmd).init(allocator);
    try cmds.appendSlice(&.{
        Cmd{ .opcode = .OP_DUP },
        Cmd{ .opcode = .OP_HASH160 },
        Cmd{ .element = try allocator.dupe(u8, &h160) },
        Cmd{ .opcode = .OP_EQUALVERIFY },
        Cmd{ .opcode = .OP_CHECKSIG },
    });

    return .{ .allocator = allocator, .cmds = cmds };
}

pub fn p2shScript(allocator: std.mem.Allocator, h160: [20]u8) !Script {
    var cmds = std.ArrayList(Cmd).init(allocator);
    try cmds.appendSlice(&.{
        Cmd{ .opcode = .OP_HASH160 },
        Cmd{ .element = try allocator.dupe(u8, &h160) },
        Cmd{ .opcode = .OP_EQUAL },
    });

    return .{ .allocator = allocator, .cmds = cmds };
}

pub fn deinit(self: Script) void {
    for (self.cmds.items) |cmd| cmd.free(self.allocator);
    self.cmds.deinit();
}

pub fn parse(allocator: std.mem.Allocator, source: []const u8) !Script {
    var fb = std.io.fixedBufferStream(source);
    const reader = fb.reader();

    return parseFromReader(allocator, reader);
}

pub fn parseFromReader(allocator: std.mem.Allocator, reader: anytype) !Script {
    const length = utils.readVarintFromReader(reader) catch return error.InvalidEncoding;
    var cmds = std.ArrayList(Cmd).init(allocator);
    var count: usize = 0;

    while (count < length) {
        const current_byte = reader.readByte() catch return error.InvalidEncoding;
        count += 1;

        if (current_byte >= 1 and current_byte <= 75) {
            const buf = try allocator.alloc(u8, current_byte);
            reader.readNoEof(buf) catch return error.InvalidEncoding;
            try cmds.append(.{ .element = buf });
            count += current_byte;
        } else if (current_byte == 76) {
            const data_length = reader.readByte() catch return error.InvalidEncoding;
            const buf = try allocator.alloc(u8, data_length);
            reader.readNoEof(buf) catch return error.InvalidEncoding;
            try cmds.append(.{ .element = buf });
            count += data_length + 1;
        } else if (current_byte == 77) {
            const data_length = utils.readIntFromReader(u16, reader, .little) catch return error.InvalidEncoding;
            const buf = try allocator.alloc(u8, data_length);
            reader.readNoEof(buf) catch return error.InvalidEncoding;
            try cmds.append(.{ .element = buf });
            count += data_length + 2;
        } else {
            const opcode: Opcode = @enumFromInt(current_byte);
            try cmds.append(.{ .opcode = opcode });
        }
    }

    if (count != length) {
        return error.InvalidEncoding;
    }

    return .{ .allocator = allocator, .cmds = cmds };
}

pub fn isP2pkhScriptPubkey(self: Script) bool {
    const cmds = self.cmds.items;

    // OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    return cmds.len == 5 and
        cmds[0] == .opcode and
        cmds[0].opcode == .OP_DUP and
        cmds[1] == .opcode and
        cmds[1].opcode == .OP_HASH160 and
        cmds[2] == .element and
        cmds[2].element.len == 20 and
        cmds[3] == .opcode and
        cmds[3].opcode == .OP_EQUALVERIFY and
        cmds[4] == .opcode and
        cmds[4].opcode == .OP_CHECKSIG;
}

pub fn isP2shScriptPubkey(self: Script) bool {
    const cmds = self.cmds.items;

    // OP_HASH160 <20-byte hash> OP_EQUAL
    return cmds.len == 3 and
        cmds[0] == .opcode and
        cmds[0].opcode == .OP_HASH160 and
        cmds[1] == .element and
        cmds[1].element.len == 20 and
        cmds[2] == .opcode and
        cmds[2].opcode == .OP_EQUAL;
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

    std.mem.reverse(Cmd, cmds.items);

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
                try stack.append(try self.allocator.dupe(u8, element));
                if (cmds.items.len == 3 and
                    cmds.items[0] == .opcode and
                    cmds.items[0].opcode == .OP_HASH160 and
                    cmds.items[1] == .element and
                    cmds.items[1].element.len == 20 and
                    cmds.items[2] == .opcode and
                    cmds.items[2].opcode == .OP_EQUAL)
                {
                    _ = cmds.pop();

                    if (!try Interpreter.table[@intFromEnum(Opcode.OP_HASH160)](interpreter, .{ .stack = &stack })) {
                        return false;
                    }

                    const h160 = cmds.pop();
                    _ = cmds.pop();

                    try stack.append(h160.element);

                    if (!try Interpreter.table[@intFromEnum(Opcode.OP_EQUALVERIFY)](interpreter, .{ .stack = &stack })) {
                        return false;
                    }

                    const element_len = try utils.encodeVarint(self.allocator, element.len);
                    const script_source = try std.mem.concat(self.allocator, u8, &.{ element_len, element });
                    defer self.allocator.free(script_source);

                    const script = try Script.parse(
                        self.allocator,
                        script_source,
                    );
                    defer self.allocator.free(script.cmds.items);

                    try cmds.appendSlice(script.cmds.items);
                }
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

pub fn clone(self: Script, allocator: std.mem.Allocator) !Script {
    var cmds = std.ArrayList(Cmd).init(allocator);
    errdefer cmds.deinit();

    for (self.cmds.items) |cmd| {
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
                    return error.TooLongCmd;
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

const testing = std.testing;
const testing_alloc = testing.allocator;

test "Script: parse" {
    const script_pubkey = try utils.hexToBytes(testing_alloc, "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937");
    defer testing_alloc.free(script_pubkey);

    const script = try Script.parse(testing_alloc, script_pubkey);
    defer script.deinit();

    const cmd0_expected = try utils.hexToBytes(testing_alloc, "304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601");
    defer testing_alloc.free(cmd0_expected);

    try testing.expectEqualSlices(u8, cmd0_expected, script.cmds.items[0].element);

    const cmd1_expected = try utils.hexToBytes(testing_alloc, "035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937");
    defer testing_alloc.free(cmd1_expected);

    try testing.expectEqualSlices(u8, cmd1_expected, script.cmds.items[1].element);
}

test "Script: serialize" {
    const script_pubkey = try utils.hexToBytes(testing_alloc, "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937");
    defer testing_alloc.free(script_pubkey);

    const script = try Script.parse(testing_alloc, script_pubkey);
    defer script.deinit();

    const serialized_script = try script.serialize(testing_alloc);
    defer testing_alloc.free(serialized_script);

    try testing.expectEqualSlices(u8, script_pubkey, serialized_script);
}
