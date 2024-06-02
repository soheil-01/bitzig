const std = @import("std");
const utils = @import("../utils.zig");
const Opcode = @import("opcode.zig");

const Interpreter = @This();

allocator: std.mem.Allocator,
stack: std.ArrayList([]u8),

pub const Error = error{OpcodeNotFound};

pub const Instruction = fn (Interpreter) Error!void;

const table: [256]Instruction = init: {
    var map: [256]Instruction = undefined;
    for (0..256) |i| {
        map[i] = switch (@as(Opcode, @enumFromInt(i))) {
            .OP_DUP => opDup,
            .OP_HASH256 => opHash256,
            .OP_HASH160 => opHash160,
            else => notFound,
        };
    }

    break :init map;
};

pub fn init(allocator: std.mem.Allocator) Interpreter {
    return .{ .allocator = allocator, .stack = std.ArrayList([]u8).init(allocator) };
}

pub fn deinit(self: Interpreter) void {
    for (self.stack.items) |item| {
        self.allocator.free(item);
    }
    self.stack.deinit();
}

fn opDup(self: Interpreter) !bool {
    if (self.stack.items.len < 1) {
        return false;
    }

    const last = try self.allocator.dupe(u8, self.stack.getLast());
    try self.stack.append(last);

    return true;
}

fn opHash256(self: Interpreter) !bool {
    if (self.stack.items.len < 1) {
        return false;
    }

    const last = self.stack.pop();
    defer self.allocator.free(last);

    const last_hash256 = try self.allocator.alloc(u8, 32);
    last_hash256[0..32].* = utils.hash256(&last);

    try self.stack.append(last_hash256);

    return true;
}

fn opHash160(self: Interpreter) !bool {
    if (self.stack.items.len < 1) {
        return false;
    }

    const last = self.stack.pop();
    defer self.allocator.free(last);

    const last_hash160 = try self.allocator.alloc(u8, 20);
    last_hash160[0..20].* = utils.hash160(&last);

    try self.stack.append(last_hash160);

    return true;
}

pub fn notFound(_: Interpreter) !bool {
    return Error.OpcodeNotFound;
}
