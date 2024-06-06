const std = @import("std");
const utils = @import("../utils.zig");
const Cmd = @import("../script/script.zig").Cmd;
const S256Point = @import("../ecc//s256_point.zig");
const Signature = @import("../ecc/signature.zig");
const Opcode = @import("opcode.zig");

const Interpreter = @This();

allocator: std.mem.Allocator,

pub const Error = error{ OpcodeNotFound, MissingZOption };

pub const Options = struct {
    stack: *std.ArrayList([]const u8),
    alt_stack: ?*std.ArrayList([]const u8) = null,
    cmds: ?*std.ArrayList(Cmd) = null,
    z: ?u256 = null,
};

pub const Instruction = fn (Interpreter, Options) Error!bool;

pub const table: [256]Instruction = init: {
    var map: [256]Instruction = undefined;
    for (0..256) |i| {
        map[i] = switch (@as(Opcode, @enumFromInt(i))) {
            .OP_DUP => opDup,
            .OP_HASH256 => opHash256,
            .OP_HASH160 => opHash160,
            .OP_CHECKSIG => opCheckSig,
            .OP_EQUAL => opEqual,
            .OP_VERIFY => opVerify,
            .OP_EQUALVERIFY => opEqualVerify,
            else => notFound,
        };
    }

    break :init map;
};

pub fn init(allocator: std.mem.Allocator) Interpreter {
    return .{
        .allocator = allocator,
    };
}

fn opEqual(self: Interpreter, options: Options) !bool {
    if (options.stack.items.len < 2) {
        return false;
    }

    const element1 = options.stack.pop();
    const element2 = options.stack.pop();

    if (std.mem.eql(u8, element1, element2)) {
        try options.stack.append(self.encodeNum(1));
    } else {
        try options.stack.append(self.encodeNum(0));
    }

    return true;
}

fn opVerify(self: Interpreter, options: Options) !bool {
    if (options.stack.items.len == 0) {
        return false;
    }

    const element = options.stack.pop();
    if (try self.decodeNum(element) == 0) {
        return false;
    }

    return true;
}

fn opEqualVerify(self: Interpreter, options: Options) !bool {
    return self.opEqual(options) and self.opVerify(options);
}

fn opDup(self: Interpreter, options: Options) !bool {
    if (options.stack.items.len < 1) {
        return false;
    }

    const last = try self.allocator.dupe(u8, self.stack.getLast());
    try options.stack.append(last);

    return true;
}

fn opCheckSig(self: Interpreter, options: Options) !bool {
    if (options.z == null) {
        return Error.MissingZOption;
    }
    const z = options.z.?;

    if (options.stack.items.len < 2) {
        return false;
    }

    const sec_pubkey = options.stack.pop();
    const last = options.stack.pop();
    const der_signature = last[0 .. last.len - 1];

    const point = try S256Point.fromSec(sec_pubkey);
    const sig = try Signature.fromDer(der_signature);

    if (point.verify(z, sig)) {
        options.stack.append(self.encodeNum(1));
    } else {
        options.stack.append(self.encodeNum(0));
    }

    return true;
}

fn opHash256(self: Interpreter, options: Options) !bool {
    if (options.stack.items.len < 1) {
        return false;
    }

    const last = options.stack.pop();
    defer self.allocator.free(last);

    const last_hash256 = try self.allocator.alloc(u8, 32);
    last_hash256[0..32].* = utils.hash256(&last);

    try options.stack.append(last_hash256);

    return true;
}

fn opHash160(self: Interpreter, options: Options) !bool {
    if (options.stack.items.len < 1) {
        return false;
    }

    const last = options.stack.pop();
    defer self.allocator.free(last);

    const last_hash160 = try self.allocator.alloc(u8, 20);
    last_hash160[0..20].* = utils.hash160(&last);

    try options.stack.append(last_hash160);

    return true;
}

pub fn notFound(_: Interpreter, _: Options) !bool {
    return Error.OpcodeNotFound;
}

pub fn encodeNum(self: Interpreter, num: i512) ![]u8 {
    var result = std.ArrayList(u8).init(self.allocator);
    if (num == 0) {
        return result.toOwnedSlice();
    }

    var abs_num = @abs(num);
    const negative = num < 0;

    while (abs_num > 0) {
        try result.append(abs_num & 0xff);
        abs_num >>= 8;
    }

    if (result.getLast() & 0x80) {
        try result.append(if (negative) 0x80 else 0);
    } else if (negative) {
        const last = result.pop();
        try result.append(last | 0x80);
    }

    return result.toOwnedSlice();
}

pub fn decodeNum(self: Interpreter, element: []const u8) !i512 {
    if (element.len == 0) {
        return 0;
    }

    var big_endian = try self.allocator.dupe(u8, element);
    defer self.allocator.free(big_endian);
    std.mem.reverse(u8, big_endian);

    var negative = false;
    var result: i512 = big_endian[0];

    if (big_endian[0] & 0x80) {
        negative = true;
        result = big_endian[0] & 0x7f;
    }

    for (big_endian[1..]) |c| {
        result <<= 8;
        result += c;
    }

    return if (negative) -result else result;
}
