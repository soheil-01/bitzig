const std = @import("std");
const utils = @import("../utils.zig");
const S256Point = @import("../ecc/s256_point.zig");
const Signature = @import("../ecc/signature.zig");
const Cmd = @import("../script/script.zig").Cmd;
const Opcode = @import("opcode.zig").Opcode;

const Interpreter = @This();

allocator: std.mem.Allocator,

pub const Options = struct {
    stack: *std.ArrayList([]const u8),
    alt_stack: ?*std.ArrayList([]const u8) = null,
    cmds: ?*std.ArrayList(Cmd) = null,
    z: ?u256 = null,
};

pub const Instruction = fn (Interpreter, Options) anyerror!bool;
pub const InstructionPtr = *const Instruction;

pub const table: [256]InstructionPtr = init: {
    var map: [256]InstructionPtr = undefined;
    for (0..256) |i| {
        if (Opcode.isValid(i)) {
            map[i] = switch (@as(Opcode, @enumFromInt(i))) {
                .OP_DUP => opDup,
                .OP_HASH256 => opHash256,
                .OP_HASH160 => opHash160,
                .OP_CHECKSIG => opCheckSig,
                .OP_EQUAL => opEqual,
                .OP_VERIFY => opVerify,
                .OP_EQUALVERIFY => opEqualVerify,
                .OP_CHECKMULTISIG => opCheckMultiSig,
                .OP_0 => push(0),
                .OP_1 => push(1),
                .OP_2 => push(2),
                else => notFound,
            };
        }
    }

    break :init map;
};

pub fn init(allocator: std.mem.Allocator) Interpreter {
    return .{
        .allocator = allocator,
    };
}

fn push(comptime n: comptime_int) InstructionPtr {
    const pushT = struct {
        fn push(self: Interpreter, options: Options) !bool {
            try options.stack.append(try self.encodeNum(n));
            return true;
        }
    };

    return pushT.push;
}

fn opEqual(self: Interpreter, options: Options) !bool {
    if (options.stack.items.len < 2) {
        return false;
    }

    const element1 = options.stack.pop();
    defer self.allocator.free(element1);

    const element2 = options.stack.pop();
    defer self.allocator.free(element2);

    if (std.mem.eql(u8, element1, element2)) {
        try options.stack.append(try self.encodeNum(1));
    } else {
        try options.stack.append(try self.encodeNum(0));
    }

    return true;
}

fn opVerify(self: Interpreter, options: Options) !bool {
    if (options.stack.items.len == 0) {
        return false;
    }

    const element = options.stack.pop();
    defer self.allocator.free(element);

    if (try self.decodeNum(element) == 0) {
        return false;
    }

    return true;
}

fn opEqualVerify(self: Interpreter, options: Options) !bool {
    return try self.opEqual(options) and try self.opVerify(options);
}

fn opDup(self: Interpreter, options: Options) !bool {
    if (options.stack.items.len < 1) {
        return false;
    }

    const last = try self.allocator.dupe(u8, options.stack.getLast());
    try options.stack.append(last);

    return true;
}

fn opCheckMultiSig(self: Interpreter, options: Options) !bool {
    if (options.z == null) {
        return error.MissingZOption;
    }
    const z = options.z.?;

    if (options.stack.items.len < 1) {
        return false;
    }

    const n_bytes = options.stack.pop();
    defer self.allocator.free(n_bytes);
    const n: usize = @intCast(try self.decodeNum(n_bytes));
    if (options.stack.items.len < n + 1) {
        return false;
    }

    var sec_pubkeys = try std.ArrayList([]const u8).initCapacity(self.allocator, n);
    defer {
        for (sec_pubkeys.items) |sec_pubkey| self.allocator.free(sec_pubkey);
        sec_pubkeys.deinit();
    }

    for (0..n) |_| {
        try sec_pubkeys.append(options.stack.pop());
    }

    const m_bytes = options.stack.pop();
    defer self.allocator.free(m_bytes);
    const m: usize = @intCast(try self.decodeNum(m_bytes));
    if (options.stack.items.len < m + 1) {
        return false;
    }

    var der_signatures = try std.ArrayList([]const u8).initCapacity(self.allocator, m);
    defer {
        for (der_signatures.items) |der_signature| self.allocator.free(der_signature);
        der_signatures.deinit();
    }

    for (0..m) |_| {
        try der_signatures.append(options.stack.pop());
    }

    self.allocator.free(options.stack.pop());

    var points = try std.ArrayList(S256Point).initCapacity(self.allocator, n);
    defer points.deinit();

    for (sec_pubkeys.items) |sec_pubkey| {
        try points.append(try S256Point.fromSec(sec_pubkey));
    }

    std.mem.reverse(S256Point, points.items);

    var sigs = try std.ArrayList(Signature).initCapacity(self.allocator, m);
    defer sigs.deinit();

    for (der_signatures.items) |der_signature| {
        try sigs.append(try Signature.fromDer(der_signature[0 .. der_signature.len - 1]));
    }

    for (sigs.items) |sig| {
        var sig_valid = false;

        while (points.popOrNull()) |point| {
            if (point.verify(z, sig)) {
                sig_valid = true;
                break;
            }
        }

        if (!sig_valid) {
            // TODO: log error
            return false;
        }
    }

    try options.stack.append(try self.encodeNum(1));
    return true;
}

fn opCheckSig(self: Interpreter, options: Options) !bool {
    if (options.z == null) {
        return error.MissingZOption;
    }
    const z = options.z.?;

    if (options.stack.items.len < 2) {
        return false;
    }

    const sec_pubkey = options.stack.pop();
    defer self.allocator.free(sec_pubkey);

    const last = options.stack.pop();
    defer self.allocator.free(last);

    const der_signature = last[0 .. last.len - 1];

    const point = try S256Point.fromSec(sec_pubkey);
    const sig = try Signature.fromDer(der_signature);

    if (point.verify(z, sig)) {
        try options.stack.append(try self.encodeNum(1));
    } else {
        try options.stack.append(try self.encodeNum(0));
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
    last_hash256[0..32].* = utils.hash256(last);

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
    last_hash160[0..20].* = utils.hash160(last);

    try options.stack.append(last_hash160);

    return true;
}

pub fn notFound(_: Interpreter, _: Options) !bool {
    return error.OpcodeNotFound;
}

pub fn encodeNum(self: Interpreter, num: i512) ![]u8 {
    var result = std.ArrayList(u8).init(self.allocator);
    if (num == 0) {
        return result.toOwnedSlice();
    }

    var abs_num = @abs(num);
    const negative = num < 0;

    while (abs_num > 0) {
        try result.append(@intCast(abs_num & 0xff));
        abs_num >>= 8;
    }

    if (result.getLast() & 0x80 > 0) {
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

    if (result & 0x80 > 0) {
        negative = true;
        result &= 0x7f;
    }

    for (big_endian[1..]) |c| {
        result <<= 8;
        result += c;
    }

    return if (negative) -result else result;
}

const testing = std.testing;
const testing_alloc = testing.allocator;

test "Interpreter: hash160" {
    const interpreter = Interpreter.init(testing_alloc);

    var stack = std.ArrayList([]const u8).init(testing_alloc);
    defer stack.deinit();

    const string = try testing_alloc.dupe(u8, "hello world");
    try stack.append(string);

    try testing.expect(try interpreter.opHash160(.{ .stack = &stack }));

    const hash160 = stack.pop();
    defer testing_alloc.free(hash160);

    const hash160_hex = std.fmt.bytesToHex(hash160[0..20], .lower);

    try testing.expectEqualSlices(u8, "d7d5ee7824ff93f94c3055af9382c86c68b5ca92", &hash160_hex);
}

test "Interpreter: opCheckSig" {
    const interpreter = Interpreter.init(testing_alloc);

    var stack = std.ArrayList([]const u8).init(testing_alloc);
    defer stack.deinit();

    const z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d;

    const sec = try utils.hexToBytes(testing_alloc, "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34");
    const sig = try utils.hexToBytes(testing_alloc, "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601");

    try stack.appendSlice(&.{ sig, sec });

    try testing.expect(try interpreter.opCheckSig(.{ .stack = &stack, .z = z }));

    const last = stack.pop();
    defer testing_alloc.free(last);

    try testing.expect(try interpreter.decodeNum(last) == 1);
}
