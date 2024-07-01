const std = @import("std");
const utils = @import("../utils.zig");

const MerkleTree = @This();

allocator: std.mem.Allocator,
total: u32,
max_depth: u32,
nodes: [][]?[32]u8,
current_depth: u32 = 0,
current_index: u32 = 0,

pub fn init(allocator: std.mem.Allocator, total: u32) !MerkleTree {
    const max_depth = std.math.log2_int_ceil(u32, total);

    var nodes = try allocator.alloc([][]?[32]u8, max_depth + 1);

    for (0..max_depth + 1) |depth| {
        const num_items = try std.math.divCeil(u32, total, std.math.pow(u32, 2, max_depth - depth));
        const level_hashes = try allocator.alloc(?[32]u8, num_items);
        @memset(level_hashes, null);

        nodes[depth] = level_hashes;
    }

    return .{ .allocator = allocator, .total = total, .max_depth = max_depth, .nodes = nodes };
}

pub fn deinit(self: MerkleTree) void {
    for (self.nodes) |level| self.allocator.free(level);
    self.allocator.free(self.nodes);
}

pub fn toString(self: MerkleTree, allocator: std.mem.Allocator) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);

    for (self.nodes, 0..) |level, depth| {
        for (level, 0..) |hash, index| {
            const short = if (hash) |h| std.fmt.bytesToHex(h, .lower)[0..8] else "None";

            if (depth == self.current_depth and index == self.current_index) {
                try result.append('*');
                try result.appendSlice(short[0 .. short.len - 2]);
                try result.append('*');
            } else try result.appendSlice(short);

            if (index != level.len - 1) try result.appendSlice(", ");
        }
        if (depth != self.nodes.len - 1) try result.append('\n');
    }

    return result.toOwnedSlice();
}

pub fn up(self: MerkleTree) void {
    self.current_depth -= 1;
    self.current_index /= 2;
}

pub fn left(self: MerkleTree) void {
    self.current_depth += 1;
    self.current_index *= 2;
}

pub fn right(self: MerkleTree) void {
    self.current_depth += 1;
    self.current_depth = self.current_index * 2 + 1;
}

pub fn root(self: MerkleTree) ?[32]u8 {
    return self.nodes[0][0];
}

pub fn setCurrentNode(self: MerkleTree, value: [32]u8) void {
    self.nodes[self.current_depth][self.current_index] = value;
}

pub fn getCurrentNode(self: MerkleTree) ?[32]u8 {
    return self.nodes[self.current_depth][self.current_index];
}

pub fn getLeftNode(self: MerkleTree) ?[32]u8 {
    return self.nodes[self.current_depth + 1][self.current_index * 2];
}

pub fn getRightNode(self: MerkleTree) ?[32]u8 {
    return self.nodes[self.current_depth + 1][self.current_index * 2 + 1];
}

pub fn isLeaf(self: MerkleTree) bool {
    return self.current_depth == self.max_depth;
}

pub fn rightExists(self: MerkleTree) bool {
    return self.nodes[self.current_depth + 1].len > self.current_index * 2 + 1;
}

pub fn populateTree(self: MerkleTree, flag_bits: []u8, hashes: [][32]u8) !void {
    var flag_index: usize = 0;
    var hash_index: usize = 0;

    while (self.root() == null) {
        if (self.isLeaf()) {
            self.setCurrentNode(hashes[hash_index]);
            flag_index += 1;
            hash_index += 1;
            self.up();
        } else {
            const left_hash = self.getLeftNode();
            if (left_hash == null) {
                if (flag_bits[flag_index] == 0) {
                    self.setCurrentNode(hashes[hash_index]);
                    flag_index += 1;
                    hash_index += 1;
                    self.up();
                } else {
                    flag_index += 1;
                    self.left();
                }
            } else if (self.rightExists()) {
                const right_hash = self.getRightNode();
                if (right_hash == null) {
                    self.right();
                } else {
                    self.setCurrentNode(utils.merkleParent(left_hash.?, right_hash.?));
                    self.up();
                }
            } else {
                self.setCurrentNode(utils.merkleParent(left_hash.?, left_hash.?));
                self.up();
            }
        }
    }

    if (hash_index != hashes.len) {
        return error.HashesNotAllConsumed;
    }

    for (flag_bits[flag_index..]) |bit| {
        if (bit != 0) return error.FlagBitsNotAllConsumed;
    }
}
