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

    var nodes = try allocator.alloc([]?[32]u8, max_depth + 1);

    for (0..max_depth + 1) |depth| {
        const num_items = try std.math.divCeil(u32, total, std.math.pow(u32, 2, @intCast(max_depth - depth)));
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

pub fn up(self: *MerkleTree) void {
    if (self.current_depth > 0) self.current_depth -= 1;
    self.current_index /= 2;
}

pub fn left(self: *MerkleTree) void {
    self.current_depth += 1;
    self.current_index *= 2;
}

pub fn right(self: *MerkleTree) void {
    self.current_depth += 1;
    self.current_index = self.current_index * 2 + 1;
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

pub fn populateTree(self: *MerkleTree, flag_bits: []u1, hashes: [][32]u8) !void {
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

const testing = std.testing;
const testing_alloc = testing.allocator;

test "MerkleTree: init" {
    const tree = try MerkleTree.init(testing_alloc, 9);
    defer tree.deinit();

    try testing.expectEqual(tree.nodes[0].len, 1);
    try testing.expectEqual(tree.nodes[1].len, 2);
    try testing.expectEqual(tree.nodes[2].len, 3);
    try testing.expectEqual(tree.nodes[3].len, 5);
    try testing.expectEqual(tree.nodes[4].len, 9);
}

test "MerkleTree: populateTree" {
    {
        const hashes_bytes = [_][]u8{
            try utils.hexToBytes(testing_alloc, "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb"),
            try utils.hexToBytes(testing_alloc, "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b"),
            try utils.hexToBytes(testing_alloc, "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05"),
            try utils.hexToBytes(testing_alloc, "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308"),
            try utils.hexToBytes(testing_alloc, "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330"),
            try utils.hexToBytes(testing_alloc, "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add"),
            try utils.hexToBytes(testing_alloc, "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836"),
            try utils.hexToBytes(testing_alloc, "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41"),
            try utils.hexToBytes(testing_alloc, "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a"),
            try utils.hexToBytes(testing_alloc, "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9"),
            try utils.hexToBytes(testing_alloc, "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab"),
            try utils.hexToBytes(testing_alloc, "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638"),
            try utils.hexToBytes(testing_alloc, "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263"),
            try utils.hexToBytes(testing_alloc, "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800"),
            try utils.hexToBytes(testing_alloc, "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2"),
            try utils.hexToBytes(testing_alloc, "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e"),
        };
        defer for (hashes_bytes) |hash_bytes| testing_alloc.free(hash_bytes);

        var hashes = try testing_alloc.alloc([32]u8, hashes_bytes.len);
        defer testing_alloc.free(hashes);

        for (0..hashes.len) |i| {
            hashes[i] = std.mem.bytesToValue([32]u8, hashes_bytes[i]);
        }

        var tree = try MerkleTree.init(testing_alloc, @intCast(hashes.len));
        defer tree.deinit();

        var flag_bits = [_]u1{1} ** 31;
        try tree.populateTree(&flag_bits, hashes);

        const merkle_root = try utils.hexToBytes(testing_alloc, "597c4bafe3832b17cbbabe56f878f4fc2ad0f6a402cee7fa851a9cb205f87ed1");
        defer testing_alloc.free(merkle_root);

        try testing.expectEqualSlices(u8, merkle_root, &tree.root().?);
    }

    {
        const hashes_bytes = [_][]u8{
            try utils.hexToBytes(testing_alloc, "42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e"),
            try utils.hexToBytes(testing_alloc, "94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4"),
            try utils.hexToBytes(testing_alloc, "959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953"),
            try utils.hexToBytes(testing_alloc, "a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2"),
            try utils.hexToBytes(testing_alloc, "62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577"),
        };
        defer for (hashes_bytes) |hash_bytes| testing_alloc.free(hash_bytes);

        var hashes = try testing_alloc.alloc([32]u8, hashes_bytes.len);
        defer testing_alloc.free(hashes);

        for (0..hashes.len) |i| {
            hashes[i] = std.mem.bytesToValue([32]u8, hashes_bytes[i]);
        }

        var tree = try MerkleTree.init(testing_alloc, @intCast(hashes.len));
        defer tree.deinit();

        var flag_bits = [_]u1{1} ** 11;
        try tree.populateTree(&flag_bits, hashes);

        const merkle_root = try utils.hexToBytes(testing_alloc, "a8e8bd023169b81bc56854137a135b97ef47a6a7237f4c6e037baed16285a5ab");
        defer testing_alloc.free(merkle_root);

        try testing.expectEqualSlices(u8, merkle_root, &tree.root().?);
    }
}
