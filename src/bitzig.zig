pub const utils = @import("utils.zig");

pub const ecc = struct {
    pub const constants = @import("ecc/constants.zig");
    pub const FieldElement = @import("ecc/field_element.zig");
    pub const Point = @import("ecc/point.zig");
    pub const S256Point = @import("ecc/s256_point.zig");
    pub const Signature = @import("ecc/signature.zig");
    pub const PrivateKey = @import("ecc/private_key.zig");
};

pub const transaction = struct {
    pub const Transaction = @import("transaction/transaction.zig");
    pub const TransactionInput = @import("transaction/transaction_input.zig");
    pub const TransactionOutput = @import("transaction/transaction_output.zig");
    pub const TransactionFetcher = @import("transaction/transaction_fetcher.zig");
};

pub const script = struct {
    pub const Script = @import("script/script.zig");
};

pub const interpreter = struct {
    pub const Interpreter = @import("interpreter/interpreter.zig");
    pub usingnamespace @import("interpreter/opcode.zig");
};

pub const block = struct {
    pub const constants = @import("block/constants.zig");
    pub const Block = @import("block/block.zig");
};

pub const network = struct {
    pub const NetworkEnvelope = @import("network/network_envelope.zig");
    pub const message = struct {
        pub const VersionMessage = @import("network/message/version_message.zig");
        pub const PingMessage = @import("network/message/ping_message.zig");
        pub const PongMessage = @import("network/message/pong_message.zig");
        pub const VerAckMessage = @import("network/message/ver_ack_message.zig");
        pub const GetHeadersMessage = @import("network/message/get_headers_message.zig");
        pub const HeadersMessage = @import("network/message/headers_message.zig");
        pub const GetDataMessage = @import("network/message/get_data_message.zig");
    };
    pub const SimpleNode = @import("network/simple_node.zig");
};

pub const merkle = struct {
    pub const MerkleTree = @import("merkle/merkle_tree.zig");
    pub const MerkleBlock = @import("merkle/merkle_block.zig");
};

pub const bloom_filter = struct {
    pub const BloomFilter = @import("bloom_filter/bloom_filter.zig");
};

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
