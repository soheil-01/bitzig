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
    pub const Block = @import("block/block.zig");
};

pub const network = struct {
    pub const NetworkEnvelope = @import("network/network_envelope.zig");
    pub const message = struct {
        pub const VersionMessage = @import("network/message/version_message.zig");
    };
};

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
