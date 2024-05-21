pub const ecc = struct {
    pub const constants = @import("ecc/constants.zig");
    pub const utils = @import("ecc/utils.zig");
    pub const FieldElement = @import("ecc/field_element.zig");
    pub const ECPoint = @import("ecc/ec_point.zig");
    pub const S256Point = @import("ecc/s256_point.zig");
    pub const Signature = @import("ecc/signature.zig");
    pub const PrivateKey = @import("ecc/private_key.zig");
};

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
