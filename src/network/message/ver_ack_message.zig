const VerAckMessage = @This();

pub const command = "verack";

pub fn serialize(_: VerAckMessage) ![]u8 {
    return &[_]u8{};
}
