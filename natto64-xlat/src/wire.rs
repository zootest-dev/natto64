//! Allocation-free big-endian integer conversion helpers for packet fields.

/// Decodes a 16-bit integer from network byte order.
pub fn read_u16_be(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes)
}

/// Decodes a 32-bit integer from network byte order.
pub fn read_u32_be(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

/// Encodes a 16-bit integer in network byte order.
pub fn write_u16_be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// Encodes a 32-bit integer in network byte order.
pub fn write_u32_be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}
