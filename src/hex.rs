//! Lowercase hexadecimal encoding of digests and raw bytes.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex of `bytes`.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 0xf)]])
        .map(char::from)
        .collect()
}
