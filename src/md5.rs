//! MD5 (RFC 1321), streaming.
//!
//! Broken for collision resistance and never used for integrity decisions
//! on its own; here because E01 images embed MD5 acquisition hashes and IR
//! reports still cite them next to SHA-256.

use std::io;

use crate::blocks::{Blocks, LengthOrder};

/// Per-round left rotations (RFC 1321 §3.4).
const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// `floor(abs(sin(i + 1)) * 2^32)` for i in 0..64 (RFC 1321 §3.4).
const T: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

const INITIAL: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// A streaming MD5 hasher. Implements [`io::Write`].
#[derive(Debug, Clone)]
pub struct Md5 {
    state: [u32; 4],
    blocks: Blocks,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// A new hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INITIAL,
            blocks: Blocks::new(),
        }
    }

    /// Add `data`.
    pub fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.blocks
            .update(data, &mut |block| compress(state, block));
    }

    /// The digest of everything added.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        let state = &mut self.state;
        self.blocks
            .finish(LengthOrder::Little, &mut |block| compress(state, block));
        let mut digest = [0u8; 16];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        digest
    }

    /// The digest of `data`.
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// One 64-byte block; names follow RFC 1321 §3.4.
#[allow(clippy::many_single_char_names)]
fn compress(state: &mut [u32; 4], block: &[u8]) {
    let mut x = [0u32; 16];
    for (word, b) in x.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    }
    let [mut a, mut b, mut c, mut d] = *state;
    for i in 0..64 {
        let (f, g) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let rotated = a
            .wrapping_add(f)
            .wrapping_add(T[i])
            .wrapping_add(x[g])
            .rotate_left(SHIFTS[i]);
        (a, b, c, d) = (d, b.wrapping_add(rotated), b, c);
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d]) {
        *word = word.wrapping_add(value);
    }
}

impl io::Write for Md5 {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::encode;

    /// RFC 1321 appendix A.5.
    #[test]
    fn rfc_1321_test_suite() {
        let cases = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                encode(&Md5::digest(input.as_bytes())),
                expected,
                "{input:?}"
            );
        }
    }
}
