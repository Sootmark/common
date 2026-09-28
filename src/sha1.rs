//! SHA-1 (FIPS 180-4), streaming.
//!
//! Broken for collision resistance and never used for integrity decisions
//! on its own; here because E01 images embed SHA-1 acquisition hashes and IR
//! reports still cite them next to SHA-256.

use std::io;

use crate::blocks::{Blocks, LengthOrder};

const INITIAL: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// A streaming SHA-1 hasher. Implements [`io::Write`].
#[derive(Debug, Clone)]
pub struct Sha1 {
    state: [u32; 5],
    blocks: Blocks,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
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
    pub fn finalize(mut self) -> [u8; 20] {
        let state = &mut self.state;
        self.blocks
            .finish(LengthOrder::Big, &mut |block| compress(state, block));
        let mut digest = [0u8; 20];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// The digest of `data`.
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// One 64-byte block; names follow FIPS 180-4 §6.1.2.
#[allow(clippy::many_single_char_names)]
fn compress(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for (word, b) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (t, &word) in w.iter().enumerate() {
        let (f, k) = match t / 20 {
            0 => ((b & c) | (!b & d), 0x5a82_7999),
            1 => (b ^ c ^ d, 0x6ed9_eba1),
            2 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(word);
        (a, b, c, d, e) = (temp, a, b.rotate_left(30), c, d);
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d, e]) {
        *word = word.wrapping_add(value);
    }
}

impl io::Write for Sha1 {
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

    /// FIPS 180-2 appendix A and NIST CSRC examples.
    #[test]
    fn nist_test_vectors() {
        assert_eq!(
            encode(&Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            encode(&Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            encode(&Sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            encode(&Sha1::digest(&vec![b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }
}
