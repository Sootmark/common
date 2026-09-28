//! Block buffering and length padding shared by MD5, SHA-1 and SHA-256
//! (the Merkle–Damgård construction with 64-byte blocks).

pub(crate) const BLOCK: usize = 64;
/// Bytes the message length occupies at the end of the last block.
const LENGTH_FIELD: usize = 8;

/// Byte order of the message length appended in the final block.
#[derive(Clone, Copy)]
pub(crate) enum LengthOrder {
    /// MD5.
    Little,
    /// SHA-1, SHA-256.
    Big,
}

/// Collects input into 64-byte blocks for a compression function.
#[derive(Debug, Clone)]
pub(crate) struct Blocks {
    buffer: [u8; BLOCK],
    buffered: usize,
    length: u64,
}

impl Blocks {
    pub(crate) const fn new() -> Self {
        Self {
            buffer: [0; BLOCK],
            buffered: 0,
            length: 0,
        }
    }

    /// Feed `data`, calling `compress` on every complete block.
    pub(crate) fn update(&mut self, mut data: &[u8], compress: &mut impl FnMut(&[u8])) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (BLOCK - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < BLOCK {
                return;
            }
            compress(&self.buffer);
            self.buffered = 0;
        }
        let mut blocks = data.chunks_exact(BLOCK);
        for block in &mut blocks {
            compress(block);
        }
        let rest = blocks.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Append the padding (`0x80`, zeros, then the bit length) so the
    /// message ends on a block boundary, compressing the final block(s).
    pub(crate) fn finish(mut self, order: LengthOrder, compress: &mut impl FnMut(&[u8])) {
        let bits = self.length.wrapping_mul(8);
        let length = match order {
            LengthOrder::Little => bits.to_le_bytes(),
            LengthOrder::Big => bits.to_be_bytes(),
        };
        // 0x80, then zeros, then the length: pad to a multiple of BLOCK.
        let zeros = (2 * BLOCK - 1 - LENGTH_FIELD - self.buffered) % BLOCK;
        let mut padding = [0u8; 1 + (BLOCK - 1) + LENGTH_FIELD];
        padding[0] = 0x80;
        padding[1 + zeros..1 + zeros + LENGTH_FIELD].copy_from_slice(&length);
        self.update(&padding[..1 + zeros + LENGTH_FIELD], compress);
    }
}
