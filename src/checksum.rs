//! CRC-32 checksums, streaming.
//!
//! - [`Crc32`]: the IEEE 802.3 polynomial (zip, EVTX, PNG, …).
//! - [`Crc32c`]: the Castagnoli polynomial (VHDX, iSCSI, …).
//! - [`adler32`]: the zlib checksum (E01, zlib streams).
//! - [`xxh64`]: XXH64, the Zstandard content checksum.

use crate::bytes::le_u64;

/// Reflected IEEE 802.3 polynomial.
const IEEE: u32 = 0xedb8_8320;
/// Reflected Castagnoli polynomial.
const CASTAGNOLI: u32 = 0x82f6_3b78;

const fn table(polynomial: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ polynomial
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const IEEE_TABLE: [u32; 256] = table(IEEE);
const CASTAGNOLI_TABLE: [u32; 256] = table(CASTAGNOLI);

fn update(table: &[u32; 256], mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc = table[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

macro_rules! crc {
    ($(#[$doc:meta])* $name:ident, $table:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy)]
        pub struct $name(u32);

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// A new, empty checksum.
            #[must_use]
            pub const fn new() -> Self {
                Self(!0)
            }

            /// Add `data` to the checksum.
            pub fn update(&mut self, data: &[u8]) {
                self.0 = update(&$table, self.0, data);
            }

            /// The checksum of everything added so far.
            #[must_use]
            pub const fn finalize(self) -> u32 {
                !self.0
            }

            /// The checksum of `data`.
            #[must_use]
            pub fn of(data: &[u8]) -> u32 {
                let mut crc = Self::new();
                crc.update(data);
                crc.finalize()
            }
        }
    };
}

crc!(
    /// CRC-32 (IEEE 802.3).
    Crc32,
    IEEE_TABLE
);
crc!(
    /// CRC-32C (Castagnoli).
    Crc32c,
    CASTAGNOLI_TABLE
);

/// Largest prime below 2^16.
const ADLER_MODULUS: u32 = 65_521;
/// Bytes that can be summed before the sums must be reduced (no overflow).
const ADLER_BLOCK: usize = 5_552;

/// Adler-32 (RFC 1950) of `data`.
#[must_use]
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for block in data.chunks(ADLER_BLOCK) {
        for &byte in block {
            a += u32::from(byte);
            b += a;
        }
        a %= ADLER_MODULUS;
        b %= ADLER_MODULUS;
    }
    (b << 16) | a
}

const XXH_PRIME_1: u64 = 0x9e37_79b1_85eb_ca87;
const XXH_PRIME_2: u64 = 0xc2b2_ae3d_27d4_eb4f;
const XXH_PRIME_3: u64 = 0x1656_67b1_9e37_79f9;
const XXH_PRIME_4: u64 = 0x85eb_ca77_c2b2_ae63;
const XXH_PRIME_5: u64 = 0x27d4_eb2f_1656_67c5;
/// XXH64 consumes its input in stripes of four 8-byte lanes.
const XXH_STRIPE: usize = 32;

/// XXH64 of `data` with `seed` (zstd frames use seed 0).
#[must_use]
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut stripes = data.chunks_exact(XXH_STRIPE);
    let mut hash = if data.len() < XXH_STRIPE {
        seed.wrapping_add(XXH_PRIME_5)
    } else {
        let mut lanes = [
            seed.wrapping_add(XXH_PRIME_1).wrapping_add(XXH_PRIME_2),
            seed.wrapping_add(XXH_PRIME_2),
            seed,
            seed.wrapping_sub(XXH_PRIME_1),
        ];
        for stripe in &mut stripes {
            for (lane, word) in lanes.iter_mut().zip(stripe.chunks_exact(8)) {
                *lane = xxh_round(*lane, le_u64(word));
            }
        }
        let mut hash = lanes[0]
            .rotate_left(1)
            .wrapping_add(lanes[1].rotate_left(7))
            .wrapping_add(lanes[2].rotate_left(12))
            .wrapping_add(lanes[3].rotate_left(18));
        for lane in lanes {
            hash = (hash ^ xxh_round(0, lane))
                .wrapping_mul(XXH_PRIME_1)
                .wrapping_add(XXH_PRIME_4);
        }
        hash
    };
    hash = hash.wrapping_add(data.len() as u64);
    let mut words = stripes.remainder().chunks_exact(8);
    for word in &mut words {
        hash ^= xxh_round(0, le_u64(word));
        hash = hash
            .rotate_left(27)
            .wrapping_mul(XXH_PRIME_1)
            .wrapping_add(XXH_PRIME_4);
    }
    let mut halves = words.remainder().chunks_exact(4);
    for half in &mut halves {
        hash ^= le_u64(half).wrapping_mul(XXH_PRIME_1);
        hash = hash
            .rotate_left(23)
            .wrapping_mul(XXH_PRIME_2)
            .wrapping_add(XXH_PRIME_3);
    }
    for &byte in halves.remainder() {
        hash ^= u64::from(byte).wrapping_mul(XXH_PRIME_5);
        hash = hash.rotate_left(11).wrapping_mul(XXH_PRIME_1);
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(XXH_PRIME_2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(XXH_PRIME_3);
    hash ^ (hash >> 32)
}

fn xxh_round(lane: u64, input: u64) -> u64 {
    lane.wrapping_add(input.wrapping_mul(XXH_PRIME_2))
        .rotate_left(31)
        .wrapping_mul(XXH_PRIME_1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn standard_check_values() {
        assert_eq!(Crc32::of(b"123456789"), 0xcbf4_3926);
        assert_eq!(Crc32c::of(b"123456789"), 0xe306_9283);
        assert_eq!(Crc32::of(b""), 0);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
        assert_eq!(adler32(b""), 1);
    }

    /// From `xxhsum -H64`; the inputs cover every tail length path.
    #[test]
    fn xxh64_reference_values() {
        assert_eq!(xxh64(b"", 0), 0xef46_db37_51d8_e999);
        assert_eq!(xxh64(b"a", 0), 0xd24e_c4f1_a98c_6e5b);
        assert_eq!(xxh64(b"abc", 0), 0x44bc_2cf5_ad77_0999);
        assert_eq!(xxh64(b"123456789", 0), 0x8cb8_41db_40e6_ae83);
        let fox = b"The quick brown fox jumps over the lazy dog";
        assert_eq!(xxh64(fox, 0), 0x0b24_2d36_1fda_71bc);
        let long = b"0123456789abcdef0123456789abcdef0123456789abcdefXYZ";
        assert_eq!(xxh64(long, 0), 0x2068_b5be_32b6_d8dc);
    }

    proptest! {
        #[test]
        fn streaming_equals_one_shot(data in proptest::collection::vec(any::<u8>(), 0..512), split in 0usize..512) {
            let split = split.min(data.len());
            let mut crc = Crc32::new();
            crc.update(&data[..split]);
            crc.update(&data[split..]);
            prop_assert_eq!(crc.finalize(), Crc32::of(&data));
        }
    }
}
