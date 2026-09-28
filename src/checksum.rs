//! CRC-32 checksums, streaming.
//!
//! - [`Crc32`]: the IEEE 802.3 polynomial (zip, EVTX, PNG, …).
//! - [`Crc32c`]: the Castagnoli polynomial (VHDX, iSCSI, …).

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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn standard_check_values() {
        assert_eq!(Crc32::of(b"123456789"), 0xcbf4_3926);
        assert_eq!(Crc32c::of(b"123456789"), 0xe306_9283);
        assert_eq!(Crc32::of(b""), 0);
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
