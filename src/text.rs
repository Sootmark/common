//! UTF-16 text that never loses information.
//!
//! Windows artifacts store UTF-16LE, and it is frequently broken: unpaired
//! surrogates in attacker-crafted file names, odd trailing bytes, garbage
//! after a NUL. Replacing bad units with U+FFFD would destroy evidence and
//! make two different names look identical. Here, every unpaired surrogate
//! is escaped as `\u{XXXX}` and an odd trailing byte as `\x{XX}`, and the
//! result says whether any escaping happened.

use core::fmt::Write;

/// Decoded text plus whether the input needed escaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The text, with invalid units escaped.
    pub text: String,
    /// True if the input contained unpaired surrogates or an odd byte.
    pub escaped: bool,
}

/// Decode UTF-16LE bytes in full (NULs included).
#[must_use]
pub fn utf16le(bytes: &[u8]) -> Decoded {
    decode(bytes, false)
}

/// Decode UTF-16LE bytes up to the first NUL code unit (or the end).
#[must_use]
pub fn utf16le_until_nul(bytes: &[u8]) -> Decoded {
    decode(bytes, true)
}

fn decode(bytes: &[u8], stop_at_nul: bool) -> Decoded {
    let (units, trailing_byte) = split_units(bytes, stop_at_nul);
    let mut text = String::with_capacity(units.len() / 2);
    let mut escaped = false;
    for item in char::decode_utf16(
        units
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]])),
    ) {
        match item {
            Ok(c) => text.push(c),
            Err(e) => {
                escaped = true;
                let _ = write!(text, "\\u{{{:04x}}}", e.unpaired_surrogate());
            }
        }
    }
    if let Some(byte) = trailing_byte {
        escaped = true;
        let _ = write!(text, "\\x{{{byte:02x}}}");
    }
    Decoded { text, escaped }
}

/// The whole code units to decode, and a dangling odd byte if decoding runs
/// to the end of the input.
fn split_units(bytes: &[u8], stop_at_nul: bool) -> (&[u8], Option<u8>) {
    let whole_units = bytes.len() & !1;
    if stop_at_nul {
        if let Some(nul) = bytes[..whole_units]
            .chunks_exact(2)
            .position(|c| c == [0, 0])
        {
            return (&bytes[..nul * 2], None);
        }
    }
    (&bytes[..whole_units], bytes.get(whole_units).copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn le(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn plain_text() {
        let d = utf16le(&le(&[0x0041, 0x00e9, 0x4e2d]));
        assert_eq!(d.text, "Aé中");
        assert!(!d.escaped);
    }

    #[test]
    fn surrogate_pairs_decode() {
        let d = utf16le(&le(&[0xd83d, 0xde00]));
        assert_eq!(d.text, "😀");
        assert!(!d.escaped);
    }

    #[test]
    fn unpaired_surrogates_are_escaped_not_replaced() {
        let d = utf16le(&le(&[0x0061, 0xd800, 0x0062, 0xdc00]));
        assert_eq!(d.text, "a\\u{d800}b\\u{dc00}");
        assert!(d.escaped);
    }

    #[test]
    fn stops_at_nul_only_when_asked() {
        let bytes = le(&[0x0061, 0x0000, 0x0062]);
        assert_eq!(utf16le_until_nul(&bytes).text, "a");
        assert_eq!(utf16le(&bytes).text, "a\0b");
    }

    #[test]
    fn odd_trailing_byte_is_kept() {
        let mut bytes = le(&[0x0061]);
        bytes.push(0xab);
        let d = utf16le(&bytes);
        assert_eq!(d.text, "a\\x{ab}");
        assert!(d.escaped);
        // …but not when decoding stopped earlier at a NUL.
        let mut bytes = le(&[0x0061, 0x0000]);
        bytes.push(0xab);
        assert!(!utf16le_until_nul(&bytes).escaped);
    }

    proptest! {
        #[test]
        fn valid_strings_round_trip(s in "\\PC*") {
            let units: Vec<u16> = s.encode_utf16().collect();
            let d = utf16le(&le(&units));
            prop_assert_eq!(d.text, s);
            prop_assert!(!d.escaped);
        }

        #[test]
        fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = utf16le(&bytes);
            let _ = utf16le_until_nul(&bytes);
        }
    }
}
