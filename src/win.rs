//! Windows identifiers: SIDs and GUIDs.

use crate::bytes::{Error, ErrorKind, Reader, Result};
use core::fmt::Write;

/// The only SID revision in use (`SID_REVISION`).
pub const SID_REVISION: u8 = 1;
/// Maximum sub-authorities in a SID (`SID_MAX_SUB_AUTHORITIES`).
pub const SID_MAX_SUB_AUTHORITIES: u8 = 15;
/// Per MS-DTYP 2.4.2.1, identifier authorities of 2^32 or more are written in hex.
const HEX_AUTHORITY_THRESHOLD: u64 = 1 << 32;

/// Parse a binary SID and return its string form (`S-1-5-21-…`).
///
/// Returns the SID string and the number of bytes consumed
/// (`8 + 4 × sub-authority count`).
///
/// # Errors
/// If the data is shorter than the SID claims, the revision isn't 1, or the
/// sub-authority count exceeds [`SID_MAX_SUB_AUTHORITIES`].
pub fn sid_to_string(bytes: &[u8]) -> Result<(String, usize)> {
    let mut r = Reader::new(bytes);
    if r.u8()? != SID_REVISION {
        return Err(Error {
            offset: 0,
            kind: ErrorKind::Invalid {
                expected: "SID revision 1",
            },
        });
    }
    let count = r.u8()?;
    if count > SID_MAX_SUB_AUTHORITIES {
        return Err(Error {
            offset: 1,
            kind: ErrorKind::LimitExceeded {
                requested: u64::from(count),
                limit: u64::from(SID_MAX_SUB_AUTHORITIES),
            },
        });
    }
    let authority = r.array::<6>()?;
    let authority = authority
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut s = String::from("S-1-");
    if authority >= HEX_AUTHORITY_THRESHOLD {
        let _ = write!(s, "0x{authority:012X}");
    } else {
        let _ = write!(s, "{authority}");
    }
    for _ in 0..count {
        let _ = write!(s, "-{}", r.u32_le()?);
    }
    Ok((s, r.position()))
}

/// Format a GUID stored in the Windows mixed-endian layout (first three
/// fields little-endian) as lowercase `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
#[must_use]
pub fn guid_to_string(b: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

/// Read a 16-byte GUID from a reader and format it with [`guid_to_string`].
///
/// # Errors
/// If fewer than 16 bytes remain.
pub fn read_guid(r: &mut Reader<'_>) -> Result<String> {
    Ok(guid_to_string(&r.array::<16>()?))
}

/// Common name for a well-known SID or a well-known domain RID, if any.
/// Domain SIDs are matched on their final RID (`S-1-5-21-…-500`).
#[must_use]
pub fn well_known_sid_name(sid: &str) -> Option<&'static str> {
    let fixed = match sid {
        "S-1-0-0" => Some("Nobody"),
        "S-1-1-0" => Some("Everyone"),
        "S-1-2-0" => Some("Local"),
        "S-1-3-0" => Some("Creator Owner"),
        "S-1-5-2" => Some("Network"),
        "S-1-5-4" => Some("Interactive"),
        "S-1-5-6" => Some("Service"),
        "S-1-5-7" => Some("Anonymous Logon"),
        "S-1-5-11" => Some("Authenticated Users"),
        "S-1-5-18" => Some("Local System"),
        "S-1-5-19" => Some("Local Service"),
        "S-1-5-20" => Some("Network Service"),
        "S-1-5-32-544" => Some("Administrators"),
        "S-1-5-32-545" => Some("Users"),
        "S-1-5-32-546" => Some("Guests"),
        "S-1-5-32-555" => Some("Remote Desktop Users"),
        _ => None,
    };
    if fixed.is_some() {
        return fixed;
    }
    let rid = sid.strip_prefix("S-1-5-21-")?.rsplit('-').next()?;
    match rid {
        "500" => Some("Administrator"),
        "501" => Some("Guest"),
        "502" => Some("krbtgt"),
        "512" => Some("Domain Admins"),
        "513" => Some("Domain Users"),
        "515" => Some("Domain Computers"),
        "516" => Some("Domain Controllers"),
        "519" => Some("Enterprise Admins"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn local_system_sid() {
        let bytes = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(sid_to_string(&bytes).unwrap(), ("S-1-5-18".to_string(), 12));
    }

    #[test]
    fn domain_sid_with_trailing_data() {
        let mut bytes = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1_111_111_111, 2_222_222_222, 3_333_333_333, 1_001] {
            bytes.extend_from_slice(&sub.to_le_bytes());
        }
        bytes.extend_from_slice(&[0xff, 0xff]);
        let (sid, used) = sid_to_string(&bytes).unwrap();
        assert_eq!(sid, "S-1-5-21-1111111111-2222222222-3333333333-1001");
        assert_eq!(used, 28);
    }

    #[test]
    fn large_authority_is_hex() {
        let bytes = [1, 0, 0x01, 0, 0, 0, 0, 0];
        assert_eq!(sid_to_string(&bytes).unwrap().0, "S-1-0x010000000000");
    }

    #[test]
    fn rejects_bad_sids() {
        assert!(
            sid_to_string(&[2, 0, 0, 0, 0, 0, 0, 5]).is_err(),
            "revision 2"
        );
        assert!(
            sid_to_string(&[1, 16, 0, 0, 0, 0, 0, 5]).is_err(),
            "too many subs"
        );
        assert!(
            sid_to_string(&[1, 2, 0, 0, 0, 0, 0, 5, 1, 0]).is_err(),
            "truncated"
        );
    }

    #[test]
    fn guid_mixed_endian() {
        let b = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(guid_to_string(&b), "00112233-4455-6677-8899-aabbccddeeff");
        let mut r = Reader::new(&b);
        assert_eq!(
            read_guid(&mut r).unwrap(),
            "00112233-4455-6677-8899-aabbccddeeff"
        );
    }

    #[test]
    fn well_known_names() {
        assert_eq!(well_known_sid_name("S-1-5-18"), Some("Local System"));
        assert_eq!(
            well_known_sid_name("S-1-5-21-1-2-3-500"),
            Some("Administrator")
        );
        assert_eq!(well_known_sid_name("S-1-5-21-1-2-3-1001"), None);
        assert_eq!(well_known_sid_name("S-1-5-99"), None);
    }

    proptest! {
        #[test]
        fn sid_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
            if let Ok((s, used)) = sid_to_string(&bytes) {
                prop_assert!(s.starts_with("S-1-"));
                prop_assert!(used <= bytes.len());
            }
        }
    }
}
