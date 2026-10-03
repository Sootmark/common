//! Zstandard frames made by the reference `zstd` CLI (see
//! `tests/fixtures/zstd/generate.py`), whole and damaged.

use std::io;
use std::path::Path;

use proptest::prelude::*;
use sootmark_common::sha256::{self, Sha256};
use sootmark_common::zstd::{decompress, is_zstd};

const LIMIT: usize = 1 << 20;
/// Size of the `mixed-*` inputs.
const MIXED_SIZE: usize = 300 * 1024;

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/zstd")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn error_text(data: &[u8], limit: usize) -> String {
    decompress(data, limit).unwrap_err().to_string()
}

#[test]
fn decodes_every_reference_vector() {
    let sums = String::from_utf8(fixture("SHA256SUMS")).unwrap();
    for line in sums.lines() {
        let [digest, length, name] = line.split(' ').collect::<Vec<_>>()[..] else {
            panic!("bad SHA256SUMS line: {line}");
        };
        let data = fixture(name);
        assert!(is_zstd(&data), "{name}");
        let output = decompress(&data, LIMIT).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(output.len().to_string(), length, "{name}");
        assert_eq!(sha256::hex(&Sha256::digest(&output)), digest, "{name}");
    }
}

#[test]
fn enforces_the_output_limit() {
    let mixed = fixture("mixed-19.zst");
    assert_eq!(decompress(&mixed, MIXED_SIZE).unwrap().len(), MIXED_SIZE);
    // Declared content size, then a pipe-made frame that declares none.
    assert!(error_text(&mixed, MIXED_SIZE - 1).contains("larger than expected"));
    assert!(error_text(&fixture("zeros.zst"), 1000).contains("larger than expected"));
    assert!(error_text(&fixture("text-pipe.zst"), 1000).contains("larger than expected"));
}

#[test]
fn detects_a_bad_checksum() {
    let mut data = fixture("text-3.zst");
    let last = data.len() - 1;
    data[last] ^= 1;
    assert!(error_text(&data, LIMIT).contains("XXH64"));
}

#[test]
fn rejects_what_is_not_a_frame() {
    assert!(decompress(b"", LIMIT).is_err());
    assert!(error_text(b"hello, zstd\n", LIMIT).contains("not a zstd stream"));
    let mut junk = fixture("hello.zst");
    junk.extend_from_slice(b"junk");
    assert!(error_text(&junk, LIMIT).contains("data after the last frame"));
    let skippable_only = [0x5f, 0x2a, 0x4d, 0x18, 2, 0, 0, 0, 0xaa, 0xbb];
    assert!(!is_zstd(&skippable_only));
    assert_eq!(decompress(&skippable_only, LIMIT).unwrap(), b"");
    let cut_skippable = &skippable_only[..9];
    assert_eq!(
        decompress(cut_skippable, LIMIT).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn truncation_is_an_error() {
    for name in ["hello.zst", "dna.zst", "text-pipe.zst"] {
        let data = fixture(name);
        let near_end = data.len().saturating_sub(64);
        let lengths = (1..near_end).step_by(53).chain(near_end..data.len());
        for length in lengths {
            assert!(
                decompress(&data[..length], LIMIT).is_err(),
                "{name} cut to {length}"
            );
        }
    }
}

proptest! {
    /// Arbitrary bytes, alone or after the frame magic, never panic.
    #[test]
    fn arbitrary_input_never_panics(body in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decompress(&body, LIMIT);
        let framed: Vec<u8> = [0x28, 0xb5, 0x2f, 0xfd].into_iter().chain(body).collect();
        let _ = decompress(&framed, LIMIT);
    }

    /// Damaged reference frames decode or fail: never a panic. Besides
    /// changes anywhere, some land in the first 256 bytes, where the
    /// headers and tables are.
    #[test]
    fn damage_never_panics(
        which in 0usize..4,
        flips in proptest::collection::vec((any::<proptest::sample::Index>(), any::<u8>()), 1..8),
        early in proptest::collection::vec((0usize..256, any::<u8>()), 0..4),
    ) {
        let name = ["text-19.zst", "dna.zst", "frames.zst", "mixed-19.zst"][which];
        let mut data = fixture(name);
        for (at, byte) in flips {
            let at = at.index(data.len());
            data[at] = byte;
        }
        for (at, byte) in early {
            let at = at % data.len();
            data[at] ^= byte;
        }
        let _ = decompress(&data, LIMIT);
    }
}
