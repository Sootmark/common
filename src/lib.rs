//! Shared helpers for Sootmark parsers.
//!
//! This crate is a toolbox, not a contract. Parsers use it internally and
//! emit plain data that follows the Sootmark output spec; none of these
//! types need to appear in a parser's output, so parsers can depend on
//! different versions of this crate without affecting each other.
//!
//! - [`time`]: every forensic timestamp format → one canonical value
//! - [`bytes`]: bounds-checked reading of untrusted input
//! - [`text`]: UTF-16 decoding that never loses information
//! - [`win`]: Windows SIDs and GUIDs
//! - [`checksum`]: CRC-32 and CRC-32C
//! - [`sha256`]: SHA-256 for evidence hashing
//! - [`md5`], [`sha1`]: legacy digests embedded in E01 images and cited in reports
//! - [`hex`]: lowercase hex encoding
//! - [`deflate`]: DEFLATE/Deflate64 and zlib decompression
//! - [`json`]: JSON values, output and a strict parser
//!
//! Written from scratch with no dependencies, so it builds everywhere
//! (including `wasm32`) and carries no third-party licence obligations.

mod blocks;
pub mod bytes;
pub mod checksum;
pub mod deflate;
pub mod hex;
pub mod json;
pub mod md5;
pub mod sha1;
pub mod sha256;
pub mod text;
pub mod time;
pub mod win;
