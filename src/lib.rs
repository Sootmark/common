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

pub mod bytes;
pub mod text;
pub mod time;
pub mod win;
