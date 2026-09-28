# common

Shared helpers for Sootmark parsers. A toolbox, not a contract: parsers use it internally and emit their own types, so each parser can depend on whichever version it likes.

| Module | What it does |
|---|---|
| `time` | Converts FILETIME, Unix (s/ms/µs/ns), WebKit/Chrome, OLE, HFS, Cocoa and FAT/DOS times to one canonical value: signed 100 ns ticks since 1970-01-01 UTC, with source precision and meaning. Zero and sentinel values are never turned into 1601 or 1970. |
| `bytes` | A bounds-checked reader for untrusted input. Never panics; every error carries the absolute offset. `checked_count` caps allocations driven by input values. |
| `text` | UTF-16LE decoding that never loses information: unpaired surrogates and odd bytes are escaped, not replaced. |
| `win` | Windows SIDs and GUIDs, plus well-known SID names. |
| `checksum` | CRC-32 (IEEE) and CRC-32C (Castagnoli), streaming. |
| `sha256` | SHA-256 (FIPS 180-4), streaming, `io::Write` for `io::copy`; checked against the NIST vectors. |
| `json` | A JSON value type, compact and pretty output, and a strict RFC 8259 parser with a nesting limit for untrusted input. |

## Guarantees

- Written from scratch, no dependencies: nothing to license, nothing to audit but this code. Builds for `wasm32-unknown-unknown`.
- `#![forbid(unsafe_code)]`, `clippy::pedantic` clean.
- Property tests: calendar round-trips, lossless FILETIME, and no panics on arbitrary input.

## Use

```toml
[dependencies]
common = { git = "https://github.com/Sootmark/common", tag = "v0.2.0" }
```

```rust
use common::time::Ts;

let ts = Ts::from_filetime(125_911_584_000_000_000);
assert_eq!(ts.to_string(), "2000-01-01T00:00:00.0000000Z");
assert_eq!(Ts::from_filetime(0).to_string(), "<not set>");
```

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
