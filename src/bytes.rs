//! Bounds-checked reading of untrusted input.
//!
//! Evidence is hostile by definition: a record can claim to be 4 GB long,
//! point past the end of its buffer, or loop back on itself. [`Reader`] never
//! panics on bad input. Every failure is an [`Error`] carrying the offset
//! where it happened, so parsers can report *where* a file is corrupt.
//! [`checked_count`] caps allocations driven by values read from the input.

use core::fmt;

/// A reading failure, with the absolute offset where it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Offset (from the start of the reader's base buffer) of the failure.
    pub offset: usize,
    /// What went wrong.
    pub kind: ErrorKind,
}

/// The kind of reading failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// Needed more bytes than remain.
    UnexpectedEof {
        /// Bytes requested.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// A size or count read from the input exceeds the caller's limit.
    LimitExceeded {
        /// What the input asked for.
        requested: u64,
        /// The limit.
        limit: u64,
    },
    /// A structural value that isn't allowed (e.g. an unknown version).
    Invalid {
        /// What was expected, for the error message.
        expected: &'static str,
    },
    /// A seek outside the buffer.
    OutOfBounds {
        /// The requested position.
        position: usize,
        /// The buffer length.
        len: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::UnexpectedEof { needed, available } => write!(
                f,
                "unexpected end of data at offset {}: needed {needed} bytes, {available} available",
                self.offset
            ),
            ErrorKind::LimitExceeded { requested, limit } => write!(
                f,
                "value at offset {} asks for {requested}, above the limit of {limit}",
                self.offset
            ),
            ErrorKind::Invalid { expected } => {
                write!(
                    f,
                    "invalid data at offset {}: expected {expected}",
                    self.offset
                )
            }
            ErrorKind::OutOfBounds { position, len } => write!(
                f,
                "position {position} is outside the {len}-byte buffer (at offset {})",
                self.offset
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        Self::new(std::io::ErrorKind::InvalidData, error)
    }
}

/// Result alias for this module.
pub type Result<T> = core::result::Result<T, Error>;

/// A cursor over a byte slice that never panics.
///
/// Offsets in errors are absolute: a sub-reader created with
/// [`Reader::sub`] reports offsets relative to the original buffer.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
}

/// Generates a fixed-width integer reader with complete docs.
macro_rules! read_int {
    ($name:ident, $ty:ty, $from:ident, $endian:literal) => {
        #[doc = concat!("Read a ", $endian, " `", stringify!($ty), "`.")]
        ///
        /// # Errors
        /// [`ErrorKind::UnexpectedEof`] if too few bytes remain.
        pub fn $name(&mut self) -> Result<$ty> {
            Ok(<$ty>::$from(self.array()?))
        }
    };
}

impl<'a> Reader<'a> {
    /// A reader positioned at the start of `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            base: 0,
        }
    }

    /// Current position, relative to this reader's start.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Current absolute offset (includes the base of sub-readers).
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.base + self.pos
    }

    /// Bytes left after the current position.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Total length of this reader's slice.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether this reader's slice is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn eof(&self, needed: usize) -> Error {
        Error {
            offset: self.offset(),
            kind: ErrorKind::UnexpectedEof {
                needed,
                available: self.remaining(),
            },
        }
    }

    /// Move to `position` (relative to this reader's start).
    ///
    /// # Errors
    /// [`ErrorKind::OutOfBounds`] if `position` is past the end.
    pub fn seek(&mut self, position: usize) -> Result<()> {
        if position > self.data.len() {
            return Err(Error {
                offset: self.offset(),
                kind: ErrorKind::OutOfBounds {
                    position,
                    len: self.data.len(),
                },
            });
        }
        self.pos = position;
        Ok(())
    }

    /// Advance by `n` bytes.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedEof`] if fewer than `n` bytes remain.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }

    /// Read `n` bytes, borrowing from the input.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedEof`] if fewer than `n` bytes remain.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(self.eof(n));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Look at the next `n` bytes without consuming them.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedEof`] if fewer than `n` bytes remain.
    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(self.eof(n));
        }
        Ok(&self.data[self.pos..self.pos + n])
    }

    /// Read a fixed-size array.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedEof`] if fewer than `N` bytes remain.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    /// A reader over the next `n` bytes, consuming them from this one.
    /// Errors from the sub-reader report absolute offsets.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedEof`] if fewer than `n` bytes remain.
    pub fn sub(&mut self, n: usize) -> Result<Reader<'a>> {
        let base = self.offset();
        let data = self.bytes(n)?;
        Ok(Reader { data, pos: 0, base })
    }

    /// Read one byte.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedEof`] at the end of the data.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    read_int!(u16_le, u16, from_le_bytes, "little-endian");
    read_int!(u16_be, u16, from_be_bytes, "big-endian");
    read_int!(u32_le, u32, from_le_bytes, "little-endian");
    read_int!(u32_be, u32, from_be_bytes, "big-endian");
    read_int!(u64_le, u64, from_le_bytes, "little-endian");
    read_int!(u64_be, u64, from_be_bytes, "big-endian");
    read_int!(i16_le, i16, from_le_bytes, "little-endian");
    read_int!(i32_le, i32, from_le_bytes, "little-endian");
    read_int!(i64_le, i64, from_le_bytes, "little-endian");
    read_int!(f64_le, f64, from_le_bytes, "little-endian");
}

/// Validate a count read from untrusted input before allocating for it.
///
/// Returns `count` as `usize` if `count <= max`, and if `count * elem_size`
/// bytes could actually be present in `available` bytes of input. The second
/// check stops a 10-byte file from claiming four billion records.
///
/// # Errors
/// [`ErrorKind::LimitExceeded`] (reported at `offset`) otherwise.
pub fn checked_count(
    count: u64,
    elem_size: usize,
    max: u64,
    available: usize,
    offset: usize,
) -> Result<usize> {
    let limit = max_elements_in(available, elem_size).min(max);
    let too_many = || Error {
        offset,
        kind: ErrorKind::LimitExceeded {
            requested: count,
            limit,
        },
    };
    if count > limit {
        return Err(too_many());
    }
    usize::try_from(count).map_err(|_| too_many())
}

/// Up to 8 bytes as a little-endian integer.
pub(crate) fn le_u64(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, &byte| value << 8 | u64::from(byte))
}

/// How many `elem_size`-byte elements fit in `available` bytes.
fn max_elements_in(available: usize, elem_size: usize) -> u64 {
    if elem_size == 0 {
        u64::MAX
    } else {
        (available / elem_size) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn reads_integers_in_both_endiannesses() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut r = Reader::new(&data);
        assert_eq!(r.u16_le().unwrap(), 0x0201);
        assert_eq!(r.u16_be().unwrap(), 0x0304);
        assert_eq!(r.u32_le().unwrap(), 0x0807_0605);
        assert_eq!(r.remaining(), 0);
        let mut r = Reader::new(&data);
        assert_eq!(r.u64_be().unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn eof_reports_offset_and_sizes() {
        let mut r = Reader::new(&[1, 2, 3]);
        r.skip(2).unwrap();
        let err = r.u32_le().unwrap_err();
        assert_eq!(err.offset, 2);
        assert_eq!(
            err.kind,
            ErrorKind::UnexpectedEof {
                needed: 4,
                available: 1
            }
        );
        assert_eq!(r.position(), 2, "a failed read doesn't move the cursor");
    }

    #[test]
    fn sub_reader_reports_absolute_offsets() {
        let data = [0u8; 16];
        let mut r = Reader::new(&data);
        r.skip(10).unwrap();
        let mut sub = r.sub(4).unwrap();
        sub.skip(3).unwrap();
        let err = sub.u16_le().unwrap_err();
        assert_eq!(err.offset, 13);
        assert_eq!(r.position(), 14);
    }

    #[test]
    fn seek_and_peek() {
        let mut r = Reader::new(&[9, 8, 7]);
        assert_eq!(r.peek(2).unwrap(), &[9, 8]);
        assert_eq!(r.position(), 0);
        r.seek(3).unwrap();
        assert!(r.seek(4).is_err());
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn checked_count_caps_allocations() {
        assert_eq!(checked_count(10, 4, 100, 40, 0).unwrap(), 10);
        // Above the explicit limit.
        assert!(matches!(
            checked_count(101, 1, 100, 1_000, 7).unwrap_err().kind,
            ErrorKind::LimitExceeded { requested: 101, .. }
        ));
        // A tiny input claiming a huge number of records.
        let err = checked_count(4_000_000_000, 8, u64::MAX, 10, 3).unwrap_err();
        assert_eq!(err.offset, 3);
        // Overflowing multiplication is rejected, not wrapped.
        assert!(checked_count(u64::MAX, 16, u64::MAX, usize::MAX, 0).is_err());
    }

    proptest! {
        #[test]
        fn never_panics_on_arbitrary_input(data in proptest::collection::vec(any::<u8>(), 0..64),
                                           ops in proptest::collection::vec(0u8..8, 0..32)) {
            let mut r = Reader::new(&data);
            for op in ops {
                let _ = match op {
                    0 => r.u8().map(|_| ()),
                    1 => r.u16_le().map(|_| ()),
                    2 => r.u32_be().map(|_| ()),
                    3 => r.u64_le().map(|_| ()),
                    4 => r.skip(usize::from(op) * 3),
                    5 => r.sub(5).map(|_| ()),
                    6 => r.seek(data.len() / 2),
                    _ => r.f64_le().map(|_| ()),
                };
                prop_assert!(r.position() <= data.len());
            }
        }
    }
}
