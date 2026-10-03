//! gzip (RFC 1952) as a stream: a header, DEFLATE data, then the CRC-32
//! and length of what it held, each checked. Several members in a row
//! read as one stream, as `gunzip` does; zero bytes after the last member
//! (padding some tools add) are ignored, anything else is an error.

use std::io::{self, Read};

use crate::checksum::Crc32;
use crate::deflate::{Inflate, Variant};

const MAGIC: [u8; 2] = [0x1f, 0x8b];
const METHOD_DEFLATE: u8 = 8;
const FLAG_HCRC: u8 = 0x02;
const FLAG_EXTRA: u8 = 0x04;
const FLAG_NAME: u8 = 0x08;
const FLAG_COMMENT: u8 = 0x10;

/// Whether `head` starts a gzip stream.
#[must_use]
pub fn is_gzip(head: &[u8]) -> bool {
    head.len() >= 3 && head[..2] == MAGIC && head[2] == METHOD_DEFLATE
}

/// The input, with bytes read ahead put back in front of it.
struct Input<R> {
    ahead: Vec<u8>,
    at: usize,
    inner: R,
}

impl<R: Read> Read for Input<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at < self.ahead.len() {
            let n = out.len().min(self.ahead.len() - self.at);
            out[..n].copy_from_slice(&self.ahead[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        self.inner.read(out)
    }
}

impl<R: Read> Input<R> {
    fn byte(&mut self) -> io::Result<Option<u8>> {
        let mut one = [0u8];
        Ok((self.read(&mut one)? == 1).then_some(one[0]))
    }

    fn exact(&mut self, out: &mut [u8]) -> io::Result<()> {
        self.read_exact(out)
            .map_err(|_| corrupt("gzip stream cut short"))
    }
}

enum State<R> {
    /// Before a member's header (`first`: none read yet).
    Header {
        input: Input<R>,
        first: bool,
    },
    Body {
        inflate: Inflate<Input<R>>,
        crc: Crc32,
        size: u32,
    },
    Done,
}

/// A gzip decoder over `R`.
pub struct Decoder<R> {
    state: State<R>,
}

impl<R: Read> Decoder<R> {
    /// Decode the gzip stream read from `input`.
    pub fn new(input: R) -> Self {
        Self {
            state: State::Header {
                input: Input {
                    ahead: Vec::new(),
                    at: 0,
                    inner: input,
                },
                first: true,
            },
        }
    }
}

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("corrupt gzip data: {what}"),
    )
}

/// Read a member's header; `None` at a clean end of the stream.
fn header<R: Read>(input: &mut Input<R>, first: bool) -> io::Result<Option<()>> {
    let Some(b0) = input.byte()? else {
        return if first {
            Err(corrupt("empty"))
        } else {
            Ok(None)
        };
    };
    if !first && b0 == 0 {
        // Padding after the last member: the rest must be zeros too.
        let mut rest = Vec::new();
        input.read_to_end(&mut rest)?;
        return if rest.iter().all(|&b| b == 0) {
            Ok(None)
        } else {
            Err(corrupt("data after the last member"))
        };
    }
    let mut fixed = [0u8; 9];
    input.exact(&mut fixed)?;
    if [b0, fixed[0]] != MAGIC || fixed[1] != METHOD_DEFLATE {
        return Err(corrupt(if first {
            "not a gzip stream"
        } else {
            "data after the last member"
        }));
    }
    let flags = fixed[2];
    if flags & FLAG_EXTRA != 0 {
        let mut length = [0u8; 2];
        input.exact(&mut length)?;
        let mut extra = vec![0u8; usize::from(u16::from_le_bytes(length))];
        input.exact(&mut extra)?;
    }
    for flag in [FLAG_NAME, FLAG_COMMENT] {
        if flags & flag != 0 {
            while input
                .byte()?
                .ok_or_else(|| corrupt("gzip header cut short"))?
                != 0
            {}
        }
    }
    if flags & FLAG_HCRC != 0 {
        input.exact(&mut [0u8; 2])?;
    }
    Ok(Some(()))
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            match std::mem::replace(&mut self.state, State::Done) {
                State::Done => return Ok(0),
                State::Header { mut input, first } => {
                    if header(&mut input, first)?.is_none() {
                        return Ok(0);
                    }
                    self.state = State::Body {
                        inflate: Inflate::new(input, Variant::Deflate),
                        crc: Crc32::new(),
                        size: 0,
                    };
                }
                State::Body {
                    mut inflate,
                    mut crc,
                    mut size,
                } => {
                    let n = inflate.read(out)?;
                    if n > 0 || out.is_empty() {
                        crc.update(&out[..n]);
                        size = size.wrapping_add(n as u32);
                        self.state = State::Body { inflate, crc, size };
                        return Ok(n);
                    }
                    // End of the member: its trailer, then maybe another.
                    let (rest, input) = inflate.into_rest();
                    let mut input = Input {
                        ahead: rest
                            .into_iter()
                            .chain(input.ahead[input.at..].iter().copied())
                            .collect(),
                        at: 0,
                        inner: input.inner,
                    };
                    let mut trailer = [0u8; 8];
                    input.exact(&mut trailer)?;
                    if u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]])
                        != crc.finalize()
                    {
                        return Err(corrupt("CRC-32 mismatch"));
                    }
                    if u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]) != size
                    {
                        return Err(corrupt("length mismatch"));
                    }
                    self.state = State::Header {
                        input,
                        first: false,
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `printf 'hello, gzip\n' | gzip -9 -n`.
    const MEMBER: &str = "1f8b0800000000000203cb48cdc9c9d75148afca2ce00200861f82a40c000000";
    /// The same with its file name in the header (`gzip -9 -c note.txt`).
    const NAMED: &str =
        "1f8b0808f0aa556902036e6f74652e74787400cb48cdc9c9d75148afca2ce00200861f82a40c000000";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn decode(data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        Decoder::new(data).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn members_in_a_row_and_padding() {
        let member = hex(MEMBER);
        assert!(is_gzip(&member));
        assert_eq!(decode(&member).unwrap(), b"hello, gzip\n");
        assert_eq!(decode(&hex(NAMED)).unwrap(), b"hello, gzip\n");
        let mut two = member.repeat(2);
        two.extend_from_slice(&[0, 0]);
        assert_eq!(decode(&two).unwrap(), b"hello, gzip\nhello, gzip\n");
    }

    #[test]
    fn damage_is_an_error() {
        let member = hex(MEMBER);
        let mut crc = member.clone();
        let at = crc.len() - 6;
        crc[at] ^= 0xff;
        assert!(decode(&crc).is_err(), "CRC-32");
        assert!(decode(&member[..member.len() - 3]).is_err(), "cut short");
        let mut garbage = member.clone();
        garbage.extend_from_slice(b"junk");
        assert!(decode(&garbage).is_err(), "data after the last member");
        assert!(decode(b"").is_err());
    }

    proptest::proptest! {
        /// Damaged streams decode or fail: never a panic.
        #[test]
        fn damage_never_panics(flips in proptest::collection::vec((0usize..64, proptest::prelude::any::<u8>()), 0..6), cut in 0usize..64) {
            let mut data = hex(NAMED);
            for (at, byte) in flips {
                let len = data.len();
                data[at % len] = byte;
            }
            data.truncate(cut.max(1));
            let _ = decode(&data);
        }
    }
}
