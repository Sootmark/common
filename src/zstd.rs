//! Zstandard (RFC 8878) decompression of whole buffers. Frames in a row
//! decode as one output, as `zstd -d` does, and skippable frames are
//! passed over. Each frame's content size and XXH64 checksum are checked
//! when present. Frames that need a dictionary are refused.

use std::borrow::Cow;
use std::io;

use crate::bytes::{le_u64, Reader};
use crate::checksum::xxh64;

const FRAME_MAGIC: u32 = 0xfd2f_b528;
/// Skippable frames use any of the 16 magic numbers 0x184d2a50..=0x184d2a5f.
const SKIPPABLE_MAGIC: u32 = 0x184d_2a50;
const SKIPPABLE_MASK: u32 = 0xffff_fff0;

const FLAG_SINGLE_SEGMENT: u8 = 0x20;
const FLAG_RESERVED: u8 = 0x08;
const FLAG_CHECKSUM: u8 = 0x04;
/// Width of the dictionary ID, by the frame header's two low bits.
const DICTIONARY_ID_WIDTH: [usize; 4] = [0, 1, 2, 4];

const RAW_BLOCK: u64 = 0;
const RLE_BLOCK: u64 = 1;
const COMPRESSED_BLOCK: u64 = 2;
/// Largest block, decompressed, whatever the window size.
const MAX_BLOCK_SIZE: u64 = 128 * 1024;

const RAW_LITERALS: u8 = 0;
const RLE_LITERALS: u8 = 1;
const COMPRESSED_LITERALS: u8 = 2;

/// Longest Huffman code for literals.
const MAX_HUFFMAN_BITS: u32 = 11;
/// Weights stored in a Huffman table description; the last one is implied.
const MAX_STORED_WEIGHTS: usize = 255;
/// Largest FSE accuracy log for the table that codes Huffman weights.
const MAX_WEIGHTS_LOG: u32 = 6;

const PREDEFINED_MODE: u8 = 0;
const RLE_MODE: u8 = 1;
const FSE_MODE: u8 = 2;

/// Repeat offsets at the start of every frame.
const INITIAL_OFFSETS: [usize; 3] = [1, 4, 8];

/// Base literal lengths and extra bits for literal length codes 0..=35.
const LITERAL_LENGTH_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const LITERAL_LENGTH_EXTRA: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
/// Base match lengths and extra bits for match length codes 0..=52.
const MATCH_LENGTH_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
const MATCH_LENGTH_EXTRA: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// One of the three FSE-coded sequence fields: its alphabet and the
/// distribution used in `Predefined_Mode`.
struct SequenceCode {
    max_symbol: u8,
    max_log: u32,
    predefined: &'static [i16],
    predefined_log: u32,
}

const LITERAL_LENGTHS: SequenceCode = SequenceCode {
    max_symbol: 35,
    max_log: 9,
    predefined: &[
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1,
        1, 1, -1, -1, -1, -1,
    ],
    predefined_log: 6,
};
const MATCH_LENGTHS: SequenceCode = SequenceCode {
    max_symbol: 52,
    max_log: 9,
    predefined: &[
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
    ],
    predefined_log: 6,
};
const OFFSETS: SequenceCode = SequenceCode {
    max_symbol: 31,
    max_log: 8,
    predefined: &[
        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
    ],
    predefined_log: 5,
};

/// Whether `head` starts a Zstandard frame. A stream that opens with a
/// skippable frame is not recognised: LZ4 uses the same skippable magic.
#[must_use]
pub fn is_zstd(head: &[u8]) -> bool {
    head.starts_with(&FRAME_MAGIC.to_le_bytes())
}

/// Decompress every frame in `data`, stopping with an error if the output
/// would exceed `limit` bytes.
///
/// # Errors
/// [`io::ErrorKind::InvalidData`] on corrupt or truncated data, a content
/// size or checksum mismatch, data after the last frame, or output larger
/// than `limit`; [`io::ErrorKind::Unsupported`] for a frame that needs a
/// dictionary.
pub fn decompress(data: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    if data.is_empty() {
        return Err(corrupt("empty"));
    }
    let mut input = Reader::new(data);
    let mut output = Output {
        data: Vec::new(),
        limit,
    };
    while input.remaining() > 0 {
        let first = input.position() == 0;
        let magic = input.u32_le()?;
        if magic == FRAME_MAGIC {
            decode_frame(&mut input, &mut output)?;
        } else if magic & SKIPPABLE_MASK == SKIPPABLE_MAGIC {
            let size = input.u32_le()?;
            input.skip(size as usize)?;
        } else {
            return Err(corrupt(if first {
                "not a zstd stream"
            } else {
                "data after the last frame"
            }));
        }
    }
    Ok(output.data)
}

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("corrupt zstd data: {what}"),
    )
}

/// A little-endian integer `width` bytes wide (at most 8).
fn read_le(input: &mut Reader, width: usize) -> io::Result<u64> {
    Ok(le_u64(input.bytes(width)?))
}

/// Everything left in `input`.
fn rest<'a>(input: &mut Reader<'a>) -> &'a [u8] {
    input.bytes(input.remaining()).unwrap_or_default()
}

/// Decompressed data so far, never longer than `limit`.
struct Output {
    data: Vec<u8>,
    limit: usize,
}

impl Output {
    fn make_room(&self, more: usize) -> io::Result<()> {
        if more > self.limit - self.data.len() {
            return Err(corrupt("decompressed data larger than expected"));
        }
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.make_room(bytes.len())?;
        self.data.extend_from_slice(bytes);
        Ok(())
    }

    fn repeat(&mut self, byte: u8, count: usize) -> io::Result<()> {
        self.make_room(count)?;
        self.data.resize(self.data.len() + count, byte);
        Ok(())
    }

    /// Copy `length` bytes from `offset` back, which may overlap what is
    /// being written, never reaching before `floor` (the frame's start).
    fn copy_match(&mut self, offset: usize, length: usize, floor: usize) -> io::Result<()> {
        if offset > self.data.len() - floor {
            return Err(corrupt("offset points before the start of the frame"));
        }
        self.make_room(length)?;
        // Copy from one fixed start, doubling what is available each time.
        let from = self.data.len() - offset;
        let mut left = length;
        while left > 0 {
            let count = left.min(self.data.len() - from);
            self.data.extend_from_within(from..from + count);
            left -= count;
        }
        Ok(())
    }
}

/// What a frame header declares.
struct FrameHeader {
    content_size: Option<u64>,
    block_maximum: usize,
    checksum: bool,
}

impl FrameHeader {
    fn read(input: &mut Reader) -> io::Result<Self> {
        let descriptor = input.u8()?;
        if descriptor & FLAG_RESERVED != 0 {
            return Err(corrupt("reserved frame header bit set"));
        }
        let single_segment = descriptor & FLAG_SINGLE_SEGMENT != 0;
        let window_size = if single_segment {
            None
        } else {
            let window = input.u8()?;
            let base = 1u64 << (10 + (window >> 3));
            Some(base + base / 8 * u64::from(window & 7))
        };
        let dictionary = read_le(input, DICTIONARY_ID_WIDTH[usize::from(descriptor & 3)])?;
        if dictionary != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "zstd frame needs a dictionary, which is not supported",
            ));
        }
        let content_size = match descriptor >> 6 {
            0 if single_segment => Some(read_le(input, 1)?),
            0 => None,
            1 => Some(read_le(input, 2)? + 256),
            2 => Some(read_le(input, 4)?),
            _ => Some(read_le(input, 8)?),
        };
        // A single-segment frame's window is its whole content.
        let window_size = window_size.or(content_size).unwrap_or_default();
        Ok(Self {
            content_size,
            block_maximum: window_size.min(MAX_BLOCK_SIZE) as usize,
            checksum: descriptor & FLAG_CHECKSUM != 0,
        })
    }
}

fn decode_frame(input: &mut Reader, output: &mut Output) -> io::Result<()> {
    let header = FrameHeader::read(input)?;
    let room = (output.limit - output.data.len()) as u64;
    if header.content_size.is_some_and(|size| size > room) {
        return Err(corrupt("decompressed data larger than expected"));
    }
    let mut frame = Frame {
        start: output.data.len(),
        block_maximum: header.block_maximum,
        huffman: None,
        literal_lengths: None,
        offsets: None,
        match_lengths: None,
        recent_offsets: RecentOffsets(INITIAL_OFFSETS),
    };
    loop {
        let block = read_le(input, 3)?;
        let size = (block >> 3) as usize;
        if size > frame.block_maximum {
            return Err(corrupt("block larger than the frame allows"));
        }
        match (block >> 1) & 3 {
            RAW_BLOCK => output.extend(input.bytes(size)?)?,
            RLE_BLOCK => output.repeat(input.u8()?, size)?,
            COMPRESSED_BLOCK => frame.decode_block(input.sub(size)?, output)?,
            _ => return Err(corrupt("reserved block type")),
        }
        if block & 1 == 1 {
            break;
        }
    }
    let content = &output.data[frame.start..];
    if header
        .content_size
        .is_some_and(|size| size != content.len() as u64)
    {
        return Err(corrupt("content size mismatch"));
    }
    if header.checksum && input.u32_le()? != xxh64(content, 0) as u32 {
        return Err(corrupt("XXH64 checksum mismatch"));
    }
    Ok(())
}

/// Decoding state a frame's blocks share: each may reuse the tables and
/// offsets the ones before it left.
struct Frame {
    /// Where the frame's output starts; matches cannot reach before it.
    start: usize,
    block_maximum: usize,
    huffman: Option<Huffman>,
    literal_lengths: Option<Fse>,
    offsets: Option<Fse>,
    match_lengths: Option<Fse>,
    recent_offsets: RecentOffsets,
}

impl Frame {
    fn decode_block(&mut self, mut block: Reader, output: &mut Output) -> io::Result<()> {
        let block_start = output.data.len();
        let literals = self.read_literals(&mut block)?;
        self.execute_sequences(&mut block, &literals, output)?;
        if output.data.len() - block_start > self.block_maximum {
            return Err(corrupt("block decompresses past the frame's block size"));
        }
        Ok(())
    }

    fn read_literals<'a>(&mut self, block: &mut Reader<'a>) -> io::Result<Cow<'a, [u8]>> {
        let first = block.u8()?;
        let kind = first & 3;
        let size_format = (first >> 2) & 3;
        if kind == RAW_LITERALS || kind == RLE_LITERALS {
            let (extra_bytes, shift) = match size_format {
                1 => (1, 4),
                3 => (2, 4),
                _ => (0, 3),
            };
            let header = u64::from(first) | read_le(block, extra_bytes)? << 8;
            let size = self.literals_size(header >> shift)?;
            return Ok(if kind == RAW_LITERALS {
                Cow::Borrowed(block.bytes(size)?)
            } else {
                Cow::Owned(vec![block.u8()?; size])
            });
        }
        let (streams, extra_bytes, field_bits) = match size_format {
            0 => (1, 2, 10),
            1 => (4, 2, 10),
            2 => (4, 3, 14),
            _ => (4, 4, 18),
        };
        let header = u64::from(first) | read_le(block, extra_bytes)? << 8;
        let size = self.literals_size((header >> 4) & ((1 << field_bits) - 1))?;
        let mut section = block.sub((header >> (4 + field_bits)) as usize)?;
        if kind == COMPRESSED_LITERALS {
            self.huffman = Some(Huffman::read(&mut section)?);
        }
        let huffman = self
            .huffman
            .as_ref()
            .ok_or_else(|| corrupt("literals reuse a Huffman table never sent"))?;
        Ok(Cow::Owned(huffman.decode_literals(section, streams, size)?))
    }

    fn literals_size(&self, size: u64) -> io::Result<usize> {
        if size > self.block_maximum as u64 {
            return Err(corrupt("more literals than a block holds"));
        }
        Ok(size as usize)
    }

    fn execute_sequences(
        &mut self,
        block: &mut Reader,
        literals: &[u8],
        output: &mut Output,
    ) -> io::Result<()> {
        let count = read_sequence_count(block)?;
        if count == 0 {
            if block.remaining() > 0 {
                return Err(corrupt("data after an empty sequences section"));
            }
            return output.extend(literals);
        }
        let modes = block.u8()?;
        if modes & 3 != 0 {
            return Err(corrupt("reserved sequence mode bits set"));
        }
        let literal_lengths = select_table(
            &mut self.literal_lengths,
            modes >> 6,
            block,
            &LITERAL_LENGTHS,
        )?;
        let offsets = select_table(&mut self.offsets, (modes >> 4) & 3, block, &OFFSETS)?;
        let match_lengths = select_table(
            &mut self.match_lengths,
            (modes >> 2) & 3,
            block,
            &MATCH_LENGTHS,
        )?;
        let mut bits = BackwardBits::new(rest(block))?;
        let mut literal_length_state = literal_lengths.initial_state(&mut bits);
        let mut offset_state = offsets.initial_state(&mut bits);
        let mut match_length_state = match_lengths.initial_state(&mut bits);
        let mut literals = literals;
        for left in (0..count).rev() {
            let offset_code = offsets.symbol(offset_state);
            let match_code = usize::from(match_lengths.symbol(match_length_state));
            let literal_code = usize::from(literal_lengths.symbol(literal_length_state));
            let offset_value = (1u64 << offset_code) | bits.read(u32::from(offset_code));
            let match_length = MATCH_LENGTH_BASE[match_code] as usize
                + bits.read(u32::from(MATCH_LENGTH_EXTRA[match_code])) as usize;
            let literal_length = LITERAL_LENGTH_BASE[literal_code] as usize
                + bits.read(u32::from(LITERAL_LENGTH_EXTRA[literal_code])) as usize;
            if left > 0 {
                literal_length_state = literal_lengths.next_state(literal_length_state, &mut bits);
                match_length_state = match_lengths.next_state(match_length_state, &mut bits);
                offset_state = offsets.next_state(offset_state, &mut bits);
            }
            let offset = self.recent_offsets.resolve(offset_value, literal_length)?;
            let (now, later) = literals
                .split_at_checked(literal_length)
                .ok_or_else(|| corrupt("sequence uses more literals than the block has"))?;
            output.extend(now)?;
            output.copy_match(offset, match_length, self.start)?;
            literals = later;
        }
        bits.expect_end()?;
        output.extend(literals)
    }
}

fn read_sequence_count(block: &mut Reader) -> io::Result<usize> {
    let first = usize::from(block.u8()?);
    Ok(match first {
        0..=127 => first,
        128..=254 => ((first - 128) << 8) + usize::from(block.u8()?),
        _ => usize::from(block.u16_le()?) + 0x7f00,
    })
}

/// The table `mode` asks for, kept in `previous` for a later block's
/// `Repeat_Mode`.
fn select_table<'t>(
    previous: &'t mut Option<Fse>,
    mode: u8,
    block: &mut Reader,
    code: &SequenceCode,
) -> io::Result<&'t Fse> {
    let table = match mode {
        PREDEFINED_MODE => Fse::new(code.predefined, code.predefined_log),
        RLE_MODE => {
            let symbol = block.u8()?;
            if symbol > code.max_symbol {
                return Err(corrupt("RLE sequence code out of range"));
            }
            Fse::rle(symbol)
        }
        FSE_MODE => Fse::read(block, code.max_symbol, code.max_log)?,
        _ => {
            return previous
                .as_ref()
                .ok_or_else(|| corrupt("sequences reuse a table never sent"))
        }
    };
    Ok(previous.insert(table))
}

/// The three most recent match offsets, which short offset values refer to.
struct RecentOffsets([usize; 3]);

impl RecentOffsets {
    /// The offset `value` stands for, updating the history.
    fn resolve(&mut self, value: u64, literal_length: usize) -> io::Result<usize> {
        let [first, second, third] = self.0;
        if value > 3 {
            let offset = usize::try_from(value - 3).map_err(|_| corrupt("offset too large"))?;
            self.0 = [offset, first, second];
            return Ok(offset);
        }
        // Values 1..=3 pick a recent offset, shifted by one when the
        // sequence has no literals (repeating the last offset is pointless).
        let offset = match value as usize - usize::from(literal_length > 0) {
            0 => return Ok(first),
            1 => {
                self.0 = [second, first, third];
                second
            }
            2 => {
                self.0 = [third, first, second];
                third
            }
            _ => {
                let offset = first - 1;
                if offset == 0 {
                    return Err(corrupt("repeat offset of zero"));
                }
                self.0 = [offset, first, second];
                offset
            }
        };
        Ok(offset)
    }
}

/// An FSE decoding table, one entry per state.
struct Fse {
    accuracy_log: u32,
    states: Vec<FseState>,
}

#[derive(Clone, Copy)]
struct FseState {
    symbol: u8,
    /// Bits to read for the next state, added to `baseline`.
    bits: u8,
    baseline: u16,
}

impl Fse {
    /// Read a table description: an accuracy log, then each symbol's
    /// probability in a variable number of bits (RFC 8878 §4.1.1).
    fn read(input: &mut Reader, max_symbol: u8, max_log: u32) -> io::Result<Self> {
        let mut bits = ForwardBits {
            data: input.peek(input.remaining()).unwrap_or_default(),
            position: 0,
        };
        let accuracy_log = bits.read(4)? + 5;
        if accuracy_log > max_log {
            return Err(corrupt("FSE accuracy log too large"));
        }
        let mut probabilities = Vec::new();
        let mut remaining = (1i32 << accuracy_log) + 1;
        while remaining > 1 {
            if probabilities.len() > usize::from(max_symbol) {
                return Err(corrupt("FSE table has too many symbols"));
            }
            // Values 0..=remaining: the smallest ones take one bit fewer.
            let width = 32 - remaining.leading_zeros();
            let threshold = 1 << (width - 1);
            let short_values = 2 * threshold - 1 - remaining;
            let low = bits.peek(width - 1) as i32;
            let value = if low < short_values {
                bits.consume(width - 1)?;
                low
            } else {
                let value = bits.read(width)? as i32;
                if value >= threshold {
                    value - short_values
                } else {
                    value
                }
            };
            // -1 marks a "less than one" probability, which takes one slot.
            let probability = value - 1;
            remaining -= probability.abs();
            probabilities.push(probability as i16);
            if probability == 0 {
                // Two-bit counts of further zero probabilities; 3 means more follow.
                loop {
                    let repeat = bits.read(2)?;
                    probabilities.extend((0..repeat).map(|_| 0));
                    if repeat < 3 {
                        break;
                    }
                }
            }
        }
        // No value exceeds `remaining`, so it ends at exactly 1: the
        // probabilities fill the table.
        input.skip(bits.position.div_ceil(8))?;
        Ok(Self::new(&probabilities, accuracy_log))
    }

    /// Spread the symbols over the states (RFC 8878 §4.1.1). The
    /// probabilities, -1 counting as 1, add up to the table size, as they
    /// do in every description and predefined distribution.
    fn new(probabilities: &[i16], accuracy_log: u32) -> Self {
        let size = 1usize << accuracy_log;
        let mut symbols = vec![0u8; size];
        // "Less than one" symbols take the last states, one each.
        let mut high = size;
        for (symbol, _) in probabilities.iter().enumerate().filter(|(_, &p)| p == -1) {
            high -= 1;
            symbols[high] = symbol as u8;
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mut position = 0;
        for (symbol, &probability) in probabilities.iter().enumerate() {
            for _ in 0..probability.max(0) {
                symbols[position] = symbol as u8;
                loop {
                    position = (position + step) & (size - 1);
                    if position < high {
                        break;
                    }
                }
            }
        }
        let mut next: Vec<u32> = probabilities
            .iter()
            .map(|p| u32::from(p.unsigned_abs()))
            .collect();
        let states = symbols
            .into_iter()
            .map(|symbol| {
                let count = &mut next[usize::from(symbol)];
                let x = *count;
                *count += 1;
                let bits = accuracy_log - x.ilog2();
                FseState {
                    symbol,
                    bits: bits as u8,
                    baseline: ((x << bits) - size as u32) as u16,
                }
            })
            .collect();
        Self {
            accuracy_log,
            states,
        }
    }

    /// A table that always gives `symbol` and reads no bits.
    fn rle(symbol: u8) -> Self {
        Self {
            accuracy_log: 0,
            states: vec![FseState {
                symbol,
                bits: 0,
                baseline: 0,
            }],
        }
    }

    fn initial_state(&self, bits: &mut BackwardBits) -> usize {
        bits.read(self.accuracy_log) as usize
    }

    fn symbol(&self, state: usize) -> u8 {
        self.states[state].symbol
    }

    fn next_state(&self, state: usize, bits: &mut BackwardBits) -> usize {
        let entry = self.states[state];
        usize::from(entry.baseline) + bits.read(u32::from(entry.bits)) as usize
    }
}

/// A literals Huffman code, decoded with a lookup table indexed by the
/// next `max_bits` bits.
struct Huffman {
    max_bits: u32,
    table: Vec<HuffmanEntry>,
}

#[derive(Clone, Copy, Default)]
struct HuffmanEntry {
    symbol: u8,
    length: u8,
}

impl Huffman {
    /// Read a table description: symbol weights, stored directly as
    /// nibbles or compressed with FSE (RFC 8878 §4.2.1).
    fn read(input: &mut Reader) -> io::Result<Self> {
        let header = input.u8()?;
        let weights = if header < 128 {
            Self::fse_weights(input.sub(usize::from(header))?)?
        } else {
            let count = usize::from(header - 127);
            input
                .bytes(count.div_ceil(2))?
                .iter()
                .flat_map(|&byte| [byte >> 4, byte & 0xf])
                .take(count)
                .collect()
        };
        Self::from_weights(&weights)
    }

    fn fse_weights(mut section: Reader) -> io::Result<Vec<u8>> {
        let table = Fse::read(&mut section, MAX_HUFFMAN_BITS as u8, MAX_WEIGHTS_LOG)?;
        let mut bits = BackwardBits::new(rest(&mut section))?;
        let mut states = [
            table.initial_state(&mut bits),
            table.initial_state(&mut bits),
        ];
        let mut weights = Vec::new();
        // Two states take turns until the bits run out; the other one then
        // gives the last weight.
        for turn in [0, 1].into_iter().cycle() {
            if weights.len() >= MAX_STORED_WEIGHTS {
                return Err(corrupt("too many Huffman weights"));
            }
            weights.push(table.symbol(states[turn]));
            states[turn] = table.next_state(states[turn], &mut bits);
            if bits.overrun() {
                weights.push(table.symbol(states[1 - turn]));
                break;
            }
        }
        if weights.len() > MAX_STORED_WEIGHTS {
            return Err(corrupt("too many Huffman weights"));
        }
        Ok(weights)
    }

    /// Build the code: a symbol of weight `w` gets a code `max_bits + 1 - w`
    /// bits long, codes assigned by increasing weight, then symbol.
    fn from_weights(stored: &[u8]) -> io::Result<Self> {
        let mut total = 0u32;
        for &weight in stored {
            if u32::from(weight) > MAX_HUFFMAN_BITS {
                return Err(corrupt("Huffman weight too large"));
            }
            if weight > 0 {
                total += 1 << (weight - 1);
            }
        }
        if total == 0 {
            return Err(corrupt("Huffman table has no symbols"));
        }
        let max_bits = total.ilog2() + 1;
        // The implied last weight must complete the code exactly.
        let left = (1 << max_bits) - total;
        if max_bits > MAX_HUFFMAN_BITS || !left.is_power_of_two() {
            return Err(corrupt("Huffman weights do not form a complete code"));
        }
        let mut weights = stored.to_vec();
        weights.push(left.ilog2() as u8 + 1);
        let mut table = vec![HuffmanEntry::default(); 1 << max_bits];
        let mut next = 0;
        for weight in 1..=max_bits as u8 {
            for (symbol, _) in weights.iter().enumerate().filter(|(_, &w)| w == weight) {
                let span = 1 << (weight - 1);
                table[next..next + span].fill(HuffmanEntry {
                    symbol: symbol as u8,
                    length: max_bits as u8 + 1 - weight,
                });
                next += span;
            }
        }
        Ok(Self { max_bits, table })
    }

    /// Decode `size` literals from one stream, or from four with a jump
    /// table giving the first three streams' sizes.
    fn decode_literals(
        &self,
        mut section: Reader,
        streams: usize,
        size: usize,
    ) -> io::Result<Vec<u8>> {
        let mut literals = Vec::with_capacity(size);
        if streams == 1 {
            self.decode_stream(rest(&mut section), size, &mut literals)?;
            return Ok(literals);
        }
        let jumps = [section.u16_le()?, section.u16_le()?, section.u16_le()?];
        let segment = size.div_ceil(4);
        let last = size
            .checked_sub(3 * segment)
            .ok_or_else(|| corrupt("too few literals for four streams"))?;
        for jump in jumps {
            self.decode_stream(section.bytes(usize::from(jump))?, segment, &mut literals)?;
        }
        self.decode_stream(rest(&mut section), last, &mut literals)?;
        Ok(literals)
    }

    fn decode_stream(&self, stream: &[u8], count: usize, literals: &mut Vec<u8>) -> io::Result<()> {
        let mut bits = BackwardBits::new(stream)?;
        for _ in 0..count {
            let entry = self.table[bits.peek(self.max_bits) as usize];
            bits.consume(u32::from(entry.length));
            literals.push(entry.symbol);
        }
        bits.expect_end()
    }
}

/// Reads bits least significant first, as FSE table descriptions are stored.
struct ForwardBits<'a> {
    data: &'a [u8],
    position: usize,
}

impl ForwardBits<'_> {
    /// The next `n` (at most 32) bits, zero past the end.
    fn peek(&self, n: u32) -> u32 {
        let first = self.position / 8;
        if first >= self.data.len() {
            return 0;
        }
        let end = (self.position + n as usize)
            .div_ceil(8)
            .min(self.data.len());
        let word = le_u64(&self.data[first..end]) >> (self.position % 8);
        (word & ((1 << n) - 1)) as u32
    }

    fn consume(&mut self, n: u32) -> io::Result<()> {
        let position = self.position + n as usize;
        if position > self.data.len() * 8 {
            return Err(corrupt("FSE table description cut short"));
        }
        self.position = position;
        Ok(())
    }

    fn read(&mut self, n: u32) -> io::Result<u32> {
        let value = self.peek(n);
        self.consume(n)?;
        Ok(value)
    }
}

/// Reads a bitstream backwards from its end, as FSE and Huffman streams are
/// stored: the last byte's highest set bit marks where the bits start.
/// Reads past the beginning give zeros and drive `remaining` below zero.
struct BackwardBits<'a> {
    data: &'a [u8],
    /// Bits not read yet, the low end of `data` first.
    remaining: i64,
}

impl<'a> BackwardBits<'a> {
    fn new(data: &'a [u8]) -> io::Result<Self> {
        let last = data.last().copied().unwrap_or_default();
        if last == 0 {
            return Err(corrupt("bitstream end mark missing"));
        }
        Ok(Self {
            data,
            remaining: (data.len() as i64 - 1) * 8 + i64::from(last.ilog2()),
        })
    }

    /// The next `n` (at most 32) bits, zero-padded past the beginning.
    fn peek(&self, n: u32) -> u64 {
        if self.remaining <= 0 {
            return 0;
        }
        let end = self.remaining as usize;
        let start = end.saturating_sub(n as usize);
        let available = (end - start) as u32;
        let word = le_u64(&self.data[start / 8..end.div_ceil(8)]) >> (start % 8);
        (word & ((1 << available) - 1)) << (n - available)
    }

    fn consume(&mut self, n: u32) {
        self.remaining -= i64::from(n);
    }

    fn read(&mut self, n: u32) -> u64 {
        let value = self.peek(n);
        self.consume(n);
        value
    }

    /// Whether more bits were read than the stream holds.
    fn overrun(&self) -> bool {
        self.remaining < 0
    }

    fn expect_end(&self) -> io::Result<()> {
        if self.remaining != 0 {
            return Err(corrupt("bitstream not used exactly"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One compressed block by hand, which `zstd -d` accepts: four RLE
    /// literals `a`, then one sequence with every code in RLE mode
    /// (4 literals, offset value 7 = offset 4, match length 8).
    const RLE_EVERYTHING: [u8; 17] = [
        0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x0c, 0x45, 0x00, 0x00, 0x21, 0x61, 0x01, 0x54, 0x04, 0x02,
        0x05, 0x07,
    ];

    #[test]
    fn rle_literals_and_rle_sequence_codes() {
        assert!(is_zstd(&RLE_EVERYTHING));
        assert_eq!(decompress(&RLE_EVERYTHING, 12).unwrap(), b"a".repeat(12));
        assert!(decompress(&RLE_EVERYTHING, 11).is_err(), "limit");
    }

    #[test]
    fn header_damage_is_an_error() {
        let mut size = RLE_EVERYTHING;
        size[5] = 13;
        assert!(decompress(&size, 100).is_err(), "content size");
        let mut reserved = RLE_EVERYTHING;
        reserved[4] |= FLAG_RESERVED;
        assert!(decompress(&reserved, 100).is_err(), "reserved bit");
        let mut block_type = RLE_EVERYTHING;
        block_type[6] |= 0x06;
        assert!(decompress(&block_type, 100).is_err(), "reserved block type");
        let needs_dictionary = [0x28, 0xb5, 0x2f, 0xfd, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00];
        let error = decompress(&needs_dictionary, 100).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn recent_offsets_follow_the_rfc() {
        let mut recent = RecentOffsets(INITIAL_OFFSETS);
        assert_eq!(recent.resolve(1, 5).unwrap(), 1);
        assert_eq!(recent.resolve(2, 5).unwrap(), 4);
        assert_eq!(recent.0, [4, 1, 8]);
        assert_eq!(recent.resolve(3, 5).unwrap(), 8);
        assert_eq!(recent.0, [8, 4, 1]);
        // No literals: 1 means the second offset, 3 the first minus one.
        assert_eq!(recent.resolve(1, 0).unwrap(), 4);
        assert_eq!(recent.resolve(3, 0).unwrap(), 3);
        assert_eq!(recent.0, [3, 4, 8]);
        assert_eq!(recent.resolve(103, 0).unwrap(), 100);
        assert_eq!(recent.0, [100, 3, 4]);
        let mut one = RecentOffsets([1, 2, 3]);
        assert!(one.resolve(3, 0).is_err(), "offset of zero");
    }

    /// The RFC's example: weights 4, 3, 2, 0, 1 and an implied 1 give
    /// codes 1, 01, 001, (none), 0000, 0001.
    #[test]
    fn huffman_code_from_the_rfc_example() {
        let huffman = Huffman::from_weights(&[4, 3, 2, 0, 1]).unwrap();
        assert_eq!(huffman.max_bits, 4);
        let code = |prefix: usize| {
            let entry = huffman.table[prefix];
            (entry.symbol, entry.length)
        };
        assert_eq!(code(0b1000), (0, 1));
        assert_eq!(code(0b0100), (1, 2));
        assert_eq!(code(0b0010), (2, 3));
        assert_eq!(code(0b0000), (4, 4));
        assert_eq!(code(0b0001), (5, 4));
        assert!(Huffman::from_weights(&[2, 2, 1]).is_err(), "incomplete");
        assert!(Huffman::from_weights(&[0, 0]).is_err(), "empty");
        assert!(Huffman::from_weights(&[12]).is_err(), "too long");
    }

    #[test]
    fn predefined_distributions_fill_their_tables() {
        for code in [LITERAL_LENGTHS, MATCH_LENGTHS, OFFSETS] {
            assert!(code.predefined.len() <= usize::from(code.max_symbol) + 1);
            let total: i32 = code.predefined.iter().map(|&p| i32::from(p).abs()).sum();
            assert_eq!(total, 1 << code.predefined_log);
            let table = Fse::new(code.predefined, code.predefined_log);
            assert_eq!(table.states.len(), 1 << code.predefined_log);
        }
    }

    #[test]
    fn backward_bits_read_from_the_end_marker() {
        // 0b0000_0110: the marker is bit 2, leaving the two bits 10.
        let mut bits = BackwardBits::new(&[0x06]).unwrap();
        assert_eq!(bits.read(1), 1);
        assert_eq!(bits.read(1), 0);
        bits.expect_end().unwrap();
        assert_eq!(bits.read(3), 0, "zeros past the start");
        assert!(bits.overrun());
        assert!(BackwardBits::new(&[0x10, 0x00]).is_err(), "no marker");
    }
}
