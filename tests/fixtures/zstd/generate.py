#!/usr/bin/env python3
"""Regenerate the zstd test vectors with the reference `zstd` CLI (1.5.x).

Every input is synthetic and made here from fixed seeds, so the originals
need not be stored: SHA256SUMS records each one's digest and length.
Run from this directory: `python3 generate.py`.
"""

import hashlib
import random
import struct
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORDS = (
    "evidence volume record entry offset sector cluster journal registry hive key value "
    "timestamp created modified accessed changed owner group process thread handle session "
    "event channel provider message parser artifact timeline examiner report hash chunk"
).split()


def text(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        line = " ".join(rng.choice(WORDS) for _ in range(rng.randint(4, 14)))
        out += f"{rng.randint(0, 99999):05} {line.capitalize()}.\n".encode()
    return bytes(out[:size])


def mixed() -> bytes:
    """About 300 KiB: text, noise, a run of zeros and a short period."""
    rng = random.Random(7)
    return (
        text(3, 160 * 1024)
        + rng.randbytes(12 * 1024)
        + bytes(40 * 1024)
        + b"abc" * (20 * 1024)
        + text(4, 28 * 1024)
    )


def compress(data: bytes, *args: str, pipe: bool = False) -> bytes:
    """`zstd` on `data`; from a pipe the frame carries no content size."""
    if pipe:
        return subprocess.run(["zstd", "-q", "-c", *args], input=data, check=True,
                              capture_output=True).stdout
    source = HERE / "input.tmp"
    source.write_bytes(data)
    try:
        return subprocess.run(["zstd", "-q", "-c", *args, str(source)], check=True,
                              capture_output=True).stdout
    finally:
        source.unlink()


def decompress(frame: bytes) -> bytes:
    return subprocess.run(["zstd", "-q", "-d", "-c"], input=frame, check=True,
                          capture_output=True).stdout


def skippable(payload: bytes) -> bytes:
    return struct.pack("<II", 0x184D2A53, len(payload)) + payload


def many_sequences() -> bytes:
    """By hand: a raw block `abcd`, then a block of 0x7f00 sequences, the
    most the three-byte count can hold, all codes in RLE mode: no literals,
    offset value 1 (alternating recent offsets 4 and 1), match length 3."""
    count = 0x7F00
    header = struct.pack("<IBI", 0xFD2FB528, 0xA0, 4 + 3 * count)
    raw = bytes([0x20, 0, 0]) + b"abcd"
    block = bytes([0x00, 0xFF, 0x00, 0x00, 0x54, 0, 0, 0, 0x01])
    return header + raw + struct.pack("<I", len(block) << 3 | 0b101)[:3] + block


def main() -> None:
    sample = text(1, 48 * 1024)
    noise = random.Random(2).randbytes(16 * 1024)
    bases = random.Random(5)
    dna = bytes(bases.choice(b"ACGT") for _ in range(20 * 1024))
    zeros = bytes(512 * 1024)
    big = mixed()
    shapes = random.Random(11)
    nibbles = bytes(min(15, int(shapes.expovariate(0.6))) for _ in range(4096))
    letters = bytes(shapes.choice(b"etaoinshrdlucmfwyp") for _ in range(2000))
    note = b"a short note: the examiner noted the note, then noted the examiner's notes.\n"
    vectors = {
        "empty": (b"", compress(b"")),
        "empty-pipe": (b"", compress(b"", pipe=True)),
        "hello": (b"hello, zstd\n", compress(b"hello, zstd\n", "--no-check")),
        "text-1": (sample, compress(sample, "-1")),
        "text-3": (sample, compress(sample, "-3", "--check")),
        "text-3-no-check": (sample, compress(sample, "-3", "--no-check")),
        "text-19": (sample, compress(sample, "-19")),
        "text-pipe": (sample, compress(sample, "-9", pipe=True)),
        "note-3": (note, compress(note, "-3")),
        "note-19": (note, compress(note, "-19")),
        "nibbles": (nibbles, compress(nibbles, "-3")),
        "letters": (letters, compress(letters, "-1")),
        "noise": (noise, compress(noise)),
        "dna": (dna, compress(dna, "-19")),
        "zeros": (zeros, compress(zeros)),
        "mixed-1": (big, compress(big, "-1")),
        "mixed-19": (big, compress(big, "-19")),
        "mixed-long": (big, compress(big, "-3", "--long=24", "--no-check")),
    }
    hand_made = many_sequences()
    vectors["many-sequences"] = (decompress(hand_made), hand_made)
    vectors["frames"] = (
        sample + b"hello, zstd\n" + dna,
        vectors["text-1"][1] + skippable(b"skip me") + vectors["hello"][1]
        + vectors["empty"][1] + vectors["dna"][1],
    )
    lines = []
    for name, (original, compressed) in vectors.items():
        (HERE / f"{name}.zst").write_bytes(compressed)
        digest = hashlib.sha256(original).hexdigest()
        lines.append(f"{digest} {len(original)} {name}.zst\n")
    (HERE / "SHA256SUMS").write_text("".join(lines))


if __name__ == "__main__":
    main()
