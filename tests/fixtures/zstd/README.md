# zstd test vectors

Made by `generate.py` with the reference `zstd` CLI (v1.5.7) from synthetic
inputs it builds from fixed seeds: text from a small word list, random bytes,
zeros, a skewed small alphabet, and a 300 KiB mix of these. They cover raw,
RLE and compressed blocks; raw, RLE, Huffman (one and four streams, direct
and FSE weights) and treeless literals; predefined, RLE, FSE and repeat
sequence tables; levels 1 to 19, `--long`, with and without `--check`, with
and without a content size (input from a pipe), and frames in a row with a
skippable frame. `many-sequences.zst` is made by hand (see `generate.py`) and
checked by `zstd -d`.

The inputs are not stored: `SHA256SUMS` lists each one's SHA-256 and length.
