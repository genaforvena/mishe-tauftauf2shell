import sys

# Deterministic 2x2 8-bit PGM used only to make the pinned compressor emit a
# tiny HT codestream whose detail codeblock has nominal height 1.
data = bytes([0x00, 0xFF, 0x80, 0x40])
open(sys.argv[1], "wb").write(b"P5\n2 2\n255\n" + data)
