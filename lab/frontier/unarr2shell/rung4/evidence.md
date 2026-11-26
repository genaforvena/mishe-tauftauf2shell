# unarr2shell rung-4 consumer measurement — 2026-11-26T14:05:20Z
Host: ldd (Ubuntu GLIBC 2.39-0ubuntu8.12) 2.39, x86-64; unarr v1.1.0 verbatim sink.
No unarr source patch; non-ASan build so the real glibc allocator is in play.

## gdb, breakpoint parse-tar.c:254 (after strcat(prefixed,name) at :253)
USABLE=264
CHUNKSIZE=272
NEXTCHUNK_SIZE=129329
OOB_BYTE=00

## live adjacent canary
PROBE dest=0x6543157ac5d0 canary=0x6543157ac6e0 delta=272 canary[0..7]=5a5a5a5a5a5a5a5a
PROBE canary_corrupted=0

Interpretation: malloc(257) yields a 272-byte glibc chunk (usable 264).
prefixed[257] is inside that chunk's usable slack, 272 bytes before the
next live object; the next chunk's size field is at prefixed+264 and is
untouched. No adjacent live object is modified. Structural kill of the
rung-4 adjacent-object path on this host; grade stays rung 3 verbatim /
rung 4 PARTIAL (fixed NUL), no chosen byte, no pointer, no command, no r5.
