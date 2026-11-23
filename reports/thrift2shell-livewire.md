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

## Grade and ceiling

New evidence supports rungs 1-3 on living bytes (ASan write and a plain
glibc abort from a loopback frame) and byte placement into adjacent heap
metadata of a live process. It does **not** support rung 5: no pointer
control, no chosen bytes at a chosen offset in a code pointer or return
address, no ROP, no command, no benign marker side effect, no ASLR/grooming
study and no independent witness verdict. The advisory's `AV:N` vector is
now demonstrated as a loopback wire path in this lab build; it is still not
a claim about any externally reachable configuration. The fixed build and
the safe input are clean controls, not evidence of exploitability.
