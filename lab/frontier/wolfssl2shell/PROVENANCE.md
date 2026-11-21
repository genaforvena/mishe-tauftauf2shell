# Provenance — wolfSSL CVE-2026-6679 (`wolfssl2shell`)

Local, loopback-only/in-process laboratory. All triggering is in-process via
wolfSSL's real internal APIs; no sockets, listeners, packets, external systems
or off-loopback traffic are used. Only the public provisioning URLs below were
contacted. No wolfSSL library source file was edited: both tarballs are
extracted and built verbatim (autogen/configure/make generate the usual build
files only).

## Pinned inputs

`src/SHA256SUMS` (verified by `sha256sum -c src/SHA256SUMS` from this
directory, and again inside `run.sh`/`build.sh`). Four small symlinks in this
directory point at the pinned files in `src/` so the same checksum file also
verifies when invoked as `cd src && sha256sum -c SHA256SUMS`.

```
6efc62b86f145a5c52bfd62294ca66c20ce85b54e9033f5d7e0ee73eb30306c1  v5.9.0-stable.tar.gz
d5ca7af48cd2d9a91d539e9baedeba55a0605a28d7ac8b01dc3d5254a13ca341  v5.9.1-stable.tar.gz
f5abd154cc37895b694bdd1376bddf0786486aa51cca31680e451d6a7f808665  pr10116.diff
da51ec051a493de769767a4854817166f8134e1e9c0cbf7227e789a5e2a74e11  CVE-2026-6679.json
```

| Local pin | Exact URL |
| --- | --- |
| `src/v5.9.0-stable.tar.gz` | `https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.9.0-stable.tar.gz` |
| `src/v5.9.1-stable.tar.gz` | `https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.9.1-stable.tar.gz` |
| `src/pr10116.diff` | `https://github.com/wolfSSL/wolfssl/pull/10116.diff` |
| `src/CVE-2026-6679.json` | `https://cveawg.mitre.org/api/cve/CVE-2026-6679` |

CVE JSON (pinned, published) gives wolfSSL as CNA, title "DTLS 1.3 ACK
serialization heap buffer overflow via integer truncation", CVSS 4.0 8.8 HIGH,
CWE-190/197/787, affected 5.4.0–5.9.0, fixed in 5.9.1. The vendor advisory row
was consulted as background only; its HTML is not pinned here.

## Verified line numbers in the raw pinned bytes

These were read from the extracted tarballs, not inferred from the PR diff:

**v5.9.0 (`wolfssl-5.9.0-stable/src/dtls13.c`)**

- `:2535` — `#define DTLS13_RN_SIZE 16`.
- `:2537` — `static int Dtls13GetAckListLength(Dtls13RecordNumber*, word16*)`.
- `:2550` — truncating assignment
  `*length = (word16)(DTLS13_RN_SIZE * numberElements);`.
- `:2554` — `Dtls13WriteAckMessage(WOLFSSL*, Dtls13RecordNumber*, word32*)`.
- `:2583`, `:2586` — `sendSz += OPAQUE16_LEN`, `sendSz += msgSz`.
- `:2588` — `CheckAvailableSize(ssl, sendSz)` (undersized allocation).
- `:2604`, `:2606` — `c64toa(&recordNumberList->epoch, ackMessage)` and the
  sequence write; ASan attributes the observed WRITE to `:2604`.
- `:723` — `Dtls13RtxAddAck`; its in-library caller is
  `Dtls13RecordRecvd()` at `:1547` (not driven here; see limits).
- Inlined sink frame: `wolfcrypt/src/misc.c:1010` (`c64toa`'s `XMEMCPY`).

**v5.9.1 (`wolfssl-5.9.1-stable`)**

- `src/dtls13.c:724` — `#define DTLS13_MAX_ACK_RECORDS 512` (from PR 10116).
- `src/dtls13.c:768` — `if (count >= DTLS13_MAX_ACK_RECORDS)` early return in
  `Dtls13RtxAddAck` (`:727`).
- `wolfssl/internal.h:5853` — `#define DTLS13_ACK_MAX_RECORDS 128`; the default
  effective list cap observed in this stock build is **128**, not 512 (512 is
  the PR's secondary guard).
- `src/dtls13.c:2603` — fixed `Dtls13WriteAckMessage` with `recordsCount`;
  `:2618` rejects `recordsCount > DTLS13_ACK_MAX_RECORDS`; `:2620` computes
  `msgSz`; `:2653` checks `written + DTLS13_RN_SIZE > msgSz` before every write.

## Build commands (harness-authored scripts)

`build.sh <absolute-outdir>` verifies the pins, extracts each tarball verbatim
under `build/`, and runs, in each tree:

```
./autogen.sh                      # only if configure is absent
./configure --enable-dtls --enable-tls13 --enable-dtls13 \
  --disable-shared --enable-static --disable-examples --disable-crypttests \
  CFLAGS='-fsanitize=address -g -O0 -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address'
make -j2
```

It then asserts `#define WOLFSSL_DTLS13` in each generated `wolfssl/options.h`
and compiles `ack_overflow.c` against each real static `libwolfssl.a` with the
same ASan flags. `run.sh <absolute-outdir>` calls this and executes both
binaries with `ASAN_OPTIONS=symbolize=1:detect_leaks=0:abort_on_error=0`.
`chosen_readback.sh` optionally builds a separate verbatim, non-ASan v5.9.0
copy for gdb inspection; it does not touch the ASan trees.

## What was exercised

- A real DTLS 1.3 `WOLFSSL` object (`wolfDTLSv1_3_client_method`) is created;
  `ssl->dtls13EncryptEpoch` is initialized through the real internal struct.
- 4097 distinct `(epoch, seq)` pairs are inserted with the real
  `Dtls13RtxAddAck()` (descending insertion -> sorted, duplicate-free list of
  4097 records). `Dtls13WriteAckMessage()` is then called directly on that
  real list.
- v5.9.0: harness prints `list_count=4097`, `word16_length=16`,
  `exact_length=65552`, `truncation=YES`. ASan reports
  `heap-buffer-overflow`, `WRITE of size 8`, 0 bytes after the 31-byte output
  buffer allocated by `GrowOutputBuffer` (`src/internal.c:11415`) via
  `CheckAvailableSize` (`src/internal.c:11581`), in `c64toa`
  (`wolfcrypt/src/misc.c:1010`) called from `Dtls13WriteAckMessage`
  (`src/dtls13.c:2604`). The harness aborts at the sink, as expected.
- v5.9.1 control, same 4097 inserts: list capped at 128, `word16_length=2048`,
  `exact_length=2048`, `truncation=NO`, `write_ret=0`,
  `returned_length=2050`, `harness_ok=YES`, empty stderr — ASan clean.
- Optional staged-heap probe (`chosen_readback.sh`, non-ASan v5.9.0, gdb break
  after serialization): CHOSEN epoch bytes `C0 FF EE 11 22 33 44 55` and
  per-record sequence bytes `A5 5A 00 00 00 00 00 <index>` were read at
  offsets 31, 47, 63 and 159 from `ssl->buffers.outputBuffer.buffer` while
  `buffer_size=31`, i.e. starting with the first record entirely past the
  undersized allocation. This is staged heap in an extracted harness.

`bash run.sh <absolute-outdir>` result on this host: 13 PASS, 0 FAIL, rc 0.
Trace over the ordered PASS lines (also at `<outdir>/TRACE.sha256`):

```
fb6831dc85fe7afeaaf688ac519a49bccde954a03159211fb256247c1c7ac05d  trace.txt
```

`bash chosen_readback.sh <absolute-outdir>` additionally printed 6 PASS,
0 FAIL, rc 0.

## Not exercised / limits

- No DTLS record was received from a network peer; the in-library caller
  `Dtls13RecordRecvd()` (v5.9.0 `src/dtls13.c:1547`) was not driven. The ACK
  list was populated by calling the real `Dtls13RtxAddAck()` directly, which
  is the same function that caller uses. No handshake, authentication,
  encryption, listener, client/server exchange, or application was built.
- No pointer field, allocator metadata target, return address, control-flow
  diversion, code execution or shell was demonstrated. The no-ASan readback
  freely corrupts adjacent heap while reaching the breakpoint; it is not a
  realistic exploit primitive proof.
- ASan's first-failing-write stops the vulnerable run; the CHOSEN readback is
  a separate non-ASan run and is labeled staged heap, not a live object.

## Honest rung grading

- **Rungs 1/2/3 — ESTABLISHED (in-process)**: real pinned vulnerable library,
  real internal list-building and serialization APIs; the overflow size is
  selectable via N and the word16 truncation is directly observed; ASan
  confirms the heap WRITE at the `c64toa`/`ackMessage` sink. The fixed tagged
  release is clean under the same harness.
- **Rung 4 — INSTRUMENTED ONLY**: attacker-chosen bytes were observed by gdb at
  chosen offsets past the undersized allocation in a staged, non-ASan,
  in-process heap. No live peer/listener/application, pointer control, or
  control-flow impact was built or observed; those remain UNKNOWN.
