# Provenance — gdbserver `cmd_qtdpsrc()` (CVE-2026-121997)

## Provisioning

Read-only fetches on 2026-11-23, no probe of any external system. All runtime
work is local, direct-call, loopback-free; no gdbserver process was started.

- Claim: `https://api.github.com/advisories/GHSA-jq36-9pw3-8r4v` and
  `https://cveawg.mitre.org/api/cve/CVE-2026-121997` (Red Hat, HIGH 8.1,
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CWE-122).
- Mechanism and claimed exploit chain: Red Hat Bugzilla #2565679 XML,
  `https://bugzilla.redhat.com/show_bug.cgi?ctype=xml&id=2565679`.
- Upstream tracker: Sourceware bug 34968 (XML read).
- Fix: Andrew Burgess, `[PATCH 2/5] gdbserver: prevent buffer overrun for
  QTDPsrc packet`, 2026-11-16,
  `https://sourceware.org/pipermail/gdb-patches/2026-November/231917.html`;
  review follow-up `.../232038.html`. The fix requires
  `slen == strlen(BYTES)/2` and even nibble count, then allocates and decodes
  by the actual packet length.
- Vulnerable pin: `binutils-gdb` HEAD
  `633ae02c4ea8f87c670f7192804349860cfa291d` (from `git ls-remote`, fetched
  2026-11-23). `gdbserver/tracepoint.cc:2546` still reads
  `xmalloc (slen + 1)` — the fix is posted but not merged at this pin.
- Fixed snapshot is the pinned file with the upstream check applied by
  `src/fix-head-633ae02.patch`. The posted patch hunk is against a slightly
  older revision; the saved patch adapts the same change to the pinned HEAD
  bytes. It is not a vendor release.

## Saved pinned bytes (SHA-256)

```
942306a5b1f96693a64d18819973e7e306faa1481f373615487a5fd2b4df4e2e  src/tracepoint-633ae02.cc
c3aa8ac26253ff3fa79d6dd9caa13ae09c5c6471cf3499b22fa5b0926af95f17  src/tracepoint-fixed.cc
5b8bc3cb235eb2ced96da42b15c66ec7f2510deace6f5a943b7e567e8a67d43f  src/fix-head-633ae02.patch
641d72c6c756fbc528adaa837c05d987656a4bea9df630d15a46823050ca6692  src/rsp-low-633ae02.cc
872d8e7dfbcc9e0349026b8daa1e77abec6aef875960eb3a4d051e0fc6d24a79  harness/driver.c
99780c047e65cb687800e27b50525e8dd6202bfefecca13f954fae8b1aca6145  vulnerable cmd_qtdpsrc() slice
ec699708715aad2ac60a6316f2fc5beb128544280c6d6e50847ab451f3294f87  fixed cmd_qtdpsrc() slice
b0bcd1a7a1bb77939a92547b01d78dc88e9a4d4a902af3ac63aebb2244a6e5d0  ishex + unpack_varlen_hex slices
```

`run.sh` asserts all eight hashes on every run. Slices are re-extracted from
the saved pinned files with an `awk` range that includes the exact return-type
line; the function bodies are never retyped or patched.

## Toolchain and result

g++ 13.3.0 and clang++ 18.1.3, `-g -O0 -fno-omit-frame-pointer
-fsanitize=address` for ASan variants; the plain canary variant is built
without ASan. **60 PASS / 0 FAIL** on three consecutive runs and one clean
`/tmp` replay, path-independent normalized content hash
`0c9b837e5300ac744b133e6668179cda410520177d87b859c99cac9af1c1db73`.

## Direct-call harness instrumentation boundary (original limb)

This section records the direct-call harness only; the loopback wire limb
below supersedes its socket/heap statements.

- One direct call to the verbatim pinned `cmd_qtdpsrc(own_buf)` with a
  constructed RSP packet `QTDPsrc:1:0:cond:0:1:<hex>`: declared `SLEN=1`
  (2-byte allocation), actual decoded payload `N` bytes chosen from the
  repeating pattern `0x41 + (i & 0x1f)`. `N` = 8, 32, 64, 128.
- **Decoder boundary:** `hex2bin` is a faithful fixed-count two-nibble-per-byte
  decoder written in the driver, not a verbatim GDB slice. All allocation and
  length decisions come from the verbatim `cmd_qtdpsrc()` slice; the decoder
  never varies between vulnerable, fixed and safe cases.
- `unpack_varlen_hex` and `ishex` are verbatim pinned slices; GDB's RSP numbers
  are hex, so the driver emits `SLEN` in hex (`1` for the attack, `0x10` for
  the 16-byte safe packet).
- ASan: `heap-buffer-overflow`, `WRITE of size 1`, `0 bytes after 2-byte
  region [.., ..+2)`, frames `hex2bin` -> `cmd_qtdpsrc`, on both compilers and
  all four lengths.
- Plain canary: a 64 KiB `0xEE` arena backs `xmalloc`; with `N=32/64` the
  bytes at decoded offsets `2 .. N-1` are exactly the chosen pattern
  (`WRITTEN=N-2 FIRST=2 LAST=N-1 PATTERN_OK=1`, twice per length).
- Fixed snapshot on the same attack: `RC=0 REPLY=E01 LIST_LEN=0`, no ASan
  report. Safe packet with `SLEN` equal to the decoded length: `RC=0
  REPLY=OK LIST_LEN=1` on both pins, no ASan report.
- **Not established:** no real gdbserver packet loop, no natural heap layout,
  no adjacent object identity, no `process_info_private::thread_db` pointer,
  no `qGetTLSAddr`, no marker, no command, no rung 5. The reported RIP-control
  chain from RHBZ#2565679 is a claim, not reproduced here.

## Loopback wire-dispatcher limb (gdbserver2shell W1, 2026-11-23)

New files: `rsp/wire_driver.c`, `rsp/run.sh`, and pinned
`src/linux-low-633ae02.h` (SHA-256
`4fe6cc996097cd4e3d30ecaafcfbb70a7d4f65914c3d02edfb193e3e48de2dcb`,
sourceware `blob_plain` at the same 633ae02 pin). `run.sh` re-extracts and
asserts five verbatim slices each run:

```
99780c047e65cb687800e27b50525e8dd6202bfefecca13f954fae8b1aca6145  cmd_qtdpsrc() (vulnerable)
bd86f8a40b0ac06286d6bbddf6c8fb88385c75d4f23642bcd6738c153f82f02b  handle_tracepoint_general_set()
b0bcd1a7a1bb77939a92547b01d78dc88e9a4d4a902af3ac63aebb2244a6e5d0  ishex + unpack_varlen_hex
5e9aa981020061f85eb9b48eecd991ca46bc0487f424de37ee8ff5f4f0667d46  struct process_info_private
ec699708715aad2ac60a6316f2fc5beb128544280c6d6e50847ab451f3294f87  cmd_qtdpsrc() (fixed)
```

`wire_driver.c` SHA-256
`19a04d63ce458678d9ebe638cf803f30c2e144232d20fe5f2dd11ac671532b30`.
Result: **70 PASS / 0 FAIL** twice locally and once from a clean `/tmp`
copy; path-independent normalized hash
`f25a563e0b06136e1dec12d2dbe70c593dfae5aca9aaa851f3e337d1c29331f2`.

Observed path: a child client sends a checksummed `$QTDPsrc:...#xx` frame
over a 127.0.0.1 socket; the server validates the sum, sends `+`, and
calls the verbatim pinned dispatcher, which dispatches `QTDPsrc` to the
verbatim pinned handler. Under ASan (g++ 13.3.0 and clang++ 18.1.3) N=32/64
with declared `SLEN=1` gives `heap-buffer-overflow`, `WRITE of size 1`,
`0 bytes after 2-byte region`, frames `hex2bin` -> `cmd_qtdpsrc` ->
`handle_tracepoint_general_set` -> `main`. Fixed snapshot replies `E01`
over the wire and the client sees `$E01#...`; a well-formed `SLEN=16`
packet replies `OK` on both pins; neither control reports ASan.

Plain stock-glibc limb: two 0x20 tcache holes with the victim between them
(hole1, victim, hole2) make the handler's `srctype` take hole2 and `src`
take hole1. Measured `DELTA=32` between `src` and the live victim; the
chosen pattern overwrites the victim chunk's size field
(`SIZE_HIT=1`) and all three `source_string` pointers at N=64. N=8 leaves
the adjacent object intact; N=32 hits the size field and the low byte of
`type`; N=48 reaches `next`. With the verbatim `process_info_private`
slice as the victim, N=64 writes the chosen pattern word
`0x504f4e4d4c4b4a49` into the `thread_db` pointer at offset 8
(`THREADDB_HIT=1`) and overwrites `r_debug`; safe and fixed controls leave
the object intact.

Instrumentation boundary: the RSP framing, loopback socket, tcache
grooming, stub branches and the fixed-count `hex2bin` decoder are harness
code; only the listed slices are GDB source. The `process_info_private`
object is a freshly groomed harness object, not a live gdbserver process
instance; no `qGetTLSAddr` packet, no call through the forged pointer, no
full gdbserver build, no marker, no command and no rung-5 claim. The
natural (ungroomed) layout was tried first and aborted with
`malloc(): corrupted top size` because `srctype` took the primed hole — a
recorded negative that motivated the two-hole ordering.

## Real pinned gdbserver build and wire replay (W1b, 2026-11-23T01:31Z)

`rsp/build-gdbserver.sh` clones sourceware `binutils-gdb` at the exact
pin `633ae02c4ea8f87c670f7192804349860cfa291d` (verified by `rev-parse`
and by a clean source tree at the end), configures a gdbserver-only build
with `-fsanitize=address` in CFLAGS/CXXFLAGS/LDFLAGS, builds the vulnerable
binary, applies the saved fix hunk, rebuilds and saves `gdbserver-fixed`,
then reverses the patch and restores the vulnerable binary. Only 127.0.0.1
is used at run time; fetching and building are local provisioning.

`rsp/live_probe.py` speaks RSP from a Python client with correct `+` acks
on both directions; `rsp/live_run.sh` starts the plant-built gdbserver
with `--once --debug=remote 127.0.0.1:PORT /bin/true`;
`rsp/live_verify.sh` runs three cases. Result: **16 PASS / 0 FAIL** twice,
path-independent normalized hash
`b646cc08458fb0344a3a62ceaf0e31b4eb5456572bd470e5b05f4cb17fbeb68e`.

Observed on the vulnerable build: the client creates tracepoint 1 with
`QTDP:1:0:E:0:0` (`OK`), then sends `QTDPsrc:1:0:cond:0:1:` plus 64 chosen
bytes. The server's `--debug=remote` log records the exact incoming
packet, then ASan reports `heap-buffer-overflow`, `WRITE of size 1`,
`0 bytes after a 2-byte region`, frames
`hex2bin (gdbsupport/common-utils.cc:465)` ->
`cmd_qtdpsrc (gdbserver/tracepoint.cc:2547)`, exit 134. The well-formed
`SLEN=16` packet on the same build replies `OK` and exits 0 with no ASan;
the fixed binary rejects the same attack with `E01` and exits 0 with no
ASan. A following `qGetTLSAddr` on the safe case reaches the dispatcher
and returns `E01` (no thread_db loaded).

Recorded negative: the first live client did not ack the server's reply,
so gdbserver kept resending `OK` and never parsed the `QTDPsrc` frame;
there was no ASan report. The client was corrected to ack every received
packet before the successful replay above.

Boundary: this is a real pinned gdbserver process fed attacker-controlled
loopback wire input, but the ASan build aborts at the first overflow. No
chosen-byte readback inside that process, no `qGetTLSAddr` call through a
forged pointer, no non-ASan live layout measurement, no marker, no
command and no rung 5. The advisory's live `process_info_private::thread_db`
overwrite remains a claim; the harness limb above only shows placement
feasibility in a groomed object.

## Non-ASan live outcome (2026-11-23T01:44Z)

A third local build (`lab/build/gdbserver-633ae02-plain`, same pin,
default CFLAGS) was started with the same loopback client. With the
`SLEN=1`, N=64 attack the process replied `OK` to `QTDPsrc`, then `E01`
to a following `qGetTLSAddr`, and died with SIGSEGV (exit 139) during
connection teardown after client EOF. The well-formed `SLEN=16` packet
replied `OK` and exited 0. Evidence:
`rsp/evidence/live-plain-attack-64.{log,client.out}` and
`live-plain-safe-16.{log,client.out}`. This is a delayed process failure
on the natural allocator layout, not a forged-pointer call or command:
no chosen-byte readback was attempted in the live process, and
`qGetTLSAddr` returned `E01` because no thread_db was loaded, not because
an indirect call happened. The ASan build's first-write abort and this
plain build's teardown crash are the two observed live outcomes.
