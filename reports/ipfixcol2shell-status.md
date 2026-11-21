# ipfixcol2shell — status

Admitted 2026-11-21 ~08:44Z by the operator under standing approval #6 on
frontier's handoff #698 and commits `a5f3aed` / `a832dcd`, brief
[frontier-ipfixcol2shell.md](frontier-ipfixcol2shell.md). Claim sources:
`GHSA-4575-chq4-crfc` and CVE-2026-122127 (CNA VulnCheck, 2026-11-04), both
pinned 2026-11-21. The advisory states ipfixcol2 2.7.1 before 2.9.0 lets an
unauthenticated network peer declare a small ring `buffer_size` and a large
`decompressed_size` and write up to 65535 controlled bytes past a heap buffer;
CVSS v4 8.7 is availability-only (`VC:N/VI:N/VA:H`). Vulnerable tags
`v2.7.1`/`v2.8.0` carry byte-identical `Lz4Decoder.cpp`
(`sha256=3e618628…`); fixed `v2.9.0` carries the check
(`sha256=46a0fc8b…`). Fix `fd5cb168efb4b864d33f655174711b2779cef502` adds a
four-line validation before `LZ4_decompress_safe_continue()`. Pins, hashes,
raw URLs and harness repairs are in
`lab/frontier/ipfixcol2shell/PROVENANCE.md`. External claims remain claims.

Claimed trigger: the start header's eight-byte `buffer_size` sets the ring via
`reset_stream()` (`Lz4Decoder.cpp:114-133`, `:184`); the next header's
`decompressed_size` is unchecked (`:104-107`). `decompress()` wraps the ring
position at `:141-143` but hands the declared size to
`LZ4_decompress_safe_continue()` as `dstCapacity` at `:145-151`, so a matching
all-literals LZ4 block writes that many chosen bytes past the small ring. The
fix checks exactly this inequality. The accounting fault at `:170-173` is
source-bound, not separately instrumented, and unused for a rung claim.

- Harness: `bash lab/frontier/ipfixcol2shell/run.sh` — 13 PASS / 0 FAIL, raw
  trace
  `sha256=e9c06f530d09912603ed379913699b2f1e63e08ab64b8cfcefdae0b47f3cd89f`.
- Operator replay ~08:43Z from two clean `git archive HEAD` (`18cae3d`)
  extractions into separate absolute directories: 13 PASS / 0 FAIL in both,
  raw trace
  `sha256=e9c06f530d09912603ed379913699b2f1e63e08ab64b8cfcefdae0b47f3cd89f`
  — byte-identical between directories, to the working-tree replay and to the
  brief. All 11 pin hashes, the fix commit record, both tag refs, the advisory
  pin and the fix patch were checked against `PROVENANCE.md` and `run.sh`.
- Witness replay verdict #712 (DM 2026-11-21, tape): **ESTABLISHED AS CLAIMED**.
  Two clean `git archive HEAD` extractions plus the working tree: unmodified
  `run.sh` 13 PASS / 0 FAIL and the same trace hash
  `e9c06f530d09912603ed379913699b2f1e63e08ab64b8cfcefdae0b47f3cd89f` in all
  three; rung-3 frames and fixed rejection reproduced; independent pin fetches
  matched; boundary sweep clean through declared=24 and faults at 25+. Rung 4
  stays INSTRUMENTED; live collector and allocator were UNKNOWN at that point.
- Rungs 1/2/3 on verbatim pinned v2.8.0 (vulnerable) and v2.9.0 (fixed)
  `Lz4Decoder.cpp` under `#line`, linked against the host's real
  `liblz4.so.1`: vulnerable build faults on the crafted wire input with
  `buffer_size=24`, `decompressed_size=65000`; fixed build throws
  `LZ4 Decoder: invalid decompressed size` in both ASan and plain builds;
  benign 8-byte declaration decodes clean. ASan reports
  `heap-buffer-overflow`, `WRITE of size 65000`, 0 bytes after the 24-byte
  region, allocation at pinned `Lz4Decoder.v2.8.0.cpp:184` via
  `read_start_header` `:131`, write call at `:145`.
- Rung 4 INSTRUMENTED only, with preserved negatives. In a 1 MiB mmap
  collaborator replacing the allocation, chosen wire byte `0x5a` is read back
  at offsets 0/24/28/64999 past the ring, `0x00` at 65000/65001; an `0x41`
  payload reproduces those offsets with `0x41`, and the benign input leaves
  them zero. The stock ASan build faults before those bytes can be read back.
  In that frontier harness, no pointer, saved return address, heap metadata
  field, function pointer, control-flow diversion or marker execution was
  observed or attempted; the collaborator is instrumentation, not a stock
  allocator property. A later live loopback harness did reach glibc metadata
  (below).

## Live loopback TCP replay (2026-11-21 ~09:00Z)

Harness `lab/ipfixcol2shell-live/`: the plugin's real `Lz4Decoder.cpp`,
`DecodeBuffer.cpp`, `ByteVector.cpp` and `read_until_n.hpp` compiled verbatim
from sha256-verified v2.8.0 / v2.9.0 tarballs, a real 127.0.0.1:0 TCP socket,
the host's real liblz4 and stock glibc; `sh run.sh` = 9 PASS / 0 FAIL, trace
`sha256=b81b947cf21f4ab92c6f268534dfbe8fbd6c3eb7da35ee5e9caab000e5471600`
(byte-identical in three runs). Full detail and preserved negatives in
`lab/ipfixcol2shell-live/RESULTS.md`.

- Rung 3 holds on the loopback path: ASan `WRITE of size 65000`, 0 bytes after
  a 24-byte region, allocation at real `Lz4Decoder.cpp:184`, write at `:145`;
  fixed rejects at both ASan and plain, benign 24-byte IPFIX message decodes
  clean.
- Stock glibc, no sanitizer and no replaced allocator: SIGSEGV in
  `unlink_chunk` reached from `_int_malloc` → `_int_realloc` →
  `ByteVector::reserve` → `decompress`. GDB shows `rax=0x5a5a5a5a5a5a5a58`
  for the `0x5a` payload and `0x4141414141414140` for `0x41` — chosen bytes
  occupy the corrupted chunk's size field. A crafted payload putting valid
  size/prev_size fields and chosen bytes in `p->fd`/`p->bk` faults at
  `unlink_chunk+39` (`cmp 0x18(%rax),%rdi`) with
  `rax=0x4141414141414141`: chosen bytes are consumed as a heap pointer.
- Rung 4 is still INSTRUMENTED: chosen pointer **bytes**, not a chosen valid
  address; no write-what-where, vtable/return-address overwrite, control-flow
  diversion or marker execution. This host's glibc layout and allocation
  order were required. The advisory scores availability only.
- UNKNOWN: full `ipfixcol2` daemon, libfds-backed plugin loading, shipping
  compile flags, real daemon ASan frames, CVSS as local observation, and any
  valid-address retargeting or post-write control. A full daemon build is
  blocked on this host by absent `libfds`, `lz4.h`/`liblz4-dev` and `rst2man`.
  Every probe bound 127.0.0.1; source fetching by `stage.sh` is provisioning.
