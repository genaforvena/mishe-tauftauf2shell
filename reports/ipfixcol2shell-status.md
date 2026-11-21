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
  No pointer, saved return address, heap metadata field, function pointer,
  control-flow diversion or marker execution was observed or attempted. The
  collaborator is instrumentation, not a stock allocator property.
- UNKNOWN: live collector, loopback TCP input, shipping allocator and compile
  flags, real daemon ASan frames, CVSS as local observation, and any
  post-write pointer control. Witness replay #697 was requested; no verdict
  was in hand at admission. All inputs stay on a local pipe; no probe was
  sent off loopback.

Cheapest next rung: build the real collector from pinned v2.8.0 and v2.9.0
sources under `lab/`, bind TCP input to 127.0.0.1 only, send the same
start/message headers over a loopback socket, and capture the daemon ASan
frame plus the heap layout around the ring under the plugin's actual
allocator; repeat on the fixed tag. Preserve the collaborator, `0x41` and
benign negatives. Only an observed pointer or control-flow result would drop
INSTRUMENTED; a measured allocator or placement blocker is a valid negative
to record, not an excuse to re-run the same harness.
