# Frontier brief — Srs2Shell (Simple Realtime Server, GHSA-qr8h-p53p-x564)

Status: **frontier find, ADMITTED by operator under standing approval #6**
(commit `2833514`, dedicated mind `srs2shell`). Brief written
2026-11-21T08:53Z; witness verdict #725 ESTABLISHED AS CLAIMED, grade
unchanged (precision nit fixed this wake).

Harness: `lab/frontier/srs2shell/`; `PROVENANCE.md` carries every pin, hash,
verbatim range and repair. The operator owns admission; this brief never
activates a target mind by itself.

## Verified ground truth (primary sources, fetched 2026-11-21)

- GHSA `qr8h-p53p-x564`, **no CVE assigned** at fetch, published
  `2026-10-30T14:14:41Z`, HIGH 8.2, summary "RTC: Crash and heap overflow
  from a malformed RTCP packet". Advisory API pin
  (`sha256=5a0d5189…`) and advisory page both state: affected
  `srs >=4.0,<6.0.194`, `>=7.0,<7.0.214`, `>=8.0,<8.0.73`; patched
  `6.0.194`, `7.0.214`, `8.0.73`. Only WebRTC-enabled servers are affected;
  the page claims no authentication is needed without `on_play` /
  `on_publish` callbacks. That reachability is a **claim**, not reproduced
  here.
- Fix commit `ab03c94b0744ab392320253ad1767b21b6c82a59`
  (`2026-10-29T21:18:45Z`), parent `f7968893cfdefcfa681ed5499c804095daf67469`.
  Commit JSON (`sha256=a562c2cb…`), patch (`sha256=f2c42ce0…`), parent and
  fixed `srs_kernel_rtc_rtcp.cpp` (`1a108163…` / `6b95dbe7…`) are pinned.
  The patch changes five files; this harness uses only the RTCP decoder hunk.
- Claimed primitive: one attacker-controlled RTCP packet whose 16-bit
  `length` drives a copy into a fixed 1500-byte heap array. The advisory
  gives plaintext packets: BYE `81 cb 00 00 00 00 00 01` (assert), PLI
  `81 ce 00 01 00 00 00 01` (assert), BYE `81 cb 01 90 00 00 00 01` +
  1596 chosen bytes (heap overflow). Its impact section explicitly says no
  working code-execution exploit was shown.

## Source-bound mechanism (pinned bytes)

- `srs_kernel_rtc_rtcp.hpp:19` sets `kRtcpPacketSize = 1500`;
  `:46-62` defines the bitfield header whose `length` is 16 bits;
  `:64-97` places `uint8_t payload_[kRtcpPacketSize]` inside
  `SrsRtcpCommon`.
- Parent `srs_kernel_rtc_rtcp.cpp:53-70` (`decode_header`) converts
  `header_.length` with `ntohs`, then only checks `length * 4 <=
  buffer->left()` before reading the sender SSRC. It never rejects
  `length == 0` and never caps the length for the fixed payload array.
- Parent `:84-98` (`SrsRtcpCommon::decode`) and `:802-844`
  (`SrsRtcpTWCC::decode`) compute
  `payload_len_ = (length + 1) * 4 - sizeof(SrsRtcpHeader) - 4` and pass it
  straight to `buffer->read_bytes((char*)payload_, payload_len_)`. Pinned
  `srs_kernel_buffer.cpp:242-249` calls `memcpy(data, p_, size)` after
  `srs_assert(require(size))`; the check is only that the *source* datagram
  has enough bytes. Upstream `srs_kernel_error.hpp:548` maps `srs_assert`
  to libc `assert` (`srs_kernel_error.cpp:510-519`), so a negative size
  aborts the process.
- Consequences: `length = 0` gives `payload_len_ = -4` → `require(-4)` is
  false → assertion abort; `length = 1` in a feedback decoder leaves no
  byte for the media SSRC → assertion abort; `length = 400` gives a 1596-byte
  copy into `payload_[1500]`, i.e. 96 bytes past that array (76 bytes past
  the whole object once its tail fields are crossed).
- Fix adds `length < 1` in `decode_header`, `length < 2` before each media
  SSRC read, and `payload_len_ > kRtcpPacketSize` before both copies. A
  local `diff -u` of the pinned files shows exactly those additions in the
  harnessed functions.

## Local harness and observed rungs

`./run.sh` checks all pin hashes, generates two drivers whose pinned ranges
are copied verbatim under `#line`, builds ASan and plain variants, and writes
a deterministic trace. It uses no socket, daemon, ICE/DTLS/SRTP or network;
the RTCP datagram is a local byte array. Full command:
`cd lab/frontier/srs2shell && ./run.sh`.

Latest run: **15 PASS / 0 FAIL**, trace
`sha256=1a61cbf41314d16d886d26183fbdd2fe57179c4efcf3e9c9a8f589df6c899662`.

- **Rung 1 — reproducible trigger.** Parent, BYE with `length = 0`:
  exit 134 with `srs_assert failed: require(size)` in pinned
  `srs_kernel_buffer.cpp:244`. Fixed build returns an error and survives.
- **Rung 2 — observed state failure.** A 1604-byte datagram declaring
  `length = 400` passes the parent's upper-bound check; the declared payload
  (1596) exceeds the fixed 1500-byte array.
- **Rung 3 — ASan-confirmed corruption.** Parent BYE ASan:
  `heap-buffer-overflow`, `WRITE of size 1596`, `pinned/srs_kernel_buffer.cpp:246`,
  decode frame `SrsRtcpCommon::decode` at `pinned/srs_kernel_rtc_rtcp.cpp:95`,
  `0 bytes after 1536-byte region`. Parent TWCC now constructs a real
  `SrsRtcpTWCC`, so its write frame is `SrsRtcpTWCC::decode` at
  `pinned/srs_kernel_rtc_rtcp.cpp:841` (pinned range `:802-844`); it is the
  same 1596-byte write. Fixed BYE (`SrsRtcpCommon::decode`, `:89-106`) and
  fixed TWCC (`SrsRtcpTWCC::decode`, `:811-856`) both reject before the copy
  with `payload len=1596 exceeds 1500` and `rc=0`, no ASan report; benign
  `length = 2` is clean.
- **Rung 4 — INSTRUMENTED, honestly split.** With the decoder object placed
  in a 64 KiB zeroed collaborator, chosen `0x5a` appears at 96 offsets from
  the payload-array end (20 in the object tail, 76 past the object); `0x41`
  reproduces the same count, and a benign run writes none. A guard-mapped
  object faults on the byte past the object (exit 77). No pointer, return
  address, heap-metadata field, function pointer or control-flow diversion
  was observed or attempted; the collaborator and guard page are
  instrumentation, not upstream allocator properties.

## Feasibility assessment

High tractability: maintainer advisory with three pinned fixed versions and
commit, a one-packet trigger, exact plaintext PoC bytes, an upstream fix that
is a handful of guards, and an unbounded attacker-controlled write length
(up to ~64 KB by the advisory's account). Weaker points: the WebRTC session
requires ICE/DTLS/SRTP in the real server, so pre-auth reachability is a
claim here; the harness proves pinned C++ logic in a synthetic frame, not a
built SRS daemon; rung 4 is chosen bytes in a collaborator only. Overall
status: **rungs 1/2/3 established locally, rung 4 INSTRUMENTED**.

Cheapest experiment to move up a rung: build the pinned parent SRS with
ASan, enable WebRTC on loopback, open a WHEP/WHIP session, send one SRTP-
protected BYE/TWCC packet with `length = 400` and a chosen fill byte, and
capture the daemon ASan frame plus the real heap layout around `payload_`;
repeat on v8.0.73 for the guard. Only an observed pointer/control-flow
result would drop the INSTRUMENTED label. If the real allocator faults
before chosen bytes persist, preserve that negative and cap this path at
rung 3 in practice.

All advisory and reachability claims are reproduced from public sources;
this brief proves the pinned code paths and their local memory effects, not
live-daemon exploitability or RCE.

## Clean replay (2026-11-21T08:53Z; post-nit-fix addendum below)

The pre-nit-fix commit `24db73a` was replayed as previously recorded: two
`git archive 24db73a lab/frontier/srs2shell` extractions into
`/tmp/replay-srs-a` and `/tmp/replay-srs-b`, plus the working tree, each ran
the then-current unmodified `run.sh` with byte-identical traces (14 PASS /
0 FAIL at that hash, superseded by the value above).

Post-nit-fix (this wake, working tree): two consecutive unmodified
`./run.sh` invocations each produced **15 PASS / 0 FAIL** and the same
trace `sha256=1a61cbf41314d16d886d26183fbdd2fe57179c4efcf3e9c9a8f589df6c899662`,
byte-identical. No source-generating code changed between those invocations;
the replay record is prose only.
