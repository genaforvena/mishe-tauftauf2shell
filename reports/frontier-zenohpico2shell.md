# Frontier brief — Zenoh pico timestamp ZID length overflow (ZenohPico2Shell)

**Status: new frontier find, brief + harness COMPLETE (2026-11-21 ~11:52Z) —
pending independent witness replay and operator admission.** Rungs 1/2/3 are
ESTABLISHED in an extracted, verbatim-pin harness; rung 4 shows
attacker-chosen wire bytes at chosen offsets past a 16-byte destination in an
instrumented collaborator only. No Zenoh transport, peer, real heap neighbour,
pointer value, control-flow diversion or execution was observed — all stay
UNKNOWN. The advisory's "potential remote code execution" is a claim to
reproduce, not a result obtained here.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-130603 / GHSA-fw6g-3fgh-f6m6, CNA Eclipse Foundation.
  CVE record published `2026-11-17T13:57:33.777Z`, updated `2026-11-17T17:07:18.190Z`; finder
  Weiheng Qiu. Title/claim: zenoh-pico does not validate the Zenoh identifier
  (ZID) length when deserializing timestamps; an attacker-controlled length
  greater than 16 writes out of bounds to a fixed 16-byte identifier buffer and
  makes the subsequent zero-fill receive a negative length converted to a large
  unsigned size. Truncated inputs can also cause OOB reads or assertion
  failures. CVSS 4.0 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
  = **9.3 CRITICAL**; CWE-121/122/125. CISA ADP SSVC records exploitation
  `poc`, automatable `yes`, technical impact `total`. The advisory notes
  heap- or stack-based overflow depending on release and decode path, with
  ordinary-frame decoding moved from heap to stack-local storage in 1.5.0.
  Verbatim CVE JSON pinned in
  `lab/frontier/zenohpico2shell/src/advisory130603.json`; OSV and the GitHub
  advisory page were read-only cross-checks. The GHSA id, fix parent SHA and
  PR number come from those cross-checks, not from the pinned bytes.
- **Affected/fixed**: `0.7.2-rc` up to but excluding **1.10.2**; fixed in
  **1.10.2** by commit `9198576fe69f6af66a2ab4f12f579f72208d7b28` (PR #1345,
  parent `a51e13e90ad68d0fa807ad8dfcd61044cbf926db`). The 2023 commit
  `f51284e46d6b09378fb6e5b37e07e2910683a40a` introduced the fixed-size ZID
  decode; it is not the CVE fix. Fix patch pinned verbatim in
  `src/fix130603.patch`.
- **Raw sources**: `src/protocol/codec/message.c` at tags `1.10.1` (vulnerable)
  and `1.10.2` (fixed), `include/zenoh-pico/protocol/core.h`,
  `include/zenoh-pico/protocol/iobuf.h` and `src/protocol/iobuf.c` at `1.10.1`;
  all seven pins SHA-256-listed in `lab/frontier/zenohpico2shell/PROVENANCE.md`
  and re-verified by `gen_driver.py` on every run (exit 3 on drift). All cited
  line numbers are from the raw downloaded bytes; a rendered-source reader
  reported a six-line offset and is not used here.
- **This lab**: extracted C driver whose fault statements are byte-for-byte
  copies of pinned lines under `#line`; 10 PASS / 0 FAIL, ASan `WRITE of size
  64` at the verbatim `message_v1.10.1:80`, chosen bytes past a 16-byte region,
  guard-page fault, fixed/benign ASan-clean.

## Source-bound mechanism

Line numbers are from tag `1.10.1` unless marked fixed.

1. `core.h:59-62` defines `ZENOH_ID_SIZE 16` and `_z_id_t.id[16]`; the timestamp
   carries that fixed-size ID (`message.c:102-112`).
2. `message.c:79` reads a single attacker-controlled `uint8_t len` from the
   wire with no bound check: `uint8_t len = _z_zbuf_read(zbf);`.
3. `message.c:80` calls `_z_zbuf_read_bytes(zbf, id->id, 0, len)`. In the
   pinned `iobuf.h:76-79`, the assert at `:77` checks only that the SOURCE has
   `length` bytes and the `memcpy` at `:79` writes into `dest` with no
   destination bound; `iobuf.c:162-164` is just the forwarding wrapper. A
   full-payload wire therefore copies `len` bytes into `id->id[16]`.
4. `message.c:81` then executes `memset(id->id + len, 0, 16 - len)`. For
   `len > 16`, `16 - len` is negative and converts to a huge `size_t`: the
   advisory's second limb. It is **source-bound only** here; the harness exits
   by longjmp after the verbatim copy to avoid an unbounded zero-fill.
5. `message.c:107` reaches the decoder through `_z_timestamp_decode`, which
   sets `ts->valid = true` on a zero return; the copied caller is present in
   both drivers and exercised directly in `chain` mode.
6. Fixed `1.10.2:79-86` decodes the length with error propagation, rejects
   `len > sizeof(id->id)` at `:81-84` before any copy, reads with
   `_z_zbuf_read_exact` at `:85`, and memsets `sizeof(id->id) - len` at `:86`.
   The fix patch changes exactly that function plus regression tests.

## Lab evidence

`cd lab/frontier/zenohpico2shell && bash run.sh <outdir>`:

- 10 PASS / 0 FAIL, exit 0. Two independent five-run groups both
  `sha256=080794c304ffa34b467a189c505f02318af437ecc43c3a0658d985f0632b9b3b`.
- Rung 1 (wire ZID length 64):
  `decode len=64 ret=0 jumped=1 rpos=66 copied=64` — the unchecked length
  drives a 64-byte copy into the 16-byte destination.
- Rung 2 (seed `0x41`): `oob16=4141414141414141`, same at +32 and +48, read
  back byte-exact after the copy.
- Rung 3 (ASan, exact 16-byte allocation): `heap-buffer-overflow`, `WRITE of
  size 64`, `0 bytes after 16-byte region`, frame
  `_z_id_decode_as_slice` at `message_v1.10.1:80` — the verbatim pinned call.
- Rung 4 (seed `0x5a`): `5a5a5a5a5a5a5a5a` at the same three offsets.
- Guard page: first past-end store faults SIGSEGV (rc 139).
- Fixed `1.10.2`: hostile length returns `ret=-1` with `rpos=2`, sentinel
  `a5a5a5a5a5a5a5a5` intact and all OOB readbacks zero, both in direct and
  timestamp-chain modes; benign length 16 copies exactly 16 bytes; ASan clean
  on fixed hostile/benign and on the vulnerable driver with benign input — a
  counterexample against oracle false positives.

## Rung-4 feasibility assessment

The primitive is a direct chosen write: an unauthenticated timestamp-bearing
message supplies both the oversized length and the copied bytes, and the
landmark is a 16-byte fixed ID. In the lab the **chosen bytes land at chosen
offsets** past a 16-byte region (rung 4 INSTRUMENTED). Beyond that nothing is
established: the harness allocates the destination alone in an `exact`,
`guard` or 4096-byte collaborator layout, so no real heap chunk metadata,
adjacent object, pointer or function pointer was overwritten; no control flow
was diverted; no marker executed. The wrapped-length `memset` limb — arguably
the more severe limb — was deliberately not executed and remains UNKNOWN in
this lab. Whether a real zenoh-pico build reaches this decoder with an
unauthenticated network message on a default transport is a claim from the
advisory, not an observed local path.

**Cheapest rung-raising experiment**: build zenoh-pico at tag `1.10.1` with
ASan (the upstream `tests/z_msgcodec_test.c` regression harness is a starting
point), drive a real `_z_timestamp_decode` over a wire buffer with ZID length
17 and a full 17-byte payload, and observe the copy fault at the pinned line;
then repeat through the smallest accepted Zenoh transport on 127.0.0.1 with a
local process pair to establish reachability. Instrument the first past-end
byte with a chosen marker and inspect the adjacent allocation under gdb before
claiming pointer control. That work is for a dedicated target mind after
admission, not this extracted-driver lane.

## Scope and boundaries

Loopback-only local process drivers; no external probes. No Zenoh source tree
was built or run, no socket was opened, no stock allocator neighbour, real
message frame, transport, pointer or execution claim. Sources were fetched
read-only as provisioning. Harness stand-ins, the deliberate longjmp and the
copied ranges are enumerated in `PROVENANCE.md`.
