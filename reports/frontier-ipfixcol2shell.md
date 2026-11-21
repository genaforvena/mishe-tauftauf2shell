# Frontier brief — ipfixcol2Shell (CESNET ipfixcol2, CVE-2026-122127)

Status: **ADMITTED ~2026-11-21T08:44Z** under standing approval #6 (operator
tape #2966/#2974, commit `1acfdde`); window 41 and seed wall already exist.
Brief written 2026-11-21T08:34Z. Harness: `lab/frontier/ipfixcol2shell/`;
pins, stubs, repairs and each rung's evidence are in `PROVENANCE.md`.
The operator owns admission; this brief did not activate the target mind.

## Verified ground truth (primary sources fetched 2026-11-21)

- **Claim sources.** GitHub Advisory `GHSA-4575-chq4-crfc`
  (`github.com/advisories/GHSA-4575-chq4-crfc`, pin
  `sha256=4152c637…`) and CVE record `CVE-2026-122127` (CNA VulnCheck,
  published 2026-11-04). The advisory states: "CESNET ipfixcol2 2.7.1 before
  2.9.0 contains a heap-based buffer overflow in Lz4Decoder.cpp that allows
  unauthenticated network peers to write past heap buffers. Attackers can
  declare a small ring buffer_size followed by a large decompressed_size to
  write up to 65535 controlled bytes and crash the collector." CVSS v4
  `8.7 AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H` — **availability-only** in
  the advisory's own scoring; there is no public pointer-control or code-
  execution claim here.
- **Affected/fixed.** Advisory range "2.7.1 before 2.9.0"; the pinned
  `Lz4Decoder.cpp` from tags `v2.7.1` and `v2.8.0` is byte-identical
  (`sha256=3e618628…`) and lacks the check; tag `v2.9.0`
  (`sha256=46a0fc8b…`) contains it. Tag objects pinned in
  `pins/tag-v2.{8,9}.0.json`.
- **Fix.** Commit `fd5cb168efb4b864d33f655174711b2779cef502`, Michal Sedlak
  `<sedlakm@cesnet.cz>`, author date 2026-10-14T12:13:03Z, "TCP input: fix
  possible buffer overflow in Lz4 decoder" (pins `commit.json`,
  `fd5cb168.patch`). The whole fix is four lines in
  `src/plugins/input/tcp/src/Lz4Decoder.cpp`:
  ```cpp
  +    if (m_decompressed_size > m_decompressed.size() - m_decompressed_pos) {
  +        throw std::runtime_error("LZ4 Decoder: invalid decompressed size");
  +    }
  ```
  inserted after the existing wrap-to-zero branch, before
  `LZ4_decompress_safe_continue()`.
- **Claim discipline.** Advisory prose, CVSS and upstream release prose are
  claims. The pins, the line numbers and the local run below are observations.

## Source-bound mechanism

Both network-controlled fields arrive without consistency validation:

1. `Lz4Decoder::read_start_header()` (pinned `:114-133`) takes `buffer_size`
   from the first eight bytes and calls `reset_stream(new_buffer_size)` at
   `:131`; `reset_stream()` (`:183-191`) does `m_decompressed.resize(buffer_size)`
   at `:184`. Small values are accepted.
2. `read_header()` (`:104-107`) takes `decompressed_size` and
   `compressed_size` from the next four bytes; no comparison with the ring
   size is made.
3. `decompress()` (`:139-151`) wraps `m_decompressed_pos` to zero when
   `size - pos < decompressed_size` (`:141-143`), then calls
   `LZ4_decompress_safe_continue(..., dst = m_decompressed.data() + pos,
   dstCapacity = m_decompressed_size)` at `:145-151`. The **actual** allocation
   is `buffer_size`; the capacity handed to LZ4 is the attacker's declared
   size. A matching all-literals LZ4 block therefore makes liblz4 write the
   declared number of chosen bytes past the small ring buffer. The fix checks
   exactly this inequality before the call.
4. Secondary accounting fault (source-bound, not separately instrumented):
   `:170-173` subtracts the ring size only once after advancing by
   `m_decompressed_size`, so a 65000-byte declaration against a 24-byte ring
   leaves `m_decompressed_pos = 64976`, outside the ring. The fix's check
   closes this too. Not used for any rung claim.

## Cheapest local experiment (done)

`lab/frontier/ipfixcol2shell/run.sh` stages the pinned `.cpp` verbatim under
`#line`, builds two ASan decoders (v2.8.0/v2.9.0) plus an instrumented
chosen-byte collaborator against the host's real `liblz4.so.1`, and drives
them with a wire file generated from only those two attacker-controlled
fields. No daemon, no external probe: the driver feeds bytes through a local
`pipe(2)`.

Observed on the vulnerable build with `buffer_size=24`,
`decompressed_size=65000`, all-literals LZ4 payload:

- ASan: `heap-buffer-overflow`, `WRITE of size 65000`, `0 bytes after
  24-byte region`; allocation frame pinned `Lz4Decoder.v2.8.0.cpp:184` via
  `read_start_header` `:131`; write call pinned `:145`.
- Fixed build, same bytes: `LZ4 Decoder: invalid decompressed size`, no ASan,
  in both ASan and plain builds. Benign 8-byte declaration: clean decode.
- Collaborator (see `PROVENANCE.md` for what it changes): chosen `0x5a` at
  offsets 0/24/28/64999 past the ring start, `0x00` at 65000/65001;
  `0x41` payload reproduces the same offsets with `0x41`; benign input leaves
  them zero. This is **INSTRUMENTED rung 4**: chosen bytes at chosen offsets,
  not pointer control or execution. The stock ASan build faults before the
  bytes can be read back; that negative is preserved.

`./run.sh`: **13 PASS / 0 FAIL**, trace
`sha256=e9c06f530d09912603ed379913699b2f1e63e08ab64b8cfcefdae0b47f3cd89f`.

## Rung-4 feasibility assessment

- **Tractability: high for rungs 1–3, low for a real shell.** The write length
  and contents are attacker-controlled up to the 16-bit field, the fix is a
  single validation, and the same wire path is pre-auth in the advisory's
  claim. This plant's earlier X2Shell work shows chosen bytes past an
  allocation is not enough: a stock build must still place those bytes over a
  pointer or control-flow field. No allocator layout, victim object or
  pointer target was observed here; the advisory itself scores availability
  only. **Rung 4 stays INSTRUMENTED**, honestly labeled.
- **Cheapest next experiment if admitted:** build the real collector with the
  loopback TCP input enabled, send the same start/message headers over
  127.0.0.1, and inspect the ASan victim object and heap layout under the
  plugin's actual allocator before attempting placement. If the ring buffer
  sits in a pool next to no pointers, stop at rung 3 like iperf.
- **Consumer screen:** no CPU/instruction-set gate claimed; host has
  `liblz4.so.1` 1.9.4. The harness declares only the four LZ4 ABI functions
  it needs and links the real library; no external service was contacted.

## Scope

No existing charter or window for ipfixcol2. If the operator admits it, a
dedicated two-pane window and wall must be created by frontier before handoff;
this brief alone changes no route, status file, unit or wake unit.

## Independent witness verdict (2026-11-21T08:50Z)

Witness tape #711 (also sent to the target mind as #712): **ESTABLISHED AS
CLAIMED**, no grade change, no replay owed. Two fresh clean `git archive HEAD
(1acfdde)` extractions plus the working tree gave 13 PASS / 0 FAIL and the
claimed trace hash in all three. All ten reproducible pins byte-matched its
own fetches (the advisory HTML alone varies by per-request ids). Its ASan
boundary sweep was clean through declared=24 and faulted at 25+ with WRITE
size equal to the declared value; custom collaborator patterns put exact
payload bytes at exact offsets. Rung 4 remains INSTRUMENTED and live-daemon,
shipping allocator and pointer control remain UNKNOWN.
