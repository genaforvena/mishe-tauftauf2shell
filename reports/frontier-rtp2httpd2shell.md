# Frontier brief — rtp2httpd RTSP interleaved-frame overflow (Rtp2httpd2Shell)

**Status: new frontier find, both artifacts COMPLETE (2026-11-21 ~11:22Z) —
handed to the operator and witness on the chat tape.** Rungs
1/2/3 are ESTABLISHED in an extracted, verbatim-pin harness; rung 4 shows
attacker-chosen bytes at chosen offsets in an instrumented collaborator only.
No rtp2httpd daemon, RTSP wire traffic, stock allocator neighbour, real
`buffer_ref_t` metadata, pointer overwrite or execution was observed — those
stay UNKNOWN. The advisory's own claims of a live ASan abort and neighbouring
pool-buffer overwrite are **claims to reproduce**, not lab results here.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: GHSA-35fv-hf3m-2pqc, publisher `stackia`, published
  2026-06-27T08:33:58Z, updated 2026-06-27T17:59:44Z, no CVE assigned.
  Summary: "Heap buffer overflow in RTSP interleaved-frame handling
  (unauthenticated, remotely triggerable)". Severity critical, CVSS 3.1
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8**, CWE-122 / CWE-131 /
  CWE-787. Affected `<= 3.14.1`, fix commit
  `f0fcfc194631e13266cbcfcc1818dde24932978a` in `v3.14.2`. Advisory prose
  claims a single unauthenticated HTTP request (default config, UDPxy on)
  reaches an attacker-chosen upstream RTSP server, one oversized interleaved
  frame crashes the worker, and contents overwrite an adjacent pool buffer;
  it explicitly labels RCE *potential*, not demonstrated. Stored verbatim in
  `lab/frontier/rtp2httpd2shell/src/advisory353.json`.
- **Fix**: the signed fix commit's patch changes the interleaved-frame guard
  in `src/rtsp.c` from `packet_length > RTSP_RESPONSE_BUFFER_SIZE - 4` to
  `packet_length > BUFFER_POOL_BUFFER_SIZE`, and the log argument likewise.
  Verified as an ancestor of `v3.14.2` (compare ahead 4 / behind 0).
- **Raw sources**: `src/rtsp.c` at tags `v3.14.1` (vulnerable) and `v3.14.2`
  (fixed), plus `rtsp.h`, `buffer_pool.{c,h}`, `zerocopy.c` at `v3.14.1`,
  fetched read-only and SHA-256 pinned in `PROVENANCE.md`. All eight pins are
  re-verified by `gen_driver.py` on every run.
- **This lab**: an extracted C driver whose fault statements are byte-for-byte
  copies of pinned `rtsp.c` lines under `#line`; 10 PASS / 0 FAIL, ASan
  `WRITE of size 4092` at the verbatim `:1825`, chosen bytes at three
  past-end offsets. Details below.

## Source-bound mechanism

Line numbers are from `v3.14.1` unless marked fixed.

1. `rtsp.c:1791-1792` reads `channel` from byte 1 and a 16-bit big-endian
   `packet_length` from bytes 2-3 of `session->response_buffer`. The value is
   wire-controlled, 0..65535. `:1795` only requires the buffer to hold
   `4 + packet_length`; since `response_buffer` is 4096 (`rtsp.h:25`), this
   caps the length at 4092.
2. `:1800` checks `packet_length > RTSP_RESPONSE_BUFFER_SIZE - 4` — the
   **source** buffer size (4092), not the **destination** pool slot.
3. `:1823` calls `buffer_pool_alloc()`; the returned `data` is a slot of
   `BUFFER_POOL_BUFFER_SIZE 1536` (`buffer_pool.h:13`, `zerocopy.c:91`,
   `buffer_pool.c:52,67`).
4. `:1825` copies `memcpy(packet_buf->data, &session->response_buffer[4],
   packet_length)` into that 1536-byte slot. Lengths 1537..4092 therefore
   write up to **2556 chosen bytes** past the slot; `:1826` then records the
   oversized `data_size`.
5. `v3.14.2:1801` changes the guard to `packet_length >
   BUFFER_POOL_BUFFER_SIZE`, so hostile lengths take the existing
   reject/resync path and never reach the identical `memcpy` at `:1826`.

The advisory's reachability chain (default `config.udpxy = 1`, unauthenticated
`GET /rtsp/<host>:<port>/...` selecting the upstream host, upstream-driven TCP
interleaved selection) is **source-claimed**, not reproduced here.

## Consumer-reality check

The real consumer is a `memcpy` into a contiguous, shared zero-copy pool whose
slots are followed by other slots and `buffer_ref_t` metadata; the advisory
claims a neighbouring slot is overwritten with chosen bytes. We have **not**
built the daemon or its allocator, so neighbour identity, slot adjacency,
allocator reuse, `buffer_ref_t` layout and any control-flow effect are
UNKNOWN. The harness uses a stand-in slot in a controlled mmap/heap region;
it proves the write primitive and chosen-byte placement, not what the stock
build overwrites next.

## Local harness evidence (10 PASS / 0 FAIL, replayed)

Harness `lab/frontier/rtp2httpd2shell/{gen_driver.py,run.sh}` plus
`PROVENANCE.md`, `.gitignore` and eight pinned `src/` artifacts.
`gen_driver.py` verifies all eight pins by SHA-256 and aborts on drift; it
copies the vulnerable ranges `:1791-1792`, `:1795-1797`, `:1799-1816`,
`:1822-1826` and the fixed ranges `:1792-1793`, `:1796-1798`, `:1800-1817`,
`:1823-1827` verbatim under `#line`. An independent byte comparison found 28
copied lines per driver, zero mismatches. From committed HEAD,
`bash lab/frontier/rtp2httpd2shell/run.sh <outdir>` prints **10 PASS / 0 FAIL**,
`ALL CHECKS PASS rc 0`, with two five-run groups at
`sha256=11a76ab0bcb678868229982cb64a826f0367f29d8c4b3daf9eb84eb5804ceb13`.

- **Rung 1 (reproducible trigger)**: wire length 4092 passes the v3.14.1 guard
  and reaches the copy unclamped (`plen=4092 dsize=4092`).
- **Rung 2 (state failure)**: chosen seed bytes read back at slot+1600,
  +2400 and +2500 — all past the 1536-byte slot.
- **Rung 3 (ASan-confirmed corruption)**: `heap-buffer-overflow`, `WRITE of
  size 4092`, 0 bytes after a 1536-byte region, framed at the verbatim
  `rtsp_v3.14.1:1825`.
- **Rung 4 (INSTRUMENTED)**: a different seed (`0x5a5b5c5d…`) reads back
  byte-exact at the same three offsets; a guard-page run faults with rc 139 on
  the first past-end store.
- **Negatives preserved**: the fixed build rejects length 4092 and accepts
  1536; the fixed build is ASan-clean on both; the vulnerable build is
  ASan-clean at the benign 1536 boundary. No false positive.

Grade: rungs 1/2/3 ESTABLISHED in the extracted harness; rung 4 ESTABLISHED AS
INSTRUMENTED chosen bytes at chosen offsets. Not claimed: live daemon, real
RTSP handshake, stock allocator neighbour, `buffer_ref_t` overwrite, pointer
control, or execution.

## Cheapest local experiment to move a rung

Build stock `v3.14.1` with `-fsanitize=address` on loopback and replay the
advisory's own PoC (it is pinned verbatim in `src/advisory353.json`): a local
malicious RTSP server on 127.0.0.1, a single HTTP request to a local rtp2httpd
instance, and observe whether the ASan write lands at `rtsp.c:1825` with the
declared length. That would promote rung 3 from extracted to live-daemon. A
follow-up with a non-sanitized build and an adjacent-slot sentinel would test
the advisory's chosen-neighbour claim. Both are loopback-only and belong to
the dedicated target mind after admission, not to this brief.

Anything that lowers the grade: a guard that also bounds the wire length
before `:1795`, an allocator layout with unmapped space right after the slot,
or a fixed-version difference elsewhere in the path.
