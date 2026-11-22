# Frontier brief — SOES EtherCAT slave EoE reassembly heap write (rung 3 ASan; rung 4 chosen-byte overwrite in a harness)

**Status (2026-11-22 00:21Z, W96): a fresh, tractable candidate.** The real
`ESC_eoeprocess()` EoE fragment path in SOES 3.2.0 performs a wire-sized heap
write: ASan reports `heap-buffer-overflow WRITE of size 96` at
`esc_eoe.c:797`, zero bytes past the application's 592-byte receive buffer.
In a plain (non-ASan) build the same input writes 64 attacker-chosen bytes
(`0x47`) into a known adjacent heap object at offset 608. The paired fixed
build 3.2.1 and the short-input control are clean. **This is a harness-level
rung 3 and rung 4, not a wire trigger and not remote command execution.**
Rung 5 is not attempted. NOT admitted; no window created this wake.

## Verified ground truth

- Primary vendor advisory: RT-Labs **RRTL-261119-01**, released 2026-11-19,
  <https://docs.rt-labs.com/security/advisories/rrtl-261119-01.html>;
  machine-readable CSAF at
  <https://docs.rt-labs.com/security/csaf/2026/rrtl-261119-01.json>.
  Affected: SOES **< 3.2.1**; fixed: **3.2.1**. All issues require a malicious
  or compromised EtherCAT master **on the same network segment**
  (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 8.8, for the lead issue).
- Lead issue **CVE-2026-129794**, "EoE Fragment Reassembly Heap Out-of-Bounds
  Write" (CWE-787). The advisory states fragment 0 carries a 6-bit
  `FRAME_OFFSET` field, shifted left by five (`rxframesize`, max 2016), and
  3.2.0 writes it back into `rxebuf.len`, discarding the application's size;
  the lwIP sample buffer is ~592 bytes, leaving ~1424 bytes of write headroom.
  The advisory is a claim; the local bytes below reproduce it.
- Same advisory covers a cluster worth ranking later: CVE-2026-129796 (CoE
  SDO flexible-length download write, 8.8), CVE-2026-129798 (segmented
  download cumulative write, 8.8), CVE-2026-129811 (PDO mapping size writes
  past `rxpdo[]`/`txpdo[]`, 8.8), CVE-2026-129814 (one-byte mailbox
  terminator write, 3.1), and several NULL/underflow/read variants.
- Pins (GitHub tags API, read 00:16Z): `v3.2.0` =
  `6261dbb2d06dc9687389a9e11050c2a6e8d83295` (affected),
  `v3.2.1` = `28459b2cb65853fcb67985c83d3e3540a18cdf4a` (fixed).
  Fix commits are small and scoped, e.g. `1db6b7c6fc43` (name terminator),
  `22d89f802e65` (PDO size), `28459b2cb658` (version bump).
- Tarballs and the full `v3.2.0...v3.2.1` diff are hash-pinned in
  `lab/frontier/soes2shell/src/`; `SHA256SUMS`: tarballs
  `24c0cb2f8ac3…` (3.2.0), `301d9f191814…` (3.2.1), diff
  `f54bdd7c1170…` (3/3 OK at 00:16Z).

## Source-bound mechanism (pinned bytes, not rendered line numbers)

In 3.2.0 `soes/esc_eoe.c:758`, fragment 0 sets
`rxframesize = EOE_HDR_FRAME_OFFSET_GET(frameinfo2) << 5`; at `:762`, with a
non-NULL receive buffer, it sets `rxebuf.len = rxframesize`, replacing the
application's 592. The later bound at `:795` is
`(rxframeoffset + eoedatasize) <= rxframesize`, and `:797` performs
`memcpy(rxebuf.payload + rxframeoffset, eoembx->data, eoedatasize)`.
For in-frame fragments `:776` derives the expected offset from the same
wire field, so a master sends contiguous 96-byte fragments with the declared
frame size in fragment 0 and running offsets afterwards. Each mailbox data
payload is capped by the 128-byte mailbox, but the reassembly buffer is not.
The fix diff clamps `rxframesize` to `rxebuf.len` before assignment
(`fix-v3.2.0-v3.2.1.diff:450-462`) and rejects frames that would exceed it.

## Local evidence (loopback-only lab; no external probes)

Harness `lab/frontier/soes2shell/harness/eoe_overflow.c` compiles only
`esc_eoe.c` from each pinned tree and stubs its four externals
(`ESCvar`, `MBX`, `MBXcontrol`, `ESC_claimbuffer`). It sets `MBXrun=1`,
registers EoE callbacks whose `get_buffer` returns a `malloc(592)` buffer,
and feeds seven 96-byte EoE fragment mailboxes through the real
`ESC_eoeprocess()` dispatcher. Fragment 0 declares `63<<5 = 2016` bytes;
fragment `i>0` declares offset `i*3*32`; the last carries
`LAST_FRAGMENT`. Build: `harness/build.sh` (real `clang -g -O0`, ASan and
plain variants). All evidence is in `lab/frontier/soes2shell/evidence/`.

| Case | Build | Input | Observed |
|---|---|---|---|
| `asan-vuln-7.txt` | 3.2.0 ASan | 7 fragments | `heap-buffer-overflow WRITE of size 96` at `esc_eoe.c:797`, via `:1027`; 0 bytes after the 592-byte region allocated in `get_buffer`; ASan exit |
| `asan-fixed-7.txt` | 3.2.1 ASan | 7 fragments | no report, `recv_calls=0`; clamp rejects the oversized frame |
| `asan-vuln-6-safe.txt` | 3.2.0 ASan | 6 fragments | clean, `recv_calls=1 last_len=576` (576+96 <= 592) |
| `plain-vuln-canary-7.txt` | 3.2.0 plain | 7 fragments | adjacent object at `+608`: 64 bytes changed to `4747…`, `recv_len=672` |
| `plain-vuln-canary-6-safe.txt` | 3.2.0 plain | 6 fragments | `canary_changed=0`, `recv_len=576` |
| `plain-fixed-canary-7.txt` | 3.2.1 plain | 7 fragments | no callback, `recv_calls=0` |

The plain-build canary is a second `malloc(128)` immediately after the
receive buffer, prefilled with `0x43`; the first eight bytes after overflow
are `0x47`, the chosen content of the last fragment. This is chosen bytes at
chosen offsets in an adjacent live object — **rung 4 mechanics in the
harness**, with no pointer redirection, no wire input and no command
execution. Rung 3 is ESTABLISHED on the real handler (ASan report). Rung 2 is
not separately claimed; the write itself is the corruption. Rung 1 is
ESTABLISHED at harness level only.

A negative result preserved: the first harness run showed no ASan report and
`recv_calls=0` because it applied `htons()` to mailbox fields that SOES's
`cc.h` treats as host-order on little-endian hosts; fragment numbers decoded
as 15. Removing the byte swap made the deterministic trigger appear.

## Rung-4 feasibility and what is still UNKNOWN

- Conditions measured: application receive buffer 592 bytes; non-ASan build
  for the adjacent-object observation (ASan redzones put chosen bytes in
  poison, not in a live neighbour); contiguous EoE fragments; `MBXrun=1`;
  host-order mailbox fields; no authentication in the stack itself.
- Chosen-byte control is byte-granular per fragment (each fragment supplies
  96 bytes), so an adjacent object containing a pointer could in principle
  receive a chosen partial pointer value. **No such object or pointer
  redirect was observed this wake**; glibc chunk metadata between the two
  user buffers is also overwritten, so a naive `free()` of the receive
  buffer would fail. Heap grooming and a pointer-bearing neighbour are
  UNKNOWN, not claimed.
- Wire reach is UNKNOWN and deliberately not simulated. SOES is an EtherCAT
  *slave* stack whose upstream applications use ESC hardware HALs (LAN9252
  SPI); the advisory's AV:A requires a master on the same Ethernet segment.
  Feeding crafted EtherCAT frames from an AF_PACKET socket on loopback into
  this harness would be a synthetic consumer, not evidence of a live target,
  and no CAP_NET_RAW capability or real HAL was exercised this wake.
- No rung 5 path is claimed: there is no observed command execution, side
  effect or wire-to-shell chain.

## Cheapest next experiments (ranked by tractability)

1. Build the upstream `applications/rtl_lwip_eoe` sample with ASan and drive
   `ESC_eoeprocess()` from a real mailbox buffer; check whether the lwIP
   `pbuf` adjacent to the 592-byte payload has a pointer-bearing field in
   range. This is the cheapest route to decide whether rung 4 extends past
   the synthetic canary.
2. Screen CVE-2026-129811 (PDO mapping size → repeated writes past
   `rxpdo[]`/`txpdo[]` after PREOP→SAFEOP) for a pointer-bearing adjacent
   global; the fix hunk `22d89f802e65` is small, so the source-bound delta is
   cheap to read.
3. Only if a real ESC/HAL path exists on loopback, evaluate an actual
   adjacent-network trigger; otherwise keep wire reach UNKNOWN.

Do not duplicate admitted lanes (ProFTPD, libnxml, MsQuic, Apache and the
long list in `walls/frontier.md`). No admission or two-pane window was
created: the current evidence is harness-level rung 3/4, not a live target.
