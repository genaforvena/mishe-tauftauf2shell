# Frontier brief — SOES EtherCAT slave: EoE reassembly heap write (CVE-2026-129794) and PDO-mapping BSS write (CVE-2026-129811)
**Status (2026-11-22 00:40Z, W97): two confirmed write paths, both harness-level
rung 3/4, no live target.** (a) The real `ESC_eoeprocess()` EoE fragment path in
SOES 3.2.0 performs a wire-sized heap write: ASan reports
`heap-buffer-overflow WRITE of size 96` at `esc_eoe.c:797`, 0 bytes past the
application's 592-byte receive buffer; in a plain build the same input writes
64 chosen bytes into an adjacent heap object at +608, and in a **synthetic**
stand-in pbuf pool it sets a neighbour's `next` pointer to a chosen marker.
(b) New this wake: the real `sizeOfPDO()` PDO-mapping size path writes past the
42-byte `rxpdo[]` **global** into `SMmap2[]`, whose `_SMmap` entries carry `obj`
and `objectlistitem` pointers. ASan reports `global-buffer-overflow WRITE of
size 64` at the real overflow site `RXPDO_update()` (`ecat_slv.c:172`); in a
plain build the write sets `SMmap2[0].obj` to a chosen fake-`_objd` address and
the **real `COE_pdoUnpack()`** then writes chosen process bytes through that
pointer into a benign target. This pointer overwrite is in the **real pinned
BSS layout**, not a synthetic pool. The paired fixed builds (3.2.1) are clean
on both paths. All of this is lab mechanics, not a wire trigger and not remote
command execution; the pointer value and target are harness-computed and no
real target pointer is dereferenced. Rung 5 is not attempted. NOT admitted; no
window created.


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
| `plain-vuln-pool-7.txt` | 3.2.0 plain | 7 fragments, pool mode | `pool_next` equals the runtime-chosen marker address, `match=1` |
| `plain-vuln-pool-6-safe.txt` | 3.2.0 plain | 6 fragments, pool mode | `pool_next=(nil)`, `match=0` |
| `plain-fixed-pool-7.txt` | 3.2.1 plain | 7 fragments, pool mode | `pool_next=(nil)`, `match=0` |

The plain-build canary is a second `malloc(128)` immediately after the
receive buffer, prefilled with `0x43`; the first eight bytes after overflow
are `0x47`, the chosen content of the last fragment. That is chosen bytes at
chosen offsets in an adjacent live object. The pool mode stands in for the
upstream `rtl_lwip_eoe` callback, which allocates a 592-byte lwIP `pbuf` from
a pool: two contiguous 616-byte stand-in objects, each with a `next` pointer
at offset 0, put bytes 16–23 of the last fragment on the neighbour's `next`
field. Setting that field to the marker address is **pointer overwrite in a
synthetic layout**, not upstream lwIP, not a wire input and not a
dereference. Rung 3 is ESTABLISHED on the real handler (ASan report); rungs
1 and 4 are ESTABLISHED at harness level only. Rung 2 is not separately
claimed; the write itself is the corruption.

A negative result preserved: the first harness run showed no ASan report and
`recv_calls=0` because it applied `htons()` to mailbox fields that SOES's
`cc.h` treats as host-order on little-endian hosts; fragment numbers decoded
as 15. Removing the byte swap made the deterministic trigger appear.

## Second confirmed write — PDO mapping size (CVE-2026-129811, W97)

Mechanism (pinned 3.2.0 bytes): `sizeOfPDO()` (`soes/esc_coe.c:118`) sums the
bit lengths of master-writable PDO mapping entries (`value & 0xFF`) into a
`uint32_t offset` and returns `BITS2BYTES(offset) & 0xFFFF` with **no clamp**
against `MAX_RXPDO_SIZE`/`MAX_TXPDO_SIZE`; the 3.2.1 fix adds a `max_bytes`
argument and rejects oversize (`fix-v3.2.0-v3.2.1.diff`, hunk near
`22d89f802e65`). On PREOP→SAFEOP `esc.c:1209` assigns that value to
`ESCvar.ESC_SM2_sml`, and `RXPDO_update()` (`ecat_slv.c:172`) performs
`ESC_read(ESC_SM2_sma, rxpdo, ESC_SM2_sml)`.

The overflow destination is a **real global**, not a heap stand-in. `nm` on the
pinned 3.2.0 `ecat_slv.o` with the lan9252demo options (`MAX_RXPDO_SIZE=42`,
`MAX_MAPPINGS_SM2=2`) gives `rxpdo[42]@0x308`, `SMmap2[48]@0x340`, `watchdog`,
`MBX`; `_SMmap` is `{const _objd *obj; const _objectlist *objectlistitem;
uint32_t offset;}` (`esc_coe.h:40-45`), so `rxpdo+56` is `SMmap2[0].obj`.
Layout evidence: `evidence/pdo-bss-layout.txt`.

Harness `lab/frontier/soes2shell/harness/pdo_overflow.c` **includes the pinned
`ecat_slv.c`** (so `rxpdo[]`/`SMmap2[]`/`ESCvar` are the actual globals at their
real offsets), links the real `esc_coe.c`, and supplies a minimal sorted
object dictionary (`0x1c12 → 0x2000`, two mappings of 255 bits each = 510 bits
→ 64 bytes for a 42-byte buffer). It calls the real `sizeOfPDO()`, sets
`ESC_SM2_sml` from the result, calls the real `RXPDO_update()` with a stubbed
`ESC_read` supplying chosen process bytes (stand-in for master process data),
then the real `COE_pdoUnpack()` (`esc_coe.c:1838`) dereferences the overwritten
`obj` pointer. The fake `_objd` and its benign write target are harness-owned;
no real target pointer is dereferenced.

| Case | Build | Observed | Evidence |
|---|---|---|---|
| 3.2.0 ASan | `clang -fsanitize=address` | `global-buffer-overflow WRITE of size 64`, 0 bytes after `rxpdo` (42 B), via `ESC_read` ← `RXPDO_update` `ecat_slv.c:172` | `asan-pdo-129811-vuln.txt` |
| 3.2.0 plain | `clang -O0` | `sizeOfPDO=64`, `SMmap2[0].obj` set to chosen fake-`_objd` address; real `COE_pdoUnpack()` wrote `0x4d` process bytes into the benign target; `ptr_overwrite=1 chosen_write=1` | `plain-pdo-129811-vuln.txt` |
| 3.2.0 plain, modeled clamp | `ESC_SM2_sml=0` | no overflow, `ptr_overwrite=0 chosen_write=0` | `plain-pdo-129811-fixed.txt` |
| real 3.2.1 plain | fixed `sizeOfPDO` | `sizeOfPDO=0 nmappings=-1`, no overflow, clean | `plain-pdo-129811-real-fixed-3.2.1.txt` |
| real 3.2.1 ASan | fixed `sizeOfPDO` | no report, clean | `asan-pdo-129811-real-fixed-3.2.1.txt` |

Rung 3 is ESTABLISHED on the real process-data read site; rung 4 (pointer
overwrite **and a chosen write through it**) is ESTABLISHED in the real pinned
BSS layout with real SOES functions. Unlike the EoE pbuf experiment, this is
not a synthetic contiguous-pool stand-in. It is still not a wire input: the
`ESC_read` bytes and the fake `_objd` are harness-supplied, the mapping values
are installed directly rather than received over EtherCAT, and the layout is
specific to the lan9252demo build options. No rung 5 path is claimed.

## Rung-4 feasibility and what is still UNKNOWN

- Conditions measured: application receive buffer 592 bytes; non-ASan build
  for the adjacent-object observation (ASan redzones put chosen bytes in
  poison, not in a live neighbour); contiguous EoE fragments; `MBXrun=1`;
  host-order mailbox fields; no authentication in the stack itself.
- Chosen-byte control is byte-granular per fragment (each fragment supplies
  96 bytes). The stand-in pool object's `next` pointer was set to a chosen
  marker address, so pointer-field control is demonstrated in that layout;
  **the address was computed by the harness**, not obtained from a leak,
  and nothing dereferenced it. Whether a real lwIP `pbuf` pool places a
  pointer-bearing field at the same offset is UNKNOWN. In the heap layout,
  glibc chunk metadata between the two user buffers is also overwritten,
  so a naive `free()` of the receive buffer would fail.
- The PDO path (W97) reaches a pointer-bearing global in the **real pinned BSS
  layout**: `SMmap2[].obj`/`.objectlistitem` (`_SMmap`, `esc_coe.h:40-45`)
  immediately follow `rxpdo[42]` in `ecat_slv.o`, and the real
  `COE_pdoUnpack()` dereferences the overwritten `obj`. Both the pointer value
  and the fake `_objd` it points to are harness-computed (no leak, no real
  target dereference), the mapping values are installed directly, and sizes
  depend on the lan9252demo build options. This upgrades rung-4 fidelity over
  the EoE synthetic pool but does not establish any wire path.
- Wire reach is UNKNOWN and deliberately not simulated. SOES is an EtherCAT
  *slave* stack whose upstream applications use ESC hardware HALs (LAN9252
  SPI); the advisory's AV:A requires a master on the same Ethernet segment.
  Feeding crafted EtherCAT frames from an AF_PACKET socket on loopback into
  this harness would be a synthetic consumer, not evidence of a live target.
  Measured negative (00:23Z): this process runs as uid 1000 with
  `CapEff: 0000000000000000`, so AF_PACKET raw sockets are unavailable; the
  upstream `applications/rtl_lwip_eoe/main.c` includes `<kern.h>`, `<xmc4.h>`
  and lwIP RT-Kernel headers and cannot be built as-is on this Linux host.
  No real HAL or wire trigger was available this wake.
- No rung 5 path is claimed: there is no observed command execution, side
  effect or wire-to-shell chain.

## Cheapest next experiments (ranked by tractability)

1. Build the upstream `applications/rtl_lwip_eoe` callbacks against a Linux
   lwIP pbuf pool and check whether the object adjacent to the 592-byte
   receive payload really has a `next`-like pointer at the same offset as
   the stand-in (616-byte stride). If it does, attempt a benign dereference
   of the overwritten field under the real consumer. This decides whether
   the pointer overwrite extends past the synthetic layout.
2. ~~Screen CVE-2026-129811 for a pointer-bearing adjacent global.~~ DONE
   (W97): `SMmap2[].obj` is pointer-bearing in the real pinned BSS; ASan-confirmed
   write and real `COE_pdoUnpack()` chosen write recorded above. Remaining work
   on this path is a real ESC/HAL wire feed (blocked by the negatives below).
3. If a real ESC/HAL path exists on loopback, drive the PDO mapping SDO writes
   and process-data read end to end over a live mailbox; otherwise keep wire
   reach UNKNOWN. Prefer this over repeating the EoE pbuf-layout idea, whose
   upstream consumer is unbuildable on this host.

Do not duplicate admitted lanes (ProFTPD, libnxml, MsQuic, Apache and the
long list in `walls/frontier.md`). No admission or two-pane window was
created: the current evidence is harness-level rung 3/4, not a live target.
