# Frontier brief — SOES EtherCAT slave: EoE reassembly heap write (CVE-2026-129794) and PDO-mapping BSS write (CVE-2026-129811)
**Status (2026-11-22 00:47Z, operator admission): ADMITTED under standing
approval #6 as target mind `soes2shell` (window 73, 68th route).** The grade
below is unchanged: EoE heap write and PDO mapping BSS write are rung 3 on the
real pinned SOES 3.2.0 handlers, and rung 4 is harness-level only (chosen bytes
in an adjacent heap object, synthetic pbuf `next` overwrite, and a real-BSS
`SMmap2[].obj` pointer overwrite with a real `COE_pdoUnpack()` chosen write).
There is no wire trigger, no live EtherCAT slave, no leaked address, no real
target pointer dereference and no rung 5; wire reach stays UNKNOWN with the
measured negatives recorded below. The new mind owns the lane; frontier keeps
any in-flight PDO harness edits on its own wall and stops claiming this lane
as unadmitted.

Witness W102 (#1231, 2026-11-22) independently re-extracted both pinned
tarballs and rebuilt all 12 committed harness binaries from clean HEAD
`e0a004c`; both SOES limbs are **ESTABLISHED at exactly the harness-level
scope below** (rung 3 on real pinned handlers, rung 4 harness-level), with no
refutation, no NIT and no repo edits. Its byte-variation and mapping-length
sweeps are recorded in the witness section at the end.


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
long list in `walls/frontier.md`). This lane was admitted at 00:47Z as
`soes2shell`; the grade above stays harness-level rung 3/4, not a live target.

## Operator admission note (2026-11-22 00:47Z)

Admitted under standing approval #6 on the evidence above, with the honest
grade restated in the status block: the five required elements are recorded in
`.mishe-tauftauf/charters/soes2shell.md`, announced on the tape, and reflected
in `docs/task.md`, `docs/reproducibility.md` and the README. The three SOES
digests were reported 3/3 OK by frontier at 00:16Z but were not recomputed by
the operator; recomputing `sha256sum -c SHA256SUMS` is the new mind's first
bounded action. No witness replay or wire path existed at admission.

## soes2shell first wake (2026-11-22 00:50–01:30Z): real CoE mailbox path to the PDO write

Independent verification first: `sha256sum -c SHA256SUMS` recomputed **3/3 OK**
on the pinned tarballs and fix diff. `sh harness/build.sh` rebuilt every
frontier harness; all 12 replay cases reproduced the admitted results under a
fresh record in `lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/`.

New bounded step — `harness/coe_mailbox_overflow.c` replaces direct OD-array
installation with crafted CoE mailbox bytes parsed by the **real**
`ESC_coeprocess()` / `SDO_download()` / `SDO_download_complete_access()` on the
hash-pinned source:

- One SDO Download Complete Access request to `0x1c12` writes the mapping
  count and two mapping indexes (`si=2, map1=0x2000, map2=0x2001`) into
  master-writable OD data buffers. Four expedited SDO-download requests write
  `0x2000:00`, `0x2000:01`, `0x2001:00`, `0x2001:01`; each mapping value is
  `(index<<16)|(sub<<8)|255`, i.e. a 255-bit length the master supplies.
- Vulnerable 3.2.0 plain build: `mailbox -> sizeOfPDO=64 nmappings=2`
  (`MAX_RXPDO_SIZE=42`), `SMmap2[0].obj` pointer overwritten by the 64-byte
  process-data read at `rxpdo+56`, verdict
  `mailbox_size_overflow=1 ptr_overwrite=1 chosen_write=1`. ASan on the same
  mailbox input: `global-buffer-overflow WRITE of size 64`, 0 bytes after
  `rxpdo[42]`, 54 bytes before `SMmap2` (`ecat_slv.c:172`).
- Real fixed 3.2.1 (compiled from the pinned 3.2.1 `esc_coe.c`):
  `sizeOfPDO=0 nmappings=-1`, no `ESC_SM2_sml` assignment, no overflow, ASan
  clean. Short-input control (one 255-bit mapping): `sizeOfPDO=32`, no
  pointer overwrite, both releases clean.
- Negative preserved: the stock `linux_lan9252demo` object list makes `0x1c12`
  `ATYPE_RO` with `data=NULL` and maps two 8-bit objects, so that device's own
  OD does not trigger the bug. The harness uses a device OD with writable
  mapping data — an explicit modeled precondition, not a claim about the demo.

Grade unchanged: rung 3 confirmed, rung 4 harness-level but now driven from
crafted CoE mailbox frames through real dispatch functions rather than direct
array writes. `MBX[]` is filled in-process: no wire input, no HAL, no live
slave, no leaked address, no benign command side effect. Wire reach stays
UNKNOWN and rung 5 is not claimed. Build with `sh harness/build.sh`; replay
`./build/coe_mailbox_3.2.0`, `... safe`, `..._asan_3.2.0` and the 3.2.1 twins.

## Witness replay (W102, message #1231, 2026-11-22)

Witness W102 replayed both limbs from clean HEAD `e0a004c` with its own SHA-256
check (3/3 OK), its own extraction of both pinned tarballs into `/tmp/w102-soes`
and its own rebuild of all 12 harness binaries with clang 18.1.3; it never used
this plant's `build/`. Verdict: **ESTABLISHED at exactly the claimed scope** for
both SOES limbs; no refutation, no NIT, no repo edits.

- EoE: its 3.2.0 ASan 7-fragment run gives `heap-buffer-overflow WRITE of size
  96` at `esc_eoe.c:797`, 0 bytes past the 592-byte region; 3.2.1 ASan and the
  6-fragment safe input are clean. Plain 3.2.0 canary: `offset=608`, 64 bytes
  changed, first 8 `47`; pool `match=1` on vulnerable, 0 on safe and fixed.
  Byte variation: forcing last-fragment `data[32]` (maps to canary[0] at +608)
  to `0x5a` gives `first_bytes=5a4747…`, and `0x00` gives `004747…`, with the
  rest unchanged — chosen bytes come from the attacker-shaped fragment.
- PDO/CoE: 3.2.0 ASan gives `global-buffer-overflow WRITE of size 64`, 0 bytes
  after `rxpdo[42]` and 54 before `SMmap2`, from `ecat_slv.c:172`; real pinned
  3.2.1 ASan is clean and plain `sizeOfPDO=0`. Crafted CoE mailbox through real
  `ESC_coeprocess` gives `sizeOfPDO=64`, `ptr_overwrite=1`, `chosen_write=1`;
  the 1-mapping safe input gives size 32 and is clean. A mapping-length sweep
  (255→64, 248→62, 240→60, 232→58, 200→50 with no complete pointer overwrite,
  128→32 clean) and a process-byte variation (`0x4d`→`0x5a` landing in
  target0/last) match the modeled size arithmetic.
- Boundary held by the witness: all `MBX[]`/`ESC_read`/fake `_objd`/target bytes
  are harness-supplied; no socket, HAL, exec, leak, real-target dereference or
  command side effect. Source-bound at 3.2.0 `esc_eoe.c:758/762/797`,
  `ecat_slv.c:172` and `esc_coe.c:1837` (real object dereference). Rung 3 on real
  handlers, rung 4 harness-level; rung 5 not claimed and wire reach UNKNOWN.
  Raw W102 traces: `/tmp/w102-soes/results/*.out` (witness tree, not committed).

## Wire-reach decision (soes2shell, second wake, 2026-11-22 ~01:2xZ)

No in-tree wire path exists in the admitted source. Both pinned trees declare
the same three HAL entry points (`soes/esc.h:737-739`: `ESC_read`, `ESC_write`,
`ESC_init`); all seven shipped HALs use real hardware transports (Linux
`/dev/lan9252` SPI miscdevice, bcm2835 SPI, RT-Kernel SPI/MMIO, XMC4 ECAT MMIO,
TI PRU-ICSS). Mailbox ingress is `ESC_readmbx` (`soes/esc.c:435`, 3.2.0 `:433`),
which only calls the linked HAL; no tree supplies a socket-, file-, pcap- or
TAP-backed `ESC_read` or a software ESC. The only virtual NIC,
`applications/rtl_lwip_eoe`'s dummy lwIP netif (`main.c:281-296`), sits ABOVE
the EoE mailbox and needs RT-Kernel/XMC4/lwIP headers, so it neither feeds
frames from a socket nor builds on this host. Every in-tree slave starter calls
`ecat_slv_init`/`ecat_slv`, binding to that hardware. All seven HAL files in
both pins and the other lab targets were searched; the only crafted-mailbox
injection in the repo is this lane's harness (`MBX[]` filled in-process).

Host probes this wake, all local: an AF_PACKET raw socket for EtherType
`0x88a4` returns `PermissionError [Errno 1] Operation not permitted` with
`CapEff=0`; `/dev/net/tun` opens as uid 1000 but `TUNSETIFF` returns EPERM;
`unshare -U`, `-n` and `-Urn` all fail. AF_INET loopback binding works, but
EtherCAT mailbox frames have no IP transport in these pins. `sudo -n -l` shows
passwordless full sudo, so a root netns could supply an L2 segment; that still
needs an authored ESC emulator to place frame bytes where `ESC_readmbx` reads
them. Under `docs/rce.md` §1 such an emulator is a synthetic consumer, not a
live affected target's real input path, so it cannot by itself earn rung 5. No
emulator was built: wire reach stays UNKNOWN, rung 5 is not claimed, and the
CoE mailbox harness remains rung-4 mechanics even though it drives real
dispatch.

## Adjacent cluster triage — CVE-2026-129796 (soes2shell, third wake, 2026-11-22 ~01:40Z)

Advisory technical detail was read from
<https://docs.rt-labs.com/security/advisories/rrtl-261119-01.html> this wake.
On pinned 3.2.0 `soes/esc_coe.c:795-864`, `SDO_download()` accepts a
master-declared `size` from the mailbox without comparing it to the object's
`actsize`: for `DTYPE_VISIBLE_STRING` it computes
`memset(data + size, 0, actsize - size)` (unsigned underflow when `size >
actsize`, at `:827`), and for flexible types it later calls
`copy2mbx(mbxdata, data, size)` into the object buffer with no `actsize` bound
(at `:864`, after the mailbox-length clamp). The fixed 3.2.1 source rejects
`size > actsize` with `ABORT_TYPEMISMATCH` and aborts downloads to entries
with `data == NULL` (`fix-v3.2.0-v3.2.1.diff:186-213`).

New harness `lab/frontier/soes2shell/harness/coe_download_overflow.c` builds
non-expedited SDO-download mailboxes and drives both paths through the **real**
`ESC_coeprocess()` → `SDO_download()` → `memset`/`copy2mbx()` on both pinned
releases. Its OD has writable 8-byte VISIBLE_STRING and OCTET_STRING entries
with RAM storage; that is a **modeled precondition** — the stock
`linux_lan9252demo` VISIBLE_STRING entries are `ATYPE_RO`, so this does not
claim the shipped demo OD is writable. `MBX[]` is filled in-process: no wire,
no HAL, no live slave, no leak and no command side effect.

Evidence: `lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/cve129796/`
(`INDEX.txt` lists all 20 runs and exit codes).

| Case | Build | Observed |
|---|---|---|
| `memset` | 3.2.0 ASan | `AddressSanitizer: SEGV`, "caused by a WRITE memory access", stack `__asan_memset` ← `SDO_download esc_coe.c:827` ← `ESC_coeprocess :1501`; exit 1 |
| `memset` | 3.2.0 plain | SIGSEGV, exit 139 (wild multi-GB memset) |
| `copy-global` | 3.2.0 ASan | `global-buffer-overflow`, `WRITE of size 64`, `copy2mbx esc_coe.c:248` ← `SDO_download :864` ← `ESC_coeprocess :1501`, 0 bytes after the 8-byte `g_oct_alone` global; exit 1 |
| `copy` | 3.2.0 plain | 8-byte object filled with chosen `0x5a`; final dump `canary[0..15]: 5a …`, `oct_canary_bytes=56` past the object; safe-input control `0` |
| both malicious modes | real pinned 3.2.1, ASan and plain | no write, `str_canary_bytes=0 oct_canary_bytes=0`, exit 0 |

One transient read of `canary[0]` printed `0x90` inside `deliver()` while the
final hex dump shows `5a`; the cause of that read was not investigated and is
not offered as evidence of a different write source. The chosen-byte claim
rests on the final dump and the 56-byte past-object count.

Grade for this adjacent issue: **rung 3 confirmed on real pinned functions**
for both writes, and rung 4 harness-level for the copy path (chosen bytes in
adjacent memory). Witness W102's replay covered only the original 12 cases,
not this harness. Wire reach remains UNKNOWN and rung 5 is not claimed.



## Adjacent cluster triage — CVE-2026-129798 (soes2shell, fourth wake, 2026-11-22 ~01:58Z)

Pinned 3.2.0 `SDO_download()` enters segmented mode when a master declares a
size larger than the bytes actually in the download mailbox
(`esc_coe.c:852-855`). `SDO_downloadsegment()` then computes the segment size
from the mailbox length and copies it at `ESCvar.data` without comparing the
running total to the object's capacity (`copy2mbx(mbxdata, ESCvar.data, size)`,
`esc_coe.c:1057`; non-last segments advance `ESCvar.data += size`). The pinned
3.2.1 adds `ESCvar.fragsleft = size` at the segmented branch
(`esc_coe.c:910`) and rejects `fragsleft + size > max_capacity`
(`esc_coe.c:1132`), where capacity is the object's declared bit length for a
normal transfer. This is the 8.8 "segmented download cumulative write" item
in RRTL-261119-01.

New harness `lab/frontier/soes2shell/harness/coe_segment_overflow.c` (wired
into `harness/build.sh`) sends one non-expedited SDO Download to a writable
16-byte `OCTET_STRING` that declares its full size but carries no payload
(the initial copy is four zero bytes), followed by three seven-byte Download
Segment mailboxes through the **real** `ESC_coeprocess()` →
`SDO_downloadsegment()`. The modeled precondition is a writable object with
RAM storage; the stock demo OD is not claimed writable. `MBX[]` is filled
in-process: no wire, no HAL, no live slave, no leak, no command side effect.

Evidence:
`lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/cve129798/INDEX.txt`
(ten runs, raw output, exit codes, checksums).

| Case | Build | Observed |
|---|---|---|
| `overflow` | 3.2.0 plain | `ESCvar.data` offsets 4 → 11 → 18; segment 2 writes at object offsets 11–17 and segment 3 at 18–24; nine chosen bytes past the 16-byte object: `canary[0..8] = 47 48 43 44 45 46 47 48 49` |
| `overflow-global` | 3.2.0 ASan | `global-buffer-overflow`, `WRITE of size 7` at `esc_coe.c:1057` via `copy2mbx :248` ← `ESC_coeprocess :1507`, 0 bytes after the 16-byte standalone global; exit 1 |
| `overflow` | real pinned 3.2.1, plain and ASan | `fragsleft=4` after init; segments 2 and 3 abort at `esc_coe.c:1132`, `data_off` stays 11, canary all zero, no ASan report, exit 0 |
| `overflow` with `fill0=5a` / `0x00` | 3.2.0 plain | `canary[0..8] = 60 61 5c 5d 5e 5f 60 61 62` / `06 07 02 03 04 05 06 07 08`: chosen segment bytes, not harness initialization |
| `safe` (32-byte object, 4+21=25 bytes total) | 3.2.0 and 3.2.1, plain and ASan | all clean, canary all zero |

Harness artifact found and repaired: with `ESCvar.activembxsize = 0` the SDO
response buffer aliased `MBX[0]` and `init_coesdo()` zeroed the first three
bytes of each segment payload; setting `activembxsize = MBXSIZE` gives the
full seven chosen bytes. The truncated early observation is superseded.

Grade for this adjacent issue: **rung 3 confirmed on the real pinned
segmented-download handler**, rung 4 harness-level (chosen bytes at chosen
offsets past a modeled writable object). No witness replay of this harness
yet. Wire reach stays UNKNOWN and rung 5 is not claimed.

## Adjacent cluster triage — CVE-2026-129814 (soes2shell, fifth wake, 2026-11-22 ~02:34Z)

The hash-pinned fix diff changes one loop bound in each of the two SDO
information handlers: pinned 3.2.0 `SDO_getod()` copies an object name with
`while (*s && (n < (ESC_MBXDSIZE - 0x0c)))` and then stores `*d = *s`
(`esc_coe.c:1340`, `:1347`); pinned 3.2.1 uses `n < (ESC_MBXDSIZE - 0x0c - 1)`
(`esc_coe.c:1427`). With the demo's 128-byte mailbox and three slots, a name of
111 bytes fills the last slot's name area starting at mailbox offset 18 so
that the 3.2.0 terminator lands at `MBX+384`, one byte past the whole `MBX[]`
global. This is the one-byte mailbox terminator write in RRTL-261119-01.

New harness `lab/frontier/soes2shell/harness/coe_terminator_overflow.c`
(wired into `harness/build.sh`) sends one crafted SDO Information Get Object
Description mailbox request through the **real** `ESC_coeprocess()` →
`SDO_getod()` path, with `ESC_claimbuffer()` returning the last mailbox slot.
Its modeled precondition is an object dictionary with an over-long name; the
written byte is the next name byte from the application OD, **not** a byte
chosen by the master on the wire. `MBX[]` is filled in-process: no wire, no
HAL, no live slave, no leak, no command side effect.

Evidence:
`lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/cve129814/INDEX.txt`
(eight runs, raw output, exit codes, SHA-256 checksums; `sha256sum -c
SHA256SUMS` was recomputed 3/3 OK).

| Case | Build | Observed |
|---|---|---|
| `long` | 3.2.0 plain | `byte_at_MBX_end=41` (the OD name's `A`), response length 122 |
| `long` | 3.2.0 ASan | `global-buffer-overflow`, `WRITE of size 1` at `esc_coe.c:1347` in `SDO_getod` via `ESC_coeprocess :1524`, 0 bytes after the 384-byte `MBX[]` global; exit 1 |
| `long` | real pinned 3.2.1, plain and ASan | `byte_at_MBX_end=00`, length 121, no ASan report, exit 0 |
| `safe` (10-byte name) | 3.2.0 and 3.2.1, plain and ASan | `byte_at_MBX_end=00`, length 22, no ASan report, exit 0 |

Harness artifact found and repaired: the plain-build observation initially
used `__SANITIZE_ADDRESS__`, which this clang does not define, so ASan builds
reported a harness-local read of the same out-of-bounds byte. Replaced with
`__has_feature(address_sanitizer)`; the final eight cases above are the
replay, and the early reports are preserved in the evidence index, not offered
as evidence.

Grade for this adjacent issue: **rung 3 confirmed on the real pinned SDO
information handler**, rung 4 harness-level (one byte at a chosen offset past
the real `MBX[]` global, but the byte comes from application configuration,
not wire input). No witness replay of this harness yet. Wire reach stays
UNKNOWN and rung 5 is not claimed. The advisory lists 21 CVEs total; five now
have local harness coverage (129794 / 129796 / 129798 / 129811 / 129814),
leaving 16 untested issues with source-bound candidates (ranked shortlist on
this mind's wall).

## Adjacent cluster triage — CVE-2026-129803 (soes2shell, sixth wake, 2026-11-22 ~02:59Z)

Pinned 3.2.0 `ESC_coeprocess()` accepts a CoE frame with length as small as
`COE_MINIMUM_LENGTH` (8), while `COE_HEADERSIZE` is 10. In `SDO_download()` the
3.2.0 clamp at `esc_coe.c:849-850` computes
`mbxheader.length - COE_HEADERSIZE` as a negative `int`, promoted to a huge
`uint32` for the comparison with the master-declared size; it therefore never
clamps. Fixed 3.2.1 rejects `length < COE_HEADERSIZE` at `esc_coe.c:854-858`
before any copy.

New harness `lab/frontier/soes2shell/harness/coe_shortframe_overflow.c`
(wired into `harness/build.sh`) sends one non-expedited SDO Download through
the **real** `ESC_coeprocess()` → `SDO_download()` path, declaring an 8-byte
frame while 64 marker bytes (`0xe7`) are physically present in `MBX[]` past
the declared frame. Writable flexible objects with RAM data are a modeled
precondition; the stock demo strings are `ATYPE_RO`. `MBX[]` is seeded
in-process: no wire, no HAL, no live slave, no leak, no command side effect.

| Case | Build | Observed |
|---|---|---|
| `short-read` (64-byte object, declared 64) | 3.2.0 plain and ASan | object `[0]`/`[8]`/`[63]` all `e7`, its canary clean: 56 bytes past the declared frame read into an in-bounds object; ASan clean by design (both arrays are inside globals) |
| `short-write` (8-byte object, declared 64) | 3.2.0 plain | 56 `e7` bytes past the standalone 8-byte object; `write_canary[0]=write_canary[55]=e7` |
| `short-write` | 3.2.0 ASan | `global-buffer-overflow`, `WRITE of size 64` at `esc_coe.c:248` in `copy2mbx` via `SDO_download :864` via `ESC_coeprocess :1501`, 0 bytes after `g_oct_alone[8]`; exit 1 |
| `short-read`, `short-write` | real pinned 3.2.1, plain and ASan | object and write canary all zero, no ASan report, exit 0 — the new `:854` guard rejects the frame |
| `short-safe` (normal length 22, declared 8) | both releases, plain and ASan | only the 8 declared bytes land; canaries clean, no ASan report |

Evidence:
`lab/frontier/soes2shell/evidence/replay-soes2shell-20261122/cve129803/INDEX.txt`
(12 runs, exit codes, raw output and checksums; `sha256sum -c SHA256SUMS`
recomputed 3/3 OK).

Correction preserved as a negative: a read-only scout ranked 129803 first as
a *new* chosen-byte write and cited the earlier 129796 ASan trace as proof.
Those are the same `:864` copy sink. Isolating 129803 with a size-matched
object shows a past-frame **read** into an in-bounds object (no ASan report),
not a new OOB write. The `short-write` case reaches the shared sink through a
distinct undersized-length trigger, which 3.2.1's new guard blocks.

Grade: **rung 3 confirmed on the real pinned `SDO_download()` handler**;
rung 4 harness-level only (past-frame mailbox bytes in a modeled object, and
the shared chosen-byte write via a distinct trigger). No witness replay yet.
Wire reach stays UNKNOWN and rung 5 is not claimed. Six advisory issues now
have local harness coverage (129794 / 129796 / 129798 / 129803 / 129811 /
129814), leaving 15 untested.

