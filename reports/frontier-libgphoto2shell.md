# Frontier brief: libgphoto2 JL2005 device-count stack/heap write (libgphoto2shell)

**STAGED 2026-11-23 W160** — this brief, a direct-call rung-1..4 harness and a
live registered two-pane window (inner socket index 120, name
`libgphoto2shell`) all exist; seed wall `.mishe-tauftauf/walls/libgphoto2shell.md`,
registry entry and staging DM are in place. Operator admission and an
independent witness replay are pending. Byte-exact pins and hashes:
`lab/frontier/libgphoto2shell/PINS.sha256`; harness provenance, stubs,
negatives and commands: `lab/frontier/libgphoto2shell/PROVENANCE.md`. Frontier
owns no further work on this target.

## 1. Verified ground truth

- Source claims: GHSA-7rfg-j54g-6xm2 / CVE-2026-120451 (High 7.0, CWE-787,
  Unreviewed, published 2026-11-02) and upstream issue
  https://github.com/gphoto/libgphoto2/issues/1326 (opened 2026-10-22, closed
  2026-11-09). The issue reports three findings from static source review;
  its thread claims a third-party ASan reproduction of finding 1 at
  `jl2005c.c:152`. Treated as a claim and reproduced locally below.
- Affected: libgphoto2 through 2.5.34, the newest tag observed. The advisory's
  affected/patched version fields are Unknown; the fix is commit-only as of
  this wake, so the numeric fixed version is **UNKNOWN**.
- Fix: commit `6a3393dd996502457ab965432cf0b2035278825e` (2026-10-28,
  "jl2005c: reject an allocation table that does not fit the buffers"), with a
  separate commit `30bf7ace6d47cfe1232ea73bde2aceb95aba4bfb` for issue
  finding 3 (thumbnail decompression). This brief and harness cover the
  init-path findings 1 and 2 only.
- The companion advisory GHSA-4cvw-qwj9-xjc2 / CVE-2026-120452 (finding 3,
  `jl2005bcd_decompress()`) is a separate claim, screened out here, not
  disproved.
- Attack vector as claimed: a malicious or spoofed USB camera on connect;
  no external probe was performed.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; pinned bytes live in
`lab/frontier/libgphoto2shell/pins/` and are included verbatim under `#line`.

`jl2005c_init()` declares `unsigned char info[0x4020]` (`:50`). After the
first 0x200-byte allocation-table block, it reads a 16-bit entry count
straight from device bytes 12/13 into `priv->nb_entries` (`:138`). At
`:144-146` it computes `alloc_table_size = nb_entries * 0x10 + 0x30` and
rounds up to a multiple of 0x200, with no upper bound. The follow-up
`gp_port_read(port, info + 0x200, alloc_table_size - 0x200)` at `:151-153`
writes device-supplied bytes past `info`: with count 1022 the rounded length
is 0x4200, the read is 0x4000 bytes into 0x3E20 bytes of remaining space, a
480-byte stack overflow; with count 0xffff the read is 1 MiB. Then
`memmove(priv->table, info + 0x30, alloc_table_size - 0x30)` at `:154` copies
16848 bytes into the 16384-byte pinned `Info table[0x4000]` (464-byte heap
overflow) and over-reads the source stack buffer by 480 bytes. The copy
length does not depend on how many bytes the device actually sent, so the
heap overflow also fires on a short reply.

Fix `6a3393d` inserts a guard after the round-up: reject when
`alloc_table_size > sizeof(info)` or `alloc_table_size - 0x30 >
sizeof(priv->table)`, returning `GP_ERROR_CORRUPTED_DATA`. Both attacker
length and attacker content are device-controlled on this path.

## 3. Cheapest local experiment

Build two drivers that include the pinned header and vulnerable/fixed source
under `#line`, with stub gphoto port API, emulated device replies and a
malloc'd `CameraPrivateLibrary`. Plain builds append a 16384-byte `0xa5`
canary after the allocation; ASan builds allocate exactly the pinned struct.
Drive counts 100 (baseline), 1022 (attack), a capped short reply (heap) and
65535 (layout probe).

Commands (from `lab/frontier/libgphoto2shell/harness/`): `./run.sh` generates
the drivers and builds 8 binaries; `./check.sh` runs 24 invocations plus gdb
probes and prints a normalized trace hash.

## 4. Observed evidence (this wake, direct-call harness)

- Rung 1: vulnerable baseline returns `rc=0`, `big_n=1536`; attack requests
  `big_n=16384` from the device.
- Rung 2: fixed build rejects attack and heap with `rc=-3` and never issues
  the oversized read; no ASan report in any fixed run.
- Rung 3: gcc and clang ASan both report
  `ERROR: AddressSanitizer: stack-buffer-overflow`, `WRITE of size 16384`,
  at pinned `jl2005c.c.vuln:152`. On the short-reply variant the first ASan
  report is instead a `READ of size 16848` at pinned `:154` (source
  over-read), so the heap destination write is not separately ASan-confirmed;
  that negative is preserved in PROVENANCE.md.
- Rung 4: gdb on plain builds shows eight chosen `0x5a` bytes at
  `info+0x4020` (24 bytes past the stack buffer) and at
  `priv->table+0x4000` (exactly past the heap array). In clang's plain build
  the saved return-address slot is at `info+16472`; a chosen device marker at
  offset `0x3e58` lands there byte-for-byte (`41 42 43 44 45 46 47 48`).
  The process faults inside `memmove` before `ret`, so IP control is NOT
  demonstrated — chosen bytes at the saved-RIP slot only.
- `92 PASS / 0 FAIL` over 24 runs plus gdb probes, three identical runs;
  trace `e364f756f482157bf25e852f98673131a94c4977d688bf691475024f286c6c98`.
  Raw outputs in `lab/frontier/libgphoto2shell/harness/evidence/`.

## 5. Ceiling and cheapest next rung

Direct calls with stubbed gphoto plumbing and emulated device replies. No
libgphoto2 build, USB/libusb, camera enumeration, gvfs/digiKam consumer,
socket, wire, pointer-control chain, benign marker execution, command
execution or witness replay. The malicious-USB-device attacker model is a
claim. The cheapest move toward a real consumer is to build libgphoto2
2.5.34 with ASan, register the JL2005 camlib USB id and feed the handshake
from a loopback-controlled USB/IP or usbvirt device; the next question is
whether the corrupted frame is used before abort. A rung-5 path would need a
network-facing host that processes untrusted camera data automatically.
Rung 5 is UNKNOWN, not established.
