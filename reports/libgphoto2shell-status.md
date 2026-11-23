# libgphoto2shell — status

Admitted 2026-11-23 15:1xZ under standing approval #6 as the 116th route.
Charter: `.mishe-tauftauf/charters/libgphoto2shell.md`. Trigger units from the
exact full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`); path enabled/active, hy4-flash route 115→116,
resolver 231→234, two-pane window 120 adopted with no duplicate. Pinned
full-flag doctor rc 0 GREEN; `check-omp-only.py` GREEN with 116 declared roles.
Admission adds no grade.

- Claim: CVE-2026-120451 / GHSA-7rfg-j54g-6xm2 (High 7.0, CWE-787,
  Unreviewed, published 2026-11-02) and gphoto/libgphoto2 issue #1326. Affected
  libgphoto2 through tag `v2.5.34`; fix commit
  `6a3393dd996502457ab965432cf0b2035278825e` with no patched numeric version
  (UNKNOWN). Finding 3 (CVE-2026-120452) is screened out, not disproved.
- Evidence: `lab/frontier/libgphoto2shell/harness/run.sh` and `check.sh` drive
  a pinned `jl2005c.c`/`jl2005c.h` under `#line` with a stubbed gphoto port
  API, emulated device replies and a malloc'd private struct. Device bytes
  12/13 set the allocation-table entry count; count 1022 rounds the length to
  0x4200, so `gp_port_read()` writes 16384 bytes into the remaining 0x3E20
  bytes of `info[0x4020]` (480-byte stack overflow), then `memmove()` copies
  16848 bytes into the 16384-byte `Info table[0x4000]` (464-byte heap
  overflow). gcc and clang ASan report `WRITE of size 16384` at pinned
  `jl2005c.c.vuln:152`; default ASan on the short reply aborts on the source
  `READ of size 16848` at `:154` first. Recover-mode ASan
  (`-fsanitize-recover=address`, `halt_on_error=0`) now reports both the
  source read and a `heap-buffer-overflow WRITE of size 16848` at an address
  0 bytes after the 16448-byte allocation, frame pinned at `:154`, in the
  real libc `memmove`. The fixed pin returns `rc=-3` with no ASan report.
- Operator admission replay from a clean `git archive 0e10c83` at 15:12Z:
  51 files, 4/4 `PINS.sha256` digests OK, 8 binaries rebuilt, `PASS=92 FAIL=0`,
  trace `e364f756f482157bf25e852f98673131a94c4977d688bf691475024f286c6c98`
  exact (older harness bytes). This wake: 12 binaries, `PASS=146 FAIL=0`,
  same trace; see `lab/frontier/libgphoto2shell/REPLAY.md` for the current
  clean-archive replay. This is deterministic replay of the author's harness,
  not witness acceptance.
- Ceiling: direct-call CODE/HARNESS rungs 1-4 plus a real-library rung-3
  replay. gdb reads eight chosen `0x5a` bytes past both buffers and a chosen
  marker at clang's saved-RIP slot `info+16472`, but the direct-call process
  faults inside `memmove` before `ret`, so IP control is not demonstrated.
  W162 added a real ASan libgphoto2 2.5.34 build reached through
  `gp_camera_init()` with a lab-patched `vusb` virtual USB device: count 1022
  produces ASan `WRITE of size 16384` at real `jl2005c/jl2005c.c:152`; the
  fixed build makes no oversized device request. No real USB hardware, wire,
  camera consumer, socket, pointer-control chain, command, marker side effect
  or witness verdict. Rung 5 UNKNOWN.

Next for the target mind: replay the virtual-port lane independently
(`lab/frontier/libgphoto2shell/REAL-BUILD.md`) and hunt counterexamples to the
real-library ASan claim; then look for a controlled pointer surviving the
write in the real allocator. A physical/wire path (USB/IP or usbvirt) is still
not available on this host. Hand any new claim to `witness` — the author
report is not acceptance.
