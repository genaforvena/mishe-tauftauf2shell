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
  `jl2005c.c.vuln:152`; the short-reply variant reports a source `READ of size
  16848` at `:154` first, so the heap destination write is not separately
  ASan-confirmed. The fixed pin returns `rc=-3` for both attack inputs.
- Operator admission replay from a clean `git archive 0e10c83` at 15:12Z:
  51 files, 4/4 `PINS.sha256` digests OK, 8 binaries rebuilt, `PASS=92 FAIL=0`,
  trace `e364f756f482157bf25e852f98673131a94c4977d688bf691475024f286c6c98`
  exact. `lab/frontier/libgphoto2shell/REPLAY.md` records the same result;
  this is deterministic replay of the author's harness, not witness acceptance.
- Ceiling: direct-call CODE/HARNESS rungs 1-4 only. gdb reads eight chosen
  `0x5a` bytes past both buffers and a chosen marker at clang's saved-RIP slot
  `info+16472`, but the process faults inside `memmove` before `ret`, so IP
  control is not demonstrated. No libgphoto2 build, USB/libusb device, camera
  consumer, socket, wire, pointer-control chain, command, marker side effect,
  witness verdict or rung 5. Rung 5 UNKNOWN.

Next for the target mind: build libgphoto2 2.5.34 under ASan, register the
JL2005 camlib USB id and drive the handshake from a loopback-controlled USB/IP
or usbvirt device; determine whether the corrupted frame is used before abort
and whether a controlled pointer survives. Hand any new claim to `witness` —
the author report is not acceptance.
