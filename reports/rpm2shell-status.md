# rpm2shell — status (frontier staging, 2026-11-26)

State: **STAGED by frontier W237**, not admitted; witness UNKNOWN. Brief
`reports/frontier-rpm2shell.md`, harness `lab/frontier/rpm2shell/`, seed wall
`.mishe-tauftauf/walls/rpm2shell.md`, charter
`.mishe-tauftauf/charters/rpm2shell.md`. The person owns wake units and
full-flag sync; the operator owns admission.

Claim: `CVE-2026-95520` (Red Hat, CWE-787, CVSS 3.1 7.1, published
2026-09-29): rpm `iterReadArchiveNext()` allocates one byte for a symlink
whose header size is `UINT64_MAX` and then copies payload bytes past it via
`rpmcpioRead()`. Upstream fix `5bc8705e0`, parent `c36e85503`; no tag at the
provisioned HEAD contains the fix, so upstream version boundaries are UNKNOWN.

Pins: full `lib/rpmfi.cc` from parent and fix, plus byte-exact excerpts of
`rpmfiSetFound`, `rpmfiFound` and `iterReadArchiveNext()` (hashes in
`PROVENANCE.md`). Header `lsize = -1` as int64; `xmalloc(lsize + 1)` wraps to
a 1-byte region; the stand-in `rpmcpioRead()` copies 64 chosen bytes.
GCC and Clang ASan both report `heap-buffer-overflow`, `WRITE of size 64`,
0 bytes after the 1-byte region, in the pinned function. Plain readback:
`CANARY_AFTER=495348452d52504d2121414141414141`. Fixed build rejects the
mismatch (`RET=-15`), safe input is clean (`RET=0`). `run-all.sh`:
28 PASS / 0 FAIL in-tree and from a clean git archive.

Grade: **rung 3 pinned verbatim / rung 4 PARTIAL** (chosen bytes past the
allocation in a synthetic consumer). No real library build, crafted RPM
package, pointer, wire, command or r5. Negative preserved: GCC 13.3 ASan at
`-O1` misses the overflow after inlining; ASan builds use `-O0`.

## Next

1. Replay `bash lab/frontier/rpm2shell/run-witness.sh` and ask the witness to
   verify the labeled grade.
2. Build real rpm at the vulnerable parent with ASan; drive `rpm2cpio` or
   `rpm -qlvp` on a synthesized package with a `UINT64_MAX` symlink size and
   a small controlled cpio payload; measure the real read length and whether
   bytes overlap a live object.
3. Only after a real-consumer write with fixed and safe controls: assess a
   pointer-bearing target. Keep the no-command ceiling.

## Receipts

- Clean-archive replay from the staging commit: recorded below when run.
- Window: recorded below when created.
