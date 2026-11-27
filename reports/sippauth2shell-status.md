# sippauth2shell — status (admitted 2026-11-27 W334)

State: **ADMITTED 11:0xZ under standing #6 as the 209th declared target mind;
stage independently replayed W335, ESTABLISHED AS LABELED.**
`reports/frontier-sippauth2shell.md`, lab
`lab/frontier/sippauth2shell/`, provenance in that lab's `PROVENANCE.md`,
charter `.mishe-tauftauf/charters/sippauth2shell.md`, seed wall
`.mishe-tauftauf/walls/sippauth2shell.md`. Stage commits `b5c4e199` and
`884f4fdc`; operator clean replay of
`git archive --format=tar 884f4fdc lab/frontier/sippauth2shell` (plain-tar
SHA-256 `2699180e7c67689cad4c4206bd2f6fe6f714cb1ac7783d3176b17b945eb00cba`,
gzip container `dbeb0b98c9cf2611bd773d55e3f4e1012a68d04f3d40e2ac67e4015a13e87715`)
matched all 8 harness/pin hashes, built all four variants and returned
`TOTAL: 15 PASS / 0 FAIL` with the same summary SHA-256
`8dd157952a776ea48083b9acd73c279e25a04142b4b808375fdfb3d4037fc802`. Live
inner-socket window 217 (`%440`/`%441`, dead=0), registry 218/218 unique
names.

Finding: CVE-2026-90779 (CWE-121, SIPp <= 3.7.7), pinned v3.7.7
`369b3c18…` → v3.7.8 `741ee230…`, exact fix `1d4a5622…` (not an ancestor of
v3.7.8; equivalent bounded call in that release). A challenge-controlled
`algorithm=` length feeds `strncpy(algo, start, end-start)` into `algo[32]`
at `src/auth.cpp:188`, with a NUL at `:190`.

Grade: R1/R2/R3 ✓ — ASan `WRITE of size 64` at `auth.cpp:189` into
`[32,64) 'algo'`; 32-byte boundary case is a `WRITE of size 1` at `:190`;
fixed and safe controls clean. R4 DEMONSTRATED **in-process**: read-only GDB
sees `algo+32..+43` as chosen `0x41` and saved RBP/RIP `0x4141414141414141`;
with 62 chosen bytes the six low saved-RIP bytes are chosen while the high
zero bytes survive, and a benign marker mapped at canonical
`0x0000414141414141` executes in the vulnerable plain O0 build. The marker
`mmap(MAP_FIXED)`, unprotected build and direct call are explicit lab
conditions. R5 NOT CLAIMED — no live SIPp process, socket request,
production mapping or command side effect was observed; the source-level
401/407 wire path is untested.

`./run-all.sh`: `TOTAL: 15 PASS / 0 FAIL`, stdout SHA-256
`8dd157952a776ea48083b9acd73c279e25a04142b4b808375fdfb3d4037fc802`
byte-identical across two runs; pin/harness hashes in
`lab/frontier/sippauth2shell/HARNESS_SHA256.txt`.

Witness verdict (#6378, W335 11:1xZ): **ESTABLISHED AS LABELED**, no grade
change, NO r5. From clean plain-tar `2699180e...` (the gzip container is
`dbeb0b98...`), the witness checked 8/8 pins, rebuilt all four variants and
ran the unmodified runner: 15 PASS / 0 FAIL with byte-identical summary
`8dd15795...`. Fresh ASan WRITE-1 at `auth.cpp:190` / WRITE-33/64 at `:189`,
fixed and 8/31-input controls clean; GDB saved-RIP overwrite and lab-mmap
marker reproduced. Falsifier arms: 62 bytes without the mmap faults with no
marker, and a `0x42` fill drives a `0x4242...` marker. No wire request,
command side effect or grade/r5 inflation. Detail
`.mishe-tauftauf/artifacts/witness-w335-sippauth/detail.md`.

Next (witness closed): one bounded depth experiment owned by the target mind:
  a loopback UAS/UAC
401 challenge with 62 chosen `algorithm=` bytes, checking whether
`createAuthHeader()` is reached from a real request and whether the return
target is mapped in that process; fixed v3.7.8 and safe-input controls.
Prediction: wire-reachable crash with harness-only control-flow mechanics,
not rung 5. A wire no-result is a legitimate negative; no rung-5 claim
without an observed request-driven command side effect. Wake units and
routes are person-reserved.
