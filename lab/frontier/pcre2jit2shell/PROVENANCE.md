# PROVENANCE — pcre2jit2shell

## Scope

Local, loopback-free reproduction of CVE-2026-103111 / GHSA-r9hj-j2rw-4q3m in
pinned PCRE2 10.48 and 10.49 builds. Public advisory, release tarballs, fix
commit and attached PoC were fetched read-only (provisioning, not probing).
No external system was contacted with a trigger; no socket, live service,
command or rung-5 path is claimed.

## Pins (SHA-256, local files)

- `src/pcre2-10.48.tar.gz`
  `ebcc25aadf2a51fa1fefa9b8bc9e7a79b3dae86870a0f1152a22e42befd46888`
  (vulnerable release)
  URL: https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.48/pcre2-10.48.tar.gz
- `src/pcre2-10.49.tar.gz`
  `929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae`
  (fixed release)
  URL: https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.49/pcre2-10.49.tar.gz
- `src/fix.patch`
  `38f740cb52919619945f3cf4b68a7c0892f68b564ef14879266781ee70b4165f`
  URL: https://github.com/PCRE2Project/pcre2/commit/2b4038298072684b0fae29b15bedfb1a75bda46d.patch
- `src/poc-upstream.c`
  `2bda01bc0d70ac7888a8205aa9141e4bf8efcc0e7b48cc50eb23adca56756cd4`
  URL: https://github.com/user-attachments/files/32262707/pcre2_10_48_jit_stack_underwrite_poc.c
  (hash matches the advisory's attachment table exactly)
- `evidence/regression-input.txt`
  `50be5b8ef5b1c3d4894754f055ba9d7c0c00571a0724f4f29b9851e3f482c38b`
  (the exact pattern and `\\=jitstack=192` line added to testdata/testinput17 by
  src/fix.patch)
- Pinned `src/pcre2_jit_compile.c`: 10.48
  `60cb5be780844af9edbcda95010478afe56e95623bccb677b29113b4552321c8`;
  10.49 `32b4f057cc8ac9a15c9c837121112329e866c1bc1d98acce148ceeff4525c587`.

Primary advisory re-verified 2026-11-26:
https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-r9hj-j2rw-4q3m
and https://www.cve.org/CVERecord?id=CVE-2026-103111.

## Build and inputs

`sh run-all.sh` re-extracts both tarballs into `replay-build/{vuln,fixed}`,
asserts every pin and source hash, dry-run applies the fix to pinned 10.48,
builds plain static JIT libraries via `./configure --enable-jit
--disable-shared --enable-static && make -j4 pcre2test`, and compiles the
hash-matched PoC against each library plus a `-DUNIQUE_CAPTURES=100`
small-frame variant. The shipped-CLI input is the fix patch's own regression
pattern. Nothing from a prior build directory is reused by the runner.

PoC physical mode maps a separate 1 MiB victim immediately below PCRE2's
192 KiB JIT stack with `MAP_FIXED_NOREPLACE`; it reads SLJIT's private stack
fields via a struct-representation copy only to locate that boundary and never
modifies library state. It fills the victim with 0xa5, then JIT-matches the
1,400-capture recursive pattern against a 10-byte subject. Logical mode and
arbitrary choice of written bytes were not used as evidence.

## Observations (author run 19:31Z, `console.log`, `evidence/replay/`)

- Shipped `pcre2test` + regression line: pinned 10.48 `Segmentation fault
  (core dumped)`, rc 139; pinned 10.49 `Failed: error -46: JIT stack limit
  reached`, rc 0. Traces: `out/pcre2test-{vuln,fixed}.out`.
- Pinned 10.48 JIT physical PoC (repeatable): `pcre2_match returned -46`,
  `victim bytes clobbered: 139976`, `deepest write: 139976 bytes BELOW the jit
  stack mapping`, `aligned words holding a pointer into the subject buffer:
  15`, PoC rc 0. Changed-byte count varied 139,972–139,976 across earlier
  exploratory runs; depth and pointer count stayed at 139,976 / 15.
- Controls on pinned 10.48: `--no-jit` interpreter match 2, victim clean, zero
  pointers; 100-capture small-frame build match 2, victim clean. On pinned
  10.49: JIT match -46, victim clean, zero pointers; interpreter match 2,
  victim clean. Fit results are in `evidence/replay/*.out` with rc and try
  count in `.rc` / `.tries` files.
- `sh run-all.sh` output: `RESULT PASS=46 FAIL=0`, runner rc 0.

## Preserved negatives and caveats

- `MAP_FIXED_NOREPLACE` victim placement collides under ASLR on some runs
  (10.48 JIT valid on try 3, no-jit on try 3, small frame on try 5, 10.49 JIT
  on try 8 in the author run). All failed attempts are kept as
  `evidence/replay/*-try-N.out`; only a successfully placed run is asserted.
  A placement failure means UNKNOWN for that attempt, never a pass.
- Two ASan builds (10.48/10.49, `make -j4`) were killed during parallel
  compilation of `pcre2_match.lo` in this wake; no ASan report exists here.
  Rung 3 is therefore NOT CLAIMED: the escaping stores are emitted by JIT
  machine code into mmapped regions, outside compiler instrumentation.
- The advisory's macOS/AArch64 and Rosetta observations were not reproduced;
  this host is Linux x86-64 only. The fixed version was verified from its
  release tarball; the fix patch's dry-run application to 10.48 was checked
  but no patched 10.48 physical run was performed.
- Rung 4 is bounded: chosen bytes are JIT frame state, not arbitrary attacker
  values; 15 words happen to hold pointers into the subject buffer. No
  control-flow target, command, socket, live consumer or wire input was
  exercised. Rung 5 NOT CLAIMED.
