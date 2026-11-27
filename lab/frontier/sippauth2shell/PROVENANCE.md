# Provenance — sippauth2shell (CVE-2026-90779)

## Claim and pins

- Claim: VulnCheck CNA record
  https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/90xxx/CVE-2026-90779.json
  and advisory
  https://www.vulncheck.com/advisories/sipp-through-3.7.7-stack-buffer-overflow-via-createauthheader-algorithm-parameter
  (published 2026-09-13). SIPp <= 3.7.7, oversized `algorithm=` in a 401/407
  challenge overflows `algo[32]` in `createAuthHeader()`. Public PoC: UNKNOWN;
  no GHSA ID found (UNKNOWN). Finding Tristan Madani, per CNA record.
- Vulnerable release pin: SIPp v3.7.7
  (`369b3c187f0ff96f3ec9795650820e80cf17c776`), official release tarball
  `pins/vuln.tar.gz` SHA-256
  `e55b15f567760e9febeef366a1ab51a5239d197a132ce931b78c826d22d31e69`.
- Fixed release pin: SIPp v3.7.8
  (`741ee230bfda890c8605253b32b449dfef3dd421`), official release tarball
  `pins/fixed.tar.gz` SHA-256
  `a2519f852e2c3eb803298b87219e8b83a9b068f0f472ef0486b447342ec8cfec`.
- Exact upstream fix `1d4a5622bea34d0b5cdff333e6b5734608e30af7` (parent
  `5dff0ec671c21e87ab5583cf3b75e2391bf01ccb`), patch `pins/fix.patch`
  SHA-256 `cdf11f4b10af106af3832df74b4f0443894e3fee12cffffcf532e9dd528870fe`.
  It replaces the inline `strncpy` with
  `getAuthParameter("algorithm", auth, algo, sizeof(algo))`. That commit is
  NOT an ancestor of v3.7.8; v3.7.8 carries the equivalent bounded call
  (`09916a92de768ab08056a78e4731f9edc3853e1c`), verified in the pinned source.
  GitHub archive tarballs for both tags were also fetched and hashed during
  provisioning (`2717f0fb…` / `ee6a6183…`) but lacked generated `version.h`,
  so the official release tarballs are the pins used here.
- All fetches were read-only provisioning of public sources. No external
  system received probe traffic.

## Sink and source-bound mechanism

In pinned v3.7.7 `src/auth.cpp:170` declares `char algo[32] = "MD5"`.
At `:188` the inline parser runs
`strncpy(algo, start, end - start)` where `end-start` is the attacker-controlled
length of the challenge's `algorithm=` value, and `:190` writes
`algo[end-start] = '\0'`. The fixed release uses the bounded
`getAuthParameter()` call at `:177`. The source call chain
`src/call.cpp:5503-5529` (401/407 `WWW-`/`Proxy-Authenticate` extraction,
gated by `bShouldAuthenticate`) → `src/call.cpp:4054-4058` →
`createAuthHeader()` is read from pinned source only; it was NOT exercised
over a socket in this stage.

## Build and harness

`./bootstrap.sh` creates four builds from the pinned tarballs:
`out-vuln`/`out-fixed` (`-DUSE_ASAN=ON`, Debug, `-O0 -g
-fsanitize=address -fno-sanitize-recover=all -fno-omit-frame-pointer`) and
`out-vuln-plain`/`out-fixed-plain` (Debug, `-O0 -g -fno-stack-protector
-D_FORTIFY_SOURCE=0`). Each build links the real SIPp objects. The harness
renames SIPp's own `main` with `objcopy --redefine-sym main=sipp_main` and
links all remaining objects so `createAuthHeader()` is the authentic pinned
function. `harness/auth_overflow.cpp` supplies the challenge;
`harness/marker_overflow.cpp` maps a benign lab marker with `mmap(MAP_FIXED)`
before the call; `harness/gdb-readback.cmd` reads the overwritten frame
read-only. All build and run recipes are in `bootstrap.sh` and `run-all.sh`.

## Observed results (2026-11-27 W334)

- Vulnerable ASan: 8- and 31-byte values clean; 32 bytes → `WRITE of size 1`
  at `auth.cpp:190` (the NUL), offset 64 in the frame, `[32, 64) 'algo'`;
  33 bytes → `WRITE of size 33` at `:189`; 64 bytes → `WRITE of size 64`
  at `:189` via `strncpy`, same `algo` frame. `rc=1` for all three faults.
- Fixed ASan: 8/31/32/33/64 all `rc=0`, no ASan report.
- Plain vulnerable O0: 31 bytes `rc=0`; 64 bytes `rc=139`. Fixed plain both
  `rc=0`. Default hardened builds were not used for the control-flow arm;
  the unprotected build is an explicit condition of that observation.
- Read-only GDB at `auth.cpp:190`, 64-byte value: `algo+32..+43` are twelve
  `0x41` bytes; `$rbp` and `$rbp+8` are `0x4141414141414141`; frame #1 is
  `0x4141414141414141` and the process faults at the `ret` (#GP, noncanonical).
  With 62 bytes, the six low saved-RIP bytes are chosen and the original zero
  high bytes survive, so the `ret` enters canonical `0x0000414141414141`;
  after `mmap(MAP_FIXED)` of a benign marker there, the vulnerable build
  prints `SIPP_AUTH_MARKER` and exits 0. The fixed build returns normally
  and prints no marker. The mapping is lab mechanics, not a wire primitive.
- `./run-all.sh`: `TOTAL: 15 PASS / 0 FAIL`, stdout SHA-256
  `8dd157952a776ea48083b9acd73c279e25a04142b4b808375fdfb3d4037fc802`
  (`summary.txt`). All 6 harness compiles rc 0. Pin and harness hashes are
  in `HARNESS_SHA256.txt`.

## Grade and negatives

R1 (reproducible trigger), R2 (state failure: chosen length crosses the
buffer), R3 (ASan-confirmed stack corruption) ✓. R4 DEMONSTRATED at the
in-process level: chosen bytes replace the saved RIP and a lab-mapped benign
marker executes. No live SIPp process, socket request, production mapping or
command side effect was observed. R5 NOT CLAIMED. The `bShouldAuthenticate`
gate and the exact 401/407 packet that reaches this sink remain untested;
a loopback UAS/UAC replay is the next experiment, and a no-result there is a
legitimate negative. Default production hardening (`-fstack-protector`) was
not exercised in the control-flow arm.
