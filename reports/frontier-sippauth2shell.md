# Frontier brief: sippauth2shell — 401/407 algorithm= stack write and saved-RIP control

**Status: STAGED 2026-11-27 W334, handoff brief ready for operator admission.**
Claim is a CWE-121 stack buffer overflow in SIPp's `createAuthHeader()`,
pinned between v3.7.7 and v3.7.8. Reproducible lab:
`lab/frontier/sippauth2shell/`; author-side only, no witness replay yet. CVE
is CVE-2026-90779; no GHSA ID found (UNKNOWN) and no public PoC found
(UNKNOWN).

## Verified ground truth

- Claim source: VulnCheck CNA record
  https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/90xxx/CVE-2026-90779.json
  (published 2026-09-13) and
  https://www.vulncheck.com/advisories/sipp-through-3.7.7-stack-buffer-overflow-via-createauthheader-algorithm-parameter
  (SIPp <= 3.7.7; oversized `algorithm=` in a 401/407 challenge overflows
  `algo[32]`; CWE-121; CVSS4 8.7).
- Pins: vulnerable v3.7.7
  `369b3c187f0ff96f3ec9795650820e80cf17c776`, fixed v3.7.8
  `741ee230bfda890c8605253b32b449dfef3dd421`; official release tarballs
  SHA-256 `e55b15f5…` and `a2519f85…`. Exact fix
  `1d4a5622bea34d0b5cdff333e6b5734608e30af7` is not an ancestor of v3.7.8;
  v3.7.8 contains the equivalent bounded call. See lab `PROVENANCE.md`.
- Grade: R1/R2/R3 ✓; R4 DEMONSTRATED in-process (chosen saved RIP, benign
  marker after a lab `mmap(MAP_FIXED)`); R5 NOT CLAIMED.

## Source-bound mechanism

`src/auth.cpp:170` declares `char algo[32]`. The v3.7.7 parser at `:188`
calls `strncpy(algo, start, end-start)` with the challenge-controlled length
and writes a NUL at `:190`. The fix replaces the inline parser with
`getAuthParameter("algorithm", auth, algo, sizeof(algo))`. Pinned source
traces the value from 401/407 `WWW-`/`Proxy-Authenticate` extraction in
`src/call.cpp:5503-5529` (gated by `bShouldAuthenticate`) to
`createAuthHeader()` at `src/call.cpp:4054-4058`; that wire path was not run.

## Cheapest local experiment and result

`./bootstrap.sh` builds vuln/fixed × ASan/plain from the release pins; six
harness binaries link against the real SIPp objects (SIPp's `main` renamed
by `objcopy`). Vulnerable ASan: 8/31 bytes clean, 32 bytes `WRITE of size 1`
at `auth.cpp:190`, 33 bytes `WRITE of size 33` at `:189`, 64 bytes
`WRITE of size 64` at `:189` into `[32,64) 'algo'`; fixed all five sizes
clean. Vulnerable plain O0: 64 bytes rc 139, 31 bytes rc 0; fixed both rc 0.
Read-only GDB at `:190` shows `algo+32..+43` = twelve chosen `0x41` bytes and
saved RBP/RIP `0x4141414141414141`. With 62 bytes, the six low saved-RIP
bytes are chosen and the high original zero bytes survive; a lab-mapped
benign marker at canonical `0x0000414141414141` executes and prints
`SIPP_AUTH_MARKER` in the vulnerable build, while the fixed build returns
normally with no marker. `TOTAL: 15 PASS / 0 FAIL`, summary SHA-256
`8dd157952a776e…`. The GDB readback, marker `mmap` and unprotected build are
explicit lab conditions, not a claim about a stock production process.

## Cheapest next rung

Run the pinned binaries on loopback: a UAS scenario returning 401 with
`WWW-Authenticate: Digest ... algorithm=` of 62 chosen bytes, a UAC scenario
with authentication enabled (`-u user password`) and ASan, then verify the
challenge reaches `createAuthHeader()` and record whether the `ret` target
is mapped in that process. If not, the honest outcome is a wire-reachable
crash with rung-4 mechanics only in the harness; no rung 5 without a
request-driven command side effect.

## Ranking context

Chosen over NanoMQ CVE-2026-73863 (read-only OOB READ, fixed-version conflict,
previously screened out) and bincookie CVE-2026-55246 (cheap header-only
harness but file-only and no control flow). SIPp has exact pins, a real
401/407 source path, a small fix and an observed in-process chosen-RIP
marker, making it the strongest next target for a wire experiment.
