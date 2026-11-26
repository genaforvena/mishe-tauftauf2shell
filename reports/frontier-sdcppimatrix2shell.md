# Frontier brief: sdcppimatrix2shell — CVE-2026-70659 (duplicate-name imatrix heap overflow)

**Status: ADMISSION DECLINED 2026-11-26 21:57Z (operator #5858) — duplicate of
sdimatrix2shell (168th mind, W260 ESTABLISHED): same CVE, same tags, same
verbatim sink. Local result unchanged: rung 1 + rung 2 plain-build abort, rung 3
ASan-confirmed heap-buffer-overflow; rung 4 and rung 5 NOT CLAIMED.**
Everything before the local section is a claim from the cited public pages;
the pinned bytes and observations below are this plant's own. The witness
re-runs any published claim. Window 198 was retired and its registry entry
removed; staged harness retained as an alternate rebuild. No further frontier
work on this candidate.

## Verified ground truth (claim sources read 2026-11-26)

- **Claim source:** GitHub Security Advisory
  `https://github.com/leejet/stable-diffusion.cpp/security/advisories/GHSA-6q7q-2v9c-x8m7`
  (CVE-2026-70659, published 2026-09-27, High 7.8,
  CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, CWE-787 + CWE-1284).
- **Versions:** affected `master-742-1a13107` through `master-763-4fcc6fe`;
  first fixed `master-763-4fcc6fe` (commit
  `4fcc6fef10c6f686801c6e257b22cd6a3deb906b`, PR #1750). Tag SHAs resolved
  from the GitHub refs API: `1a13107bac23…` and `4fcc6fef10c6…`.
- **Claimed primitive:** `IMatrixCollector::load_imatrix()` resizes an
  entry's `values`/`counts` only when empty; a repeated tensor name collapses
  into one `unordered_map` entry, so a second, larger `nval` loops past the
  first entry's buffers. The advisory reports attacker-controlled written
  value, written int and OOB length, plus an observed SIGSEGV in the real
  `sd-cli -M convert --imat-in poc.imatrix` path. Those real-binary details
  are **claims**, not re-tested here.
- **Fix (verified raw patch, `pins/fix-4fcc6fef.patch`):** +4 lines in
  `src/runtime/imatrix.cpp`; reject a repeated entry whose value count
  differs, clear `stats_` and return false. No other file changed.

## Source-bound mechanism (pinned bytes)

`src/imatrix.cpp.vuln:276` is
`auto& e = stats_[std::move(name)];`; `:287-290` resizes only when
`e.values.empty()`; `:301-303` is the sink:

```
for (int i = 0; i < nval; i++) {
    e.values[i] += tmp[i];
    e.counts[i] += ncall;
}
```

The fixed raw file at tag `master-763-4fcc6fe` adds the inconsistent-size
guard at `:290-292`. The sibling `collect_imatrix()` in the same file
already performs the missing consistency check at `:105` and `:142`.

## Local observation (2026-11-26 W293, GCC ASan and plain, loopback-free)

Pins: `src/imatrix.cpp.vuln` `fb09b234ddce…`, `src/imatrix.cpp.fixed`
`73c5cbd449f1…`, `src/imatrix.h.vuln` `464a0417fbdd…`, fix patch
`792c4d07666a…` (all in `lab/frontier/sdcppimatrix2shell/pins/PIN_HASHES.txt`).
`harness/main.cpp` calls the shipped global `load_imatrix()`; the stub
headers supply only the GGML type surface and logging macros, no parser
logic. Exact input (`evidence/attack.imatrix`, 298 bytes): `n_entries=2`;
entry A `("blk.0", ncall=1, nval=1, [1 float])`; entry B the **same**
`blk.0` with `nval=64` and 64 floats. `evidence/safe.imatrix` uses distinct
names and is clean on both pins.

`runs/asan-vuln-attack.out` (addresses/PIDs are run-specific):

```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4
    #0 IMatrixCollector::load_imatrix(char const*) src/imatrix.cpp.vuln:302
    #1 load_imatrix(char const*) src/imatrix.cpp.vuln:168
0x... is located 0 bytes after 4-byte region [...)
allocated by std::vector<float>::resize ... src/imatrix.cpp.vuln:288
SUMMARY: AddressSanitizer: heap-buffer-overflow src/imatrix.cpp.vuln:302
```

rc 1. `runs/plain-vuln-attack.out`: `double free or corruption (out)`,
rc 134 — a non-sanitizer file-only crash and heap state failure. The fixed
build on the same input logs `ERROR inconsistent size for a repeated entry
(1 vs 64)` and returns rc 3; safe input is rc 0 and ASan-clean on both pins.
`run-all.sh` **PASS=17 FAIL=0** at 21:42Z (`runs/run-all.log`).

## Rung-4 feasibility (honest)

- **Rung 1 and rung 2 observed**: deterministic local-file trigger, plain
  build aborts with a glibc heap-corruption diagnostic; fixed build rejects.
- **Rung 3 ASan confirmed** on the verbatim pinned sink; fixed and safe
  controls clean.
- **Rung 4 NOT CLAIMED.** ASan traps on the OOB READ half of
  `e.values[i] += tmp[i]` before the OOB WRITE half and `e.counts[i] += ncall`
  are separately observed. No chosen bytes at chosen offsets, no pointer
  control, marker or command. A plain-build heap-layout study is the next
  experiment, not an observed result.
- **Rung 5 NOT CLAIMED.** Local `.imatrix` file only; no wire path, live
  service or remote command.

## Cheapest local experiment that could move this up a rung

1. Build the full shipped `sd-cli` at both pinned tags and replay the
   advisory's `-M convert --imat-in` command, with a model-free input; that
   would confirm or refute the advisory's real-binary claim (rung 1/2 on a
   shipped consumer). Full tarballs were attempted but timed out; fetch the
   two tag tarballs or clone at the pinned tags to build `sd-cli`.
2. Under the plain build, groom the heap after the first vector resize and
   observe whether a chosen attacker float lands in a chosen neighbouring
   object's bytes; only an observed write at a controlled offset is rung 4.
3. Debugger-pin which allocation `e.counts` gets and whether its OOB write
   reaches an attacker-relevant field. Do not promote an ASan read, a glibc
   abort or a synthetic marker to rung 5.

## Re-rank of the nine unowned W288 candidates (this wake)

Three read-only scouts re-ranked all nine; none matched the do-not-duplicate
list. Ranked by tractability, not advisory severity:

1. **sd.cpp (staged here)** — HIGH: pinned tag pair, +4-line fix, 298-byte
   deterministic binary input, no model needed, shipped loader sink.
2. **OpenImageIO** CVE-2026-108386 / GHSA-h4p2-w2vv-76h5 — HIGH but heavy:
   first fixed 3.2.0.4 / 3.1.18.0, fix `54be878d…`, advisory ships full
   C++ PoC; a peer lane already holds a 3.2.0.2-dev tree and ASan build at
   `lab/openexr2shell-real/oiiolab/`, so an ownership seam is required.
3. **VVdeC** CVE-2026-124309 / GHSA-h6mq-3rv5-2v7m — HIGH: <3.2.1 fixed
   3.2.1, commit `1d657c7a…` deletes 5 lines in `SEIread.cpp`; needs an
   external VVC bitstream PoC and a `vvdecapp` build with ASan.
4. **live555** CVE-2026-137587 — HIGH-ish: <2026.08.25, mirror commit
   `03015a0a…`, 9-line guard in `parseVorbisOrTheoraConfigStr()`; needs a
   crafted SDP config and a small build, no upstream git tags.
5. **poppler** CVE-2026-131846 — MED: `SplashOutputDev::iccTransform()`
   colour buffer sized `nComps*W` but DeviceN8 writes 8 bytes/pixel; PoC is
   attached to the issue, but the issue is still open with **no fix commit
   or fixed version** — no patched control.
6. **Tesseract** CVE-2026-88051 — MED: <=5.5.3, fixed 5.5.4, commit
   `56e09ca1…` validates vector counts, unit-test PoC in the fix; heavier
   traineddata + leptonica build.
7. **OpenSCAP** CVE-2026-122056 — MED-low: one-byte NUL OOB write in
   `src/DS/sds.c`, +1-line fix `5f1f2bcc…`, tiny XCCDF trigger, but no
   tagged fixed release and a dependency-heavy build.
8. **curl** CVE-2026-92392 — MED: UAF fixed 8.23.0, commit `8b0744af…`,
   needs a malicious HTTP/2 server and timing; a simpler local API sibling
   CVE-2026-92391 exists. curl is a large build.
9. **libvorbis** CVE-2026-137079 / -137078 — LOW: affected through 1.3.7
   but fixes are **unmerged PRs** (no first-fixed tag); an abandoned local
   scaffold with two loose source files exists but has no pins, harness or
   brief. A merged sibling fix exists for CVE-2026-8946.

Negative preserved: after operator review sd.cpp was screened out as a
duplicate of sdimatrix2shell (admission declined #5858); the other eight
remain unowned, five with material control/build gaps.
