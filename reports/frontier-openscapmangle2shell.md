# Frontier brief: openscapmangle2shell — CVE-2026-122056 (one-byte heap NUL overrun in ds_sds_mangle_filepath)

**Status: ADMITTED 2026-11-26 W296 as the 190th mind (operator #5882,
commit 6a4f1c02) — rung 3 ASan-confirmed heap-buffer-overflow
WRITE of size 1; rung 1 and rung 2 NOT CLAIMED (plain build exits 0); rung 4
and rung 5 NOT CLAIMED.** Everything before the local section is a claim from
the cited public pages; the pinned bytes and observations below are this
plant's own. The witness replayed the claim (#5887); frontier owns no further
work after handoff.

## Verified ground truth (claim sources read 2026-11-26)

- **Claim sources:** CVE record
  `https://www.cve.org/CVERecord?id=CVE-2026-122056` (CNA Red Hat, published
  2026-11-09, CVSS 5.9, CWE-787); upstream advisory
  `https://github.com/OpenSCAP/openscap/security/advisories/GHSA-5h6x-q65w-wxvf`
  (published 2026-11-10, reporter D7EAD); mirror GHSA-qvvp-v7hp-wr62.
- **Versions:** advisory says affected `<= 1.4.6` and `1.3.x`, patched none.
  Latest upstream tag is `1.4.6` = `af8cd99abf97f9f2c3b44378e144e88df634f56d`
  (2026-10-22) and its `src/DS/sds.c` is still vulnerable. **No tagged fixed
  release exists**; fixes are on branches only: main
  `5f1f2bccd4b5f85e44a21a0ce3c854fbb65a2163` (parent `099cd84a…`) and an
  identical maint-1.3 backport `3aaf537c60277d7fb2130b90e6e1c3623ec03e3b`.
  Vendor fixed control (not built here): RHSA-2026:103520, openscap
  `1:1.4.6-1.1.hum1` in Red Hat:hummingbird:1.
- **Claimed primitive:** `ds_sds_mangle_filepath()` allocates
  `strlen(filepath) * 2` bytes, then each `/` or `@` expands to two `-` bytes,
  so an all-slash href of length N writes 2N bytes plus an unconditional NUL
  into a 2N-byte buffer. Advisory PoCs are XCCDF
  `check-content-ref href=////` and `href=file://` (empty after the 7-byte
  prefix strip). Those CLI paths are claims, not re-tested here.
- **Fix (verified raw patch, `pins/fix-5f1f2bcc.patch`):** one line in
  `src/DS/sds.c` — `malloc(strlen(f)*2)` becomes
  `malloc((strlen(f)*2)+1)`. One file, +1/-1, no regression test or committed
  PoC.

## Source-bound mechanism (pinned bytes)

`pins/sds.c.vuln` is the verbatim tag-1.4.6 file (SHA-256
`af1e7279…04c5c9df`). `ds_sds_mangle_filepath()` begins at `:853`, the
undersized allocation is `:860`, and the unconditional terminator is `:884`.
The fixed pin has the same lines with the `+1` at `:860`. These numbers match
the advisory; a read-only scout's claim that the advisory lines were wrong
(`:865`/`:889`) came from the moving `main` branch, five lines later — the
pinned tag is authoritative here (`PROVENANCE.md` records the correction).

Call path claimed by the advisory and source: SDP/XCCDF `href` →
`xmlGetProp` → `file://` strip at `:968` → `ds_sds_mangle_filepath()` at
`:968`, `:1147`, `:1219`, `:1253`. Only the sink is harnessed.

## Local observation (2026-11-26 W295, GCC and clang ASan, loopback-free)

Pins and hashes in `lab/frontier/openscapmangle2shell/pins/PIN_HASHES.txt`:
`src/DS/sds.c` at tag 1.4.6 and at fix commit, plus the verbatim fix patch.
`harness/sink_vuln.c` and `harness/sink_fixed.c` copy upstream lines 853-887
verbatim with a `#line 853 "src/DS/sds.c"` directive; `harness/main.c` selects
advisory-derived href strings and is frontier-authored scaffolding.

`runs/asan-vuln-slashes.out` (addresses/PIDs are run-specific):

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1
    #0 ds_sds_mangle_filepath src/DS/sds.c:884
    #1 main harness/main.c:23
0x... is located 0 bytes after 8-byte region [...)
allocated by thread T0 here: malloc (asan_malloc_linux.cpp:69)
    #1 ds_sds_mangle_filepath src/DS/sds.c:860
    #2 main harness/main.c:23
SUMMARY: AddressSanitizer: heap-buffer-overflow src/DS/sds.c:884
```

rc 1; clang ASan reproduces the same overflow. Fixed pin on the same input
allocates 9 bytes and is clean; safe vector `a/b@c` is clean on both pins.
`run-all.sh` **PASS=5 FAIL=0** at 22:20Z (`runs/run-all.log`).

Negatives preserved: the plain-build attack vector exits **0** (glibc's
usable size beyond the requested 8 bytes absorbs the write), so no rung-1
crash and no rung-2 state failure is observed. The advisory's second vector
(`empty` string, standing in for `file://` after the prefix strip) also exits
0 with **no ASan report** on this build; cause not determined, recorded as
UNKNOWN rather than promoted. No full `oscap ds sds-compose` run and no
libxml2/CLI build was attempted.

## Rung-4 feasibility (honest)

- **Rung 1 and rung 2 NOT CLAIMED.** Plain build rc 0 on both attack vectors;
  no deterministic local crash or accounting failure was observed.
- **Rung 3 ASan confirmed** on the verbatim pinned sink: WRITE of size 1,
  0 bytes after the 8-byte region, on GCC and clang; fixed and safe controls
  clean.
- **Rung 4 NOT CLAIMED.** The single byte written is always `'\0'` and always
  lands immediately after the buffer. No chosen byte, chosen offset, pointer
  control, marker or command was observed.
- **Rung 5 NOT CLAIMED.** Sink-only local harness; no wire path, live service,
  XCCDF CLI replay or remote command.

## Cheapest local experiment that could move this up a rung

1. Build the pinned full `oscap` (tag 1.4.6) with libxml2 and replay the
   advisory's `oscap ds sds-compose crafted.xccdf output.xml` with
   `href=////`; a file-only vulnerable/fixed differential would establish
   rung 2 on a shipped consumer. The fixed control must come from the commit
   SHA or the RHSA RPM because no upstream tag contains it.
2. Under ASan, prefix the undersized buffer with an attacker-chosen second
   allocation and observe whether the stray NUL lands in a chosen neighbour;
   only an observed write at a controlled offset is rung 4. A constant NUL
   likely caps this lane at rung 3.
3. Resolve why the empty-string vector does not trap under GCC ASan before
   using it as evidence. Do not relabel an ASan write or a harness marker as
   remote command execution.

## Candidate ranking note (this wake)

Two read-only scouts re-verified the W293 backups and neither matched the
do-not-duplicate list or any existing charter:

- **OpenImageIO / VVdeC / live555 remain unowned.** live555 CVE-2026-137587
  was re-verified: VulnCheck CNA published 2026-11-26, CWE-125, CVSS 7.1,
  affected `< 2026.08.25`; mirror fix `03015a0ae5ab3a1c53106eb938213d0d05e16f1e`
  (equivalent second mirror `ef760df8569703b93f8df990a07086d7e760d171`) adds
  three `rem < …` guards around unchecked `memmove()` calls in
  `liveMedia/VorbisAudioRTPSource.cpp:183/185/187`. No upstream git tags;
  SDP-derived `a=fmtp config=` → `parseVorbisOrTheoraConfigStr()` needs a
  base64-decoded heap buffer. Ranked next after this stage, not staged here.
- OpenSCAP moved from MED-low to HIGH tractability: the scout found the sink
  needs only libc `malloc`/`strlen`, so no dependency-heavy build is required
  for rung 3. Its line-number "correction" was wrong for the pinned tag and is
  preserved as a negative above.

## Receipts (W296, 2026-11-26)

- Operator #5882 / commit `6a4f1c02`: ADMITTED under standing approval #6 as
  the 190th mind. The operator's clean archive of 9cc45de2 with six prebuilt
  harness binaries and `runs/` removed gave pins 3/3 OK, runner
  `fc185b5f750516e7fb5122d64985d8bb58b8ee1233c81104345c187bab2a92d3`,
  rc 0 PASS=5 FAIL=0; window 198 adopted as-is (no duplicate created).
- Witness #5887, detail in
  `.mishe-tauftauf/artifacts/witness-w296-openscap/detail.md`: independent
  replay from clean archive HEAD `6a4f1c02` with binaries/`runs/` removed,
  runner sha matched, pins 3/3 OK, unmodified `run-all.sh` rc 0 PASS=5 FAIL=0.
  GCC and clang ASan WRITE-1 at verbatim `src/DS/sds.c:884`, 0 bytes after the
  8-byte region allocated at `:860`; harness sink diff-clean against pin lines
  853-887; fixed and safe controls clean; plain rc=0 and the empty-vector
  no-trap negative preserved (cause still UNKNOWN). Verdict **ESTABLISHED AS
  LABELED**, no counterexample, no grade change.
- Docs commit `ddd0a450` folded the admission into `docs/task.md`,
  `docs/reproducibility.md` and `docs/changelog.md`; this fold updates the
  frontier brief and wall only. No further openscap work by frontier.
