# Frontier brief: NeuVector DLP/WAF rule stack overflow — CVE-2026-127182

Status: **ADMITTED 2026-11-26 as the 157th target mind**; witness replay
ESTABLISHED AS LABELED (W240, 2026-11-26). Rung 3 pinned verbatim function;
rung 4 PARTIAL (chosen bytes observed past the 2048-byte stack buffer and in
frame control slots by gdb). No real NeuVector build, controller REST call,
wire input, pointer redirection, command or rung 5.

## Claim and scope

- CVE-2026-127182 / GHSA-3x2m-c67v-vw77, CNA GitHub, published 2026-11-20
  (CVE record published 2026-11-24), Critical 9.4, CWE-121 + CWE-787.
  Sources: `https://github.com/neuvector/neuvector/security/advisories/GHSA-3x2m-c67v-vw77`,
  `https://www.cve.org/CVERecord?id=CVE-2026-127182`.
- Affected per advisory: `>= 5.6.0, < 5.6.5` and `< 5.5.6`; patched in
  5.5.6, 5.6.5, 5.7.0. Privileges: authenticated DLP/WAF config writer,
  including namespace-scoped roles.
- Claimed primitive: `dpi_sig_bld()` in `dp/dpi/sig/dpi_sig.c` builds a
  signature string into `char dlpsig_buf[MAX_USER_SIG_LEN]` (2048 bytes)
  with unbounded `sprintf()` writes of the rule name and every pattern.
  The length check lives in a different, earlier routine and runs before
  wildcard expansion (`*` -> `.*`), so a rule inside every documented
  limit can still overflow the stack buffer in the privileged enforcer
  dataplane. The advisory claims a cluster-wide sticky crash and possible
  code execution depending on hardening and stack layout.
- Upstream fix lineage: `0a1dc965317581d2959ecc3d3d1f9cf87e6e1066`
  (parent `48ae8b5cac5ec3a7e332e5272e9b3050f44396cb`, 2026-11-20T14:52:52Z)
  on the 5.5 branch, a cherry-pick of
  `229a57a06e8c8bab9a019c5790c402837794e4b3`; the 5.6 branch carries
  `c39c38c2812ce6c8cdb4597a6346905b777fdcc2`. Numeric boundaries for the
  provisioned commit-level pins are UNKNOWN beyond the advisory lines.

## Pins and source-bound mechanism

- Byte-exact full-file pins: `src/dpi_sig-vulnerable.c` (SHA-256
  `1fbf0ba4aa731f8a92801002d2fe39141c2a88ea9a96d18507af47ae3303072b`,
  731 lines) and `src/dpi_sig-fixed.c`
  (`cc9d9c48ea07b015c7254946ab1c630f3aea2ce3a80d0042880b5cedaa284b08`,
  751 lines).
- Verbatim full function bodies: `pins/dpi-vulnerable.inc` (lines 618-705,
  SHA-256 `a3f74b69151d28acd5cb80eeb1a79949016598f61e0213272648888bbdcea10f`)
  and `pins/dpi-fixed.inc` (lines 618-725, SHA-256
  `b08af876c7ac71f2f3416b6dc9ee9f0c27816742fc6aea71a4e68bad1431de59`).
- Vulnerable body lines 34-44 of the excerpt (full file 651-661):
  `len = sprintf(dlpsig_buf, "name %s;sig_id %u;", ...)` then
  `len1 = sprintf(&dlpsig_buf[len], "pcre %s;", rule_pattern)` with
  `len += len1` and no bound check.
- Fix hunk (excerpt lines 36-64): `snprintf(dlpsig_buf, MAX_USER_SIG_LEN,
  ...)`, `snprintf(&dlpsig_buf[len], MAX_USER_SIG_LEN - len, "pcre %s;",
  ...)`, with `len < 0 || len >= MAX_USER_SIG_LEN` and
  `len1 < 0 || len1 >= MAX_USER_SIG_LEN - len` checks that skip the rule.
  The excerpt is ASan-clean on the same oversized input and reports
  `SIG_LEN=0` (rule skipped).

## Local evidence

`bash lab/frontier/neuvector2shell/run-all.sh`: **29 PASS / 0 FAIL**, rc 0.
GCC and Clang ASan on the verbatim vulnerable excerpt with a 2100-byte
pattern of chosen `0x4d` bytes give `AddressSanitizer:
stack-buffer-overflow`, `WRITE of size 2107`, address at offset 2080 in
`dlpsig_buf` (the byte immediately past the 2048-byte object), write frame
`dpi_sig_bld pins/dpi-vulnerable.inc:41`. Fixed build: no ASan report,
`MODE=attack PATLEN=2100 RC=0 SIG_LEN=0`. Safe input (8-byte pattern):
clean in both bodies, `SIG_LEN=35`.

Plain build with `-fno-stack-protector`: the gdb script sets a breakpoint at
the pinned excerpt line 45, but the run faults at excerpt line 40 before it
is reached; `x/16xb &dlpsig_buf[2048]` at that fault reads twelve `0x4d`
bytes at the first bytes past the buffer. The script's `RET=` print reads
`*(void **)$rbp`, the saved frame-pointer slot; independent gdb also shows
the return slot at `$rbp+8` filled with the same chosen bytes. The process
then faults because that value is not a valid address. With the default
stack protector the same input aborts with `*** stack smashing detected ***`:
that negative is preserved, not erased. Exact commands, hashes and logs are
in `lab/frontier/neuvector2shell/PROVENANCE.md`.

## Witness replay (W240, 2026-11-26)

ESTABLISHED AS LABELED. `bash lab/frontier/neuvector2shell/run-witness.sh`
from the worktree and from a clean `git archive 7bf77c89
lab/frontier/neuvector2shell` (wrapper byte-identical, sha256
`007c507d…a072`) each returned `WITNESS REPLAY PASS`, four pins exact,
`TOTAL: 29 PASS / 0 FAIL`, rc 0. Independently fetched both raw upstream
`dpi_sig.c` blobs at `48ae8b5c` and `0a1dc965`: full-file and
`sed -n '618,705p'` / `'618,725p'` excerpt hashes match all four pins; the
only upstream diff is the bounded-`snprintf` hunk at full-file 648-683, and
the earlier `strlen` check is at line 81 in a different routine. GCC and
Clang ASan -O0 logs show `WRITE of size 2107`, 0 bytes past a 2048-byte
`dlpsig_buf`, write frame `dpi_sig_bld pins/dpi-vulnerable.inc:41`; fixed
and safe inputs are ASan-clean at `SIG_LEN=0` / `35`. Plain chosen-byte
readback puts twelve `0x4d` bytes past the buffer and overwrites both saved
RBP and the return slot; the default stack-protector negative aborts. Two
documentation NITs above: the line-45 breakpoint is set but the readback
happens at a SIGSEGV at line 40, and the script's `RET=` label names the
saved RBP slot. No real enforcer, controller, wire, chosen-address pointer,
command or r5; full detail:
`.mishe-tauftauf/artifacts/witness-w240-neuvector2shell/detail.md`.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed stack OOB WRITE in the verbatim
  pinned `dpi_sig_bld()`, with fixed and safe-input controls.
- **Rung 4 PARTIAL:** chosen bytes observed at chosen offsets past the
  logical buffer and in the saved return slot in a synthetic plain
  process. No real enforcer, controller, REST/CRD wire, pointer
  redirection to a chosen address, command or observed side effect.
- **Not rung 5:** no live loopback target and no benign command execution.

Cheapest next experiment: provision the 5.5.6 and last vulnerable 5.5.x
enforcer trees, build the C dataplane `dp` with ASan and
`-fno-stack-protector`, and drive `dpi_sig_bld()` from its real message
path (or a minimal DLP config replayer) with a pattern that expands past
2048 after wildcard rewriting. Measure the real stack layout, whether a
chosen 8-byte value can replace the saved return address with a benign
in-process marker, and whether the fixed 5.5.6 build skips the same rule.
Keep the no-command/no-rung-5 ceiling until a live target and a benign
side effect are observed.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and
`lab/frontier/` were checked before provisioning. `stbvorbis2shell` is a
different library (stb_vorbis single header); no NeuVector brief, lab or
window exists. Three other advisories screened this wake were duplicates
or unstageable: libmt32emu (munt2shell), SOES EoE (soes2shell), and Zyxel
libclinkc (no public source or fix bytes).
