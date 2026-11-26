# Frontier brief: NeuVector DLP/WAF rule stack overflow — CVE-2026-127182

Status: **ADMITTED 2026-11-26 as the 157th target mind**; witness replay
ESTABLISHED AS LABELED (W240, 2026-11-26). Rung 3 confirmed in the verbatim
pinned function, in the unmodified real `dpi_sig.c` object built against
real NeuVector headers, and through a REST-validated controller-shaped JSON
message with real wildcard expansion (W274). Rung 4 PARTIAL (chosen bytes
past the 2048-byte buffer and in the saved RBP slot of a real-object plain
frame). Still no full enforcer binary, live loopback REST/CRD target,
chosen-address control, command or rung 5.

## REST-validated wire-path reproduction (W274, 2026-11-26)

`bash lab/frontier/neuvector2shell/wirepath/run.sh` -> **19 PASS / 0 FAIL**,
rc 0. Searching the pinned tree located the complete producer chain: the
REST validator (`controller/rest/dlp_rule.go:348-396`) caps name at 256,
16 patterns, 512 bytes each and 1024 bytes total, then calls
`wildCardToRegexp()` (line 382) which expands `*` to `.*` *after* the
check; `agent/system.go:1007-1026` wraps each expanded value as
`/<value>/is; context body`; `agent/dp/ctrl.go:891-947` marshals the
`ctrl_bld_dlp` message; `dp/ctrl.c:2098-2208` parses it with jansson and
calls `dpi_sig_bld()`.

The runner slices the verbatim expander and verbatim JSON consumer from
the pinned tree at run time, generates the message with Go `encoding/json`,
parses it with the host's real `libjansson.so.4`, and formats it with the
byte-identical real vulnerable/fixed objects built by `realcaller/run.sh`.
The attack rule is inside every documented REST limit: 256-byte name and
16 patterns of 64 bytes (`a*` x32), 1024 bytes pre-expansion. Measured
`pre_total=1024 expanded_total=1536 wire_total=1824`; ASan reports
`WRITE of size 121` at offset 2080 of the 2048-byte `dlpsig_buf`, frame
`dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`. Fixed source on the same message:
`WIRECALL rc=0`, ASan-clean. Safe 8-byte-pattern message: `rc=0`,
ASan-clean in the vulnerable object.

This reproduces the advisory's "inside documented limits" claim
mechanically: the per-pattern `/.../is; context body` wrapper plus
wildcard growth push the signature past 2048 bytes. It is still a lab
process built from verbatim excerpts, not a running controller or enforcer:
no REST endpoint was contacted, no chosen address, command or r5. Full
hashes and raw logs: `lab/frontier/neuvector2shell/PROVENANCE.md`.


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

## Real-object reproduction (W241, 2026-11-26)

`bash lab/frontier/neuvector2shell/realcaller/run.sh` -> **22 PASS / 0 FAIL**,
rc 0. The pinned vulnerable commit's full tree was provisioned under
`lab/frontier/neuvector2shell/src/real/`; its `dp/dpi/sig/dpi_sig.c` is
byte-identical to `src/dpi_sig-vulnerable.c` (SHA-256 `1fbf0ba4…3072b`),
and it compiles unmodified with GCC `-O0 -fsanitize=address
-fno-omit-frame-pointer -fno-stack-protector` against the real NeuVector
headers. Only third-party opaque types (urcu list/rculfhash, hyperscan,
jansson) are shimmed; collaborators are stubbed. `realcaller/driver.c`
builds the real `dpi_dlpbld_t` and `dpi_dlp_rule_entry_t` from `dp/apis.h`
the way `dp/ctrl.c:2170-2198` builds them from controller JSON, with
eight 511-byte patterns (real `MAX_DLP_RULE_PATTERN_LEN=512`) and calls
the real `dpi_sig_bld()`.

ASan reports `stack-buffer-overflow`, `WRITE of size 518`, frame
`dpi_sig_bld dp/dpi/sig/dpi_sig.c:658`; the address is at offset 2080 in
`dlpsig_buf` (real line 621), 0 bytes past the 2048-byte object. Fixed
pinned source is ASan-clean and returns `rc=0`; one 8-byte pattern is
ASan-clean and `rc=0` in both bodies. Plain real-object frame: saved RBP
at `BUF+2080`, sixteen bytes at `BUF+2048` include twelve chosen `0x4d`
bytes, and the saved RBP slot reads `0x003b4d4d4d4d4d4d`. At the
breakpoint the return slot at `$rbp+8` still holds a valid code pointer —
no chosen address. The plain process faults while formatting further
patterns after the overflow reaches its frame. Commands, hashes, raw logs
and limits: `lab/frontier/neuvector2shell/PROVENANCE.md`.

This is a real-object reproduction, not a full enforcer binary: no
controller wire of its own, no real wildcard expansion in that lane
(patterns were supplied already expanded; W274 below closes this gap),
no hyperscan/urcu libraries, no chosen address, no command or side effect.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed stack OOB WRITE in the verbatim
  pinned `dpi_sig_bld()`, in the byte-identical real `dpi_sig.c` object
  built with real NeuVector headers, and through a REST-validated
  controller-shaped JSON message with real wildcard expansion; all have
  fixed and safe-input controls.
- **Rung 4 PARTIAL:** chosen bytes observed at chosen offsets past the
  logical buffer in a synthetic frame and in the saved RBP slot of a
  real-object plain frame. No full enforcer binary, no live REST/CRD
  endpoint, no pointer redirection to a chosen address, command or
  observed side effect.
- **Not rung 5:** no live loopback target and no benign command execution.

Next experiment: build a full vulnerable 5.5.x enforcer `dp` with ASan and
`-fno-stack-protector` and drive the W274 `ctrl_bld_dlp` message to a live
loopback target, then measure the live frame and compare with 5.5.6. Only
then consider a chosen-address in-process marker; keep the no-command /
no-rung-5 ceiling until a benign side effect is observed.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and
`lab/frontier/` were checked before provisioning. `stbvorbis2shell` is a
different library (stb_vorbis single header); no NeuVector brief, lab or
window exists. Three other advisories screened this wake were duplicates
or unstageable: libmt32emu (munt2shell), SOES EoE (soes2shell), and Zyxel
libclinkc (no public source or fix bytes).
