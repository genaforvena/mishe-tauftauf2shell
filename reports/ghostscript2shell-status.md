# ghostscript2shell — status

Admitted 2026-11-23 ~03:4xZ under standing approval #6 as the 98th engine
route. Frontier staged this lane in W134 (brief
`reports/frontier-ghostscript.md`, site charter and seed wall, pinned
`gs_fonts.ps` blobs and fix patch, two real gs 10.07.0 binaries, injected and
safe font fixtures, and raw evidence in
`lab/frontier/ghostscript2shell/PROVENANCE.md`). Its two-pane inner tmux window
already existed at index 102 (0..101 occupied); admission created no second
window and changed no registry entry. The hy4-flash `max_parallel: 3` route was
added, the path, debounce and `@ghostscript2shell` slice drop-in were minted
with the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`), followed
by `systemctl --user daemon-reload`; the path unit is enabled and active. Both
`m2shell-wake@ghostscript2shell.service` and
`m2shell-wake-ghostscript2shell.path` were added to the site's owner resolver
map (now 197 entries). Admission changes no grade.

- Claim: CVE-2026-125396 / "Upload2Shell", VulnCheck CNA 2026-11-09, CWE-648,
  CVSS4 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H` (research page quotes 8.5),
  affected `< 10.08.0`, fixed in 10.08.0 by upstream commit `1484854e` (bug
  709684). **AV:L**, not AV:N: the writeup's CUPS / Roundcube / WordPress
  delivery paths are separate, untested claims and are not merged into the
  interpreter finding.
- Primitive: `Resource/Init/gs_fonts.ps:1026` defines `.putgstringcopy`, called
  only from `.loadfontloop` at :1138/:1150 and hidden at :1372. A real
  NimbusSans Type 1 PFA replaces the loader filename string at operand depth 2
  with a local array (`DEPTH2_BEFORE=stringtype`, `DEPTH2_AFTER=arraytype`), so
  the bound helper raises `typecheck` inside `copy`. The writeup's five-pop
  `errordict /typecheck` handler resumes at the bound `.forceput` and writes a
  benign integer into the readonly systemdict. The fixed blob adds a 10-line
  operand-type guard (`Check operand types`) before the privileged path.
- Evidence: two real gs 10.07.0 binaries built from the pinned codeload tarball
  differ only in the shipped `gs_fonts.ps` resource. Vulnerable + injected
  font: `TRAP_FIRED=true`, `GS_FORCEPUT_RESULT=true`. Fixed `1484854e` + same
  font: `TRAP_FIRED=true`, `GS_FORCEPUT_RESULT=false`. Vulnerable + unmodified
  font: both false. Harness `lab/frontier/ghostscript2shell/harness/run.sh`;
  operator replay from a fresh `/tmp` copy: rc 0, `PASS=22 FAIL=0`,
  `TRACE_SHA256=a4569485cb1fb98ab74b7d186e1566f18ede6bdb263cdb4e5e34f631e5683c29`,
  exactly frontier's value. The pinned tarball cannot be overridden with `-I`
  because the resource is in ROMFS; the fixed control is a rebuild, and the
  tree was restored to the vulnerable blob afterward.

## Grade at admission (03:4xZ)

Rung 1 trigger and rung 2 observed interpreter state failure on shipped
interpreter bytes only — a deterministic PostScript-level write of a benign
marker into the readonly systemdict, opposite-signed on vulnerable vs fixed
builds. No native memory corruption, no ASan report, no allocation aliasing
after `restore` (`STALE_KEY=true`, `UAF_READ=null`), no pointer-chain walk, no
forged string ref, no `path_control_active` overwrite, no `-dSAFER` bypass, no
`%pipe%` command, no application or network chain and no rung 5. The writeup's
case-study PoCs are unpublished; its native write-what-where and RCE remain
claims to reproduce. No independent witness verdict exists yet.

## First mind wake — 2026-11-23T03:58Z onward

Baseline `harness/run.sh` replayed unchanged first: `PASS=22 FAIL=0`,
`TRACE_SHA256=a4569485...3c29`. Fetched the writeup
`https://pwn.ai/upload2shell/research.html` and read `psi/zgeneric.c:270-312`,
which confirms `zforceput` temporarily marks systemdict local around
`idict_put`, so a local object genuinely enters a dict surviving `restore`.

The handoff's `UAF_READ=null` was isolated: `exp/uaf-diag.ps` shows the
force-put 2048-byte string is still `stringtype`, length 2048, byte0=65 after
`restore` (`AFTER_RESTORE_KNOWN=true`). The single fresh `8 array` simply did
not reuse that freed block. The writeup scans MANY fresh allocations instead.

`harness/uaf.ps` (canonical) + `harness/run-uaf.sh`: vulnerable build + injected
font stores the local 2048-byte string in systemdict, restores, allocates 96
arrays of 128 integers holding `0x12345678`, finds the byte run
`78 56 34 12` in the stale string, flips one low byte to `0x79`, and observes
exactly one live array element change. Reverse direction also holds: writing
`0x1234567a` to that live element reads back as `122,86,52,18` through the
stale string; cleanup restores byte `120`. Deterministic 5/5 direct runs and
3 harness runs: array 8 / index 118, first pattern offset 8, 10 occurrences.
`./run-uaf.sh` → `PASS=21 FAIL=0` ×3, trace
`bd4e4b4c7404a9b22dbda6e3ee077e58736d96a868af6f2aad8cc7a00f85a7cb`.
Controls: `gs-fixed` + injected and `gs-vuln` + safe font both give
`SV_PRESENT=false`, `NO_STALE_REF`. Full record in `PROVENANCE.md`.

## Current grade

Rung 4 (demonstrated security impact, PostScript level): a dangling reference
in the surviving global systemdict gives a stable, bidirectional, chosen-byte
read/write into a live interpreter object after `restore`, with vulnerable,
fixed and safe-input controls, on real gs 10.07.0 shipped bytes. Honest ceiling:
no native address, no ASan report, no forged ref, no pointer-chain walk, no
`path_control_active` write, no `-dSAFER` bypass, no command, no application or
network chain, no witness verdict. Rung 5 remains a separate claim.

## Next bounded experiment

Charter option 2: build from the pinned tree with ASan
(`CFLAGS='-fsanitize=address -g'`), swap in the vulnerable `gs_fonts.ps`, run
`harness/uaf.ps`, and check whether the PostScript allocator's reuse yields an
instrumented heap-use-after-free. If Ghostscript suballocates and ASan is
inconclusive, preserve that negative; do not start the native ref-forging
chain without it. Rung 5 requirements unchanged: a live wire-only trigger, a
chosen benign command, an observed side effect, vulnerable/fixed/safe controls
and witness replay.
