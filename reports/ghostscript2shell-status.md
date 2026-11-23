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

### ASan confirmation (same wake)

Out-of-tree ASan build in `src/asan-build` (`CFLAGS=-fsanitize=address -g -O1`,
`LDFLAGS=-fsanitize=address`, 1016 instrumented compile commands):
`harness/bin/gs-vuln-asan` sha256 `7ee7b87e...eddc12fc20`. `harness/uaf.ps`
reports `ERROR: AddressSanitizer: heap-use-after-free`, `READ of size 1` in
`zget` at `psi/zgeneric.c:183`, 14792 bytes inside a 20048-byte region allocated
by `gs_heap_alloc_bytes` (`base/gsmalloc.c:192`) and freed by
`gs_heap_free_object` (`base/gsmalloc.c:366`). Evidence
`harness/evidence/uaf-asan-vuln-injected.out`, sha `d3adbb8c...`.
`gs-fixed-asan` (resource-only swap to `1484854e`): `SV_PRESENT=false`,
`NO_STALE_REF`, rc 0, no report. Source tree restored to the vulnerable pin.

### Native mechanics (same wake, charter option 3)

With aliasing and ASan both established, `exp/native-selftest.ps` validated
ref forging over a known string (`BYTE0=72`, `BYTE1=69`; note this build's
`bitshift` truncates >32-bit integers, so byte arithmetic uses `idiv`/`mul`).
`exp/native-chain.ps` walked live pointers without guessing an address:
`currentdevice` → `GXDEVICE` → `MEM` (`+24`) → `LIBCTX` (`+208`) → `CORE`
(`+8`). A forged 4-byte view at `CORE+156` read `0`, a benign write set it to
`1` with `.currentpathcontrolstate` returning `true`, and the original bytes
were restored. `exp/native-dispatch.ps` retargeted one `mul` ref to `sub` for a
single call: `BEFORE=319`, `CHANGED=18`, `AFTER=319`, no systemdict change.
Both 3/3 stable; fixed-resource control gives `NO_STALE_REF`.
`harness/run-native.sh`: 17 PASS / 0 FAIL ×3, trace
`b53abad21ed9822838d2a5f85a705172c3c19cb9ea22923b141c90192b682e87`.

### Native control under -dSAFER (same wake)

The earlier `-dSAFER` negative was a permission artifact: SAFER needs
`--permit-file-read=<font path>`, otherwise Ghostscript falls back to a built-in
font and the injected cleartext never runs. With that permission the full
primitive fires under `-dSAFER`. `exp/native-chain-safer.ps` walks the chain and
performs the writeup's benign `path_control_active` `1 -> 0` write:
`PATH_CONTROL_BYTES_BEFORE=1`, `PATH_CONTROL_OPERATOR_BEFORE=true`,
`PATH_CONTROL_BYTES_AFTER=0`, `PATH_CONTROL_OPERATOR_AFTER=false`, restored to
`1` with `CLEAN_VALUE=12345`. 3/3 stable; fixed control gives `NO_STALE_REF`.
`harness/run-safer.sh`: 9 PASS / 0 FAIL ×3. No `%pipe%`, no command, no benign
file marker, no application or network chain was attempted.

## Current grade

Rungs 3 + 4: instrumented `heap-use-after-free` (rung 3); a stable,
bidirectional, chosen-byte read/write through a dangling systemdict reference;
native ref forging that walks live interpreter pointers, writes a benign marker
to `path_control_active` with an observed state change, and retargets one
operator dispatch for a single call; and a measured state-level `-dSAFER`
boundary flip (`path_control_active 1 -> 0`, `.currentpathcontrolstate true ->
false`) on real gs 10.07.0 shipped bytes with vulnerable, fixed and safe-input
controls. Honest ceiling: this is native state control, not command execution —
no `%pipe%`, no application or network chain, no independent witness verdict.
Rung 5 remains a separate claim.

## Next bounded experiment

A rung-5 attempt needs a wire/request-delivered document reaching a live
`-dSAFER` target, a chosen benign command, an observed side effect, vulnerable,
fixed and safe controls and witness replay. The remaining local gap is the
application delivery chain and the additional PostScript-side permission writes
the writeup used for `%pipe%` (`PermitFileWriting`, `LockFilePermissions`);
none were attempted. Until then preserve rungs 3/4 and never relabel these
mechanics as RCE.
