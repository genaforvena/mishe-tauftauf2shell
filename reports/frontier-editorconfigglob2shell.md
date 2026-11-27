# Frontier brief: editorconfigglob2shell — `ec_glob()` pattern stack overflow

**Status: STAGED (frontier W345), independent witness replay and operator
admission owed.** The target mind's charter and seed wall exist; live
dedicated inner-socket window 222 (`%450`/`%451`, `dead=0`), registry
223/223 unique. Lab: `lab/frontier/editorconfigglob2shell/`; pins and URLs
in `PROVENANCE.md`. Input is a local `.editorconfig` file plus a directory
structure with many special characters; no network I/O, listener, marker or
command was run.

## Verified ground truth

- CVE-2026-40489 / GHSA-97xg-vrcq-254h. OSV record
  (`https://api.osv.dev/v1/vulns/CVE-2026-40489`, SHA-256 `7a0fb823…`)
  says editorconfig-core-c `<=0.12.10` has a stack overflow in `ec_glob()`:
  the earlier `pcre_str` fix for CVE-2023-0341 left the adjacent
  `l_pattern[8194]` unguarded. `0.12.11` contains the fix. CWE-121/787,
  CVSS v4 `AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`. Advisory wording is
  "crash any application using libeditorconfig"; no RCE claim.
- Exact upstream fix commit
  `5159be88ad50641d9843289adda791ba300421ff`, single parent
  `b4724e475571…`; patch SHA-256 `3055f837…` read directly from
  `https://github.com/editorconfig/editorconfig-core-c/commit/5159be88…patch`.
  The hunk at `src/lib/ec_glob.c:96` adds `pattern_len = strlen(pattern)`,
  rejects `pattern_len >= sizeof(l_pattern)` with `-1`, and replaces
  `strcpy(l_pattern, pattern)` with bounded `memcpy`.
- Vulnerable source is the pinned parent tarball (SHA-256 `63096095…`),
  not a reconstructed snippet: `src/lib/ec_glob.c:95` declares
  `l_pattern[2 * PATTERN_MAX]` (`PATTERN_MAX 4097`), `:100` is the unchecked
  `strcpy`. The public API caller is real: `editorconfig_parse()` at
  `src/lib/editorconfig.c:537` → `ini_parse()` → `ini_handler()` at `:268`
  calls `ec_glob(pattern, hfparam->full_filename)`.
- Duplicate check: no EditorConfig, `ec_glob` or `editorconfigglob` slug/file
  existed in `reports/`, `lab/frontier/` or the frontier wall's admitted,
  screened-out or backups lists before this wake. CVE-2023-0341 was a
  different, already-fixed buffer in the same function; no staged lane.
- The 4096-character `MAX_SECTION_NAME` cap (`src/lib/ini.h:80`) alone cannot
  overflow an 8194-byte buffer. The real-caller case uses the directory part:
  `editorconfig.c:250-258` escapes every `?[]\\*-{},` character with a
  backslash, so a ~3.1 KB physical path made of 20 components of 150 `*`
  characters becomes a >10 KB pattern. This is the advisory's "specially
  crafted directory structure", source-bound and reproduced locally.

## Observed evidence

GCC 13.3.0, glibc 2.39, x86-64; CMake static library built from the pinned
archive with `-g -O0`, ASan/plain, stack protector off. `sh run-all.sh`
verifies 6/6 SHA-256 pins, rebuilds four consumers offline, and reports
`RUN_ALL_OK 27 PASS / 0 FAIL` with summary SHA-256
`2de80df12d64a14d968b7183f7daf059eec107b1468b0c632b7858e26f5b074c`.
A clean `git archive --format=tar 5085acab lab/frontier/editorconfigglob2shell`
replay into `/tmp/w345-editorconfig-clean` rebuilt all four consumers from
the pinned archive with no network I/O, verified 6/6 pins and returned 27/0
with a byte-identical summary; plain-tar SHA-256
`f9076cba079ffbbe9c9065cbebddf207ec0d4d596ef1891c4b45a8e81b07ce26`.
Binary hashes are path-dependent (Debug info embeds the checkout path) and
are not pinned. Author replay is not witness acceptance.

- Direct real-library call: 8192- and 8193-byte patterns are clean; 8194
  bytes gives ASan `WRITE of size 8195`, 8200 chosen `0x43` bytes gives
  `WRITE of size 8201`, both at pinned `ec_glob.c:100` with the destination
  named `l_pattern`.
- Real caller: `editorconfig_parse()` on the crafted tree reports ASan
  `stack-buffer-overflow` / `WRITE of size 10212` at `ec_glob.c:100` through
  `ini_handler` at `editorconfig.c:268` → `editorconfig_parse` at `:537`.
  The exact size tracks the absolute path length (the replay checks the
  `WRITE of size 102` prefix, not a path-dependent constant). A 64-byte
  section tree and both fixed builds are clean under the same conditions.
- Plain vulnerable build without ASan/canary survives the file case (rc 0):
  a preserved negative against any default-build crash claim. A read-only
  GDB run on the direct 8200-byte case, stopped at `ec_glob.c:101`, shows
  twelve chosen `0x43` bytes at `l_pattern+8188..+8199` (six past the object)
  and a live `saved rip` in the same frame; no chosen pointer was
  dereferenced and no control-flow word was changed.
- Fixed build: the same 8200-byte direct pattern returns `-1` with no ASan
  report; the crafted file tree parses cleanly.

## Grade and cheapest next experiment

R1 ✓ deterministic trigger, R2 ✓ observed state failure, R3 ✓ ASan-confirmed
stack corruption. **R4 DEMONSTRATED at the lab/file-API scope**: chosen bytes
at chosen stack offsets through the public `editorconfig_parse()` caller, in
an in-process `0x43` fill. No saved RIP, function pointer, marker, command or
external side effect. **R5 NOT CLAIMED**: local file plus local directory
path; no socket, wire request, live editor process or command execution.

Next: check whether a server-side editor plugin or a language server passes
untrusted section globs to `editorconfig_parse()` with an attacker-chosen
path, and whether optimized/FORTIFY builds turn the write into a usable
control-flow primitive. Without an observed command side effect in a live
target, this stays rung 4.

## Ranking context and backups

Ranked tractable because it is a small C library, an exact parent/fix pair,
a deterministic file-only trigger and a real public API caller; its local-file
vector caps the rung-5 ceiling. New candidates from this wake's two scouts,
not yet briefed: AWS SDK for C++ Base64 `Decode()` heap OOB write
CVE-2026-19642 / GHSA-wxx3-prfc-69xx, parent `2857dbc7` → fix `8eeac049`
(one .cpp, small harness); UxPlay RTSP `raop_handler_pairsetup_pin()`
64-byte stack write, fix `746ec0e` (pre-auth wire), AWS pgactive
`sscanf` into `NameData`, fix `7eb5d25` (already-related target family),
OpenSSL CMS `cms_kek_cipher`/`cms_kemri` under-allocation, fix `2a3dac8`
(heavier build). Prior backups remain: Domoticz CVE-2026-71265 `26ccc932`
(wire 966-byte stack write, heavy build), PicoTCP `d25c4c2`/`540507b`,
FNET `816d306`, lwIP SMTP `89b823c`, wolfIP `8bfdb80`, libsolv `c5b5db5`,
OIIO `cb3ea9f`/`b0dc568`/`38d5cda`/`4fe58e2`, rpcinfo `0a816602`,
entr `2467fe0`, glibc scanf `8398987`, Vim `4e5b9e31`.
