# Frontier brief: inihlongline2shell — CVE-2025-71450 (one-byte stack under-read in `ini_parse_stream`)

**Status: STAGED 2026-11-26 W288 — rung 3 ASan confirmed; rung 4 and rung 5 NOT CLAIMED.**
No remote input, no chosen bytes, no pointer control, no command. Everything
about the vulnerability before the local section is a claim from the cited
pages; the pinned bytes and the ASan observation below are this plant's own.
The witness re-runs any published claim. Operator owns admission under
standing #6; frontier owns no further work after handoff.

## Verified ground truth (claim sources read 2026-11-26)

- **Claim source:** GitHub Advisory Database `GHSA-gh7m-xpp3-w3vq`
  (`https://github.com/advisories/GHSA-gh7m-xpp3-w3vq`, CVE-2025-71450,
  published 2026-11-02, updated 2026-11-06, NVD CNA, Moderate 4.8,
  CWE-127 buffer under-read). The advisory references upstream issue
  `benhoyt/inih#223`, PR `#206`, fix commit
  `https://github.com/benhoyt/inih/commit/8e06f6b77b5d4471bdc6d85ada81b67d37354a5c`,
  the r62 source line range, the r63 release tag and two writeups on
  hackmd.io. The GHSA's package/version fields read "Unknown"; the upstream
  tags r62 (vulnerable) and r63 (fixed) are the pinned authority here.
- **Claimed primitive:** `ini_parse_stream()` discards the rest of a line
  longer than `INI_MAX_LINE` (default 200) into a 16-byte stack buffer
  `abyss`. If a reader call returns a non-NULL empty string — for the
  shipped `fgets` reader, an embedded NUL byte is enough — the expression
  `abyss[strlen(abyss) - 1]` indexes `abyss[-1]`, a one-byte stack
  under-read. The advisory calls it "reported by memory sanitizers"; it
  does not claim a crash, disclosure or control.
- **Fix (verified raw patch, see `pins/fix-8e06f6b77b5.patch`):** 3 added
  lines, 1 removed, in `ini.c`: cache `abyss_len = strlen(abyss)` and
  guard `abyss_len > 0 && abyss[abyss_len - 1] == '\n'` before breaking the
  discard loop. No other file changed.

## Source-bound mechanism (pinned bytes)

`src/inih-r62/ini.c:165-169`, verbatim:

```
if (offset == max_line - 1 && line[offset - 1] != '\n') {
    while (reader(abyss, sizeof(abyss), stream) != NULL) {
        if (!error)
            error = lineno;
        if (abyss[strlen(abyss) - 1] == '\n')
            break;
```

`src/inih-r63/ini.c:166-170` has the `abyss_len > 0` guard from the fix
patch. `INI_MAX_LINE` is 200 and `INI_INITIAL_ALLOC` is 200 in both
`ini.h`; the harness uses the shipped `ini_parse_file()` entry point and a
trivial callback, so no parser logic is reimplemented.

## Local observation (2026-11-26 W288, GCC ASan, all loopback-free)

Pins in `pins/PIN_HASHES.txt`: `inih-r62.tar.gz`
`9c15fa751bb8…f8151`, `inih-r63.tar.gz` `5d7967de62c5…aa9963`, fix patch
`cabe4da5d97b3…cd3d6`, all `sha256sum -c` clean. `src/` holds both
extracted release trees; `harness.c` calls the shipped `ini_parse_file()`;
`run-all.sh` builds four binaries (ASan and plain for each pin) and runs
five cases.

Exact input (`evidence/attack.ini`, 200 bytes): 199 `A` bytes, then one
`0x00` byte. The first `fgets(line, 200)` consumes the 199 `A`s with no
newline (`offset == max_line - 1`, `line[198] != '\n'`), so the discard
loop runs; the next `fgets(abyss, 16)` consumes the NUL and returns
non-NULL with `strlen(abyss) == 0`.

Observed bytes (`runs/r62-attack-asan.out`, addresses/PIDs are run-specific):

```
ERROR: AddressSanitizer: stack-buffer-underflow
READ of size 1
    #0 ini_parse_stream src/inih-r62/ini.c:167
    #1 ini_parse_file src/inih-r62/ini.c:268
Address ... is located in stack of thread T0 at offset 47 in frame
    [48, 64) 'abyss' (line 123) <== Memory access at offset 47 underflows this variable
SUMMARY: AddressSanitizer: stack-buffer-underflow src/inih-r62/ini.c:167
```

Exit code 1. Controls: r63 + same attack file exits 0 with no ASan report;
r62 + a properly newline-terminated 199-byte line (`evidence/safe.ini`)
exits 0 clean; r63 + safe file clean. `run-all.sh` **PASS=8 FAIL=0** at
21:21Z. Plain (non-ASan) r62 + attack file exits **0** — the byte before
`abyss` is readable stack memory on this build, so there is **no rung-1
crash and no rung-2 observable state failure**; this negative is part of
the result.
A clean-archive replay from commit `118fb82e` at 21:24Z repeated
PASS=8 FAIL=0 with the same `ini.c:167` sink; witness replay is still owed.

## Rung-4 feasibility (honest)

- **Rung 3 ASan confirmed** on the vulnerable pinned source; fixed and
  safe-input controls are clean.
- **Rung 4 NOT CLAIMED.** The invalid index is always exactly `-1`, the
  access is a READ of one byte before a local stack array, and the callback
  never sees the value (the discard loop only sets `error = lineno`). No
  attacker-chosen offset, chosen bytes, cross-object overlap, pointer,
  marker or command was observed. The byte read cannot be steered by file
  content beyond the fixed `-1` index.
- **Rung 5 NOT CLAIMED.** No wire input, no live service, no remote path,
  no control-flow effect.

## Cheapest local experiment that could move this up a rung

1. Find a shipped inih consumer where the discarded-line error path is
   observable (different `error` propagation or a handler-visible state
   change) and show a file-only differential between r62 and r63 — that
   would establish rung 2 on a real consumer.
2. Under a debugger, identify which stack byte offset 47 holds on this
   build, then look for a caller whose local variable at that slot is
   attacker-influenced and read after the parse. If the byte is never
   consumed, the lane stays at rung 3.
3. Do not attempt r5; there is no demonstrated write primitive here.

## Duplicate screening and ranking

Three of the nine scout candidates were already owned or admitted and were
**not** staged: zlib CVE-2026-85091 (`reports/zlib2shell-status.md`,
admitted 100th), SQLite FTS5 CVE-2026-119374 (`sqlitefts5shell`, admitted
172nd) and its sibling CVE-2026-119373; llama.cpp RPC CVE-2026-137567
(`llamarpc2shell`). OpenImageIO, VVdeC, tesseract, stable-diffusion.cpp,
OpenSCAP, libvorbis, live555, curl and poppler remain unowned candidates;
rank them by tractability after this handoff. inih was chosen for this wake
because two pinned release tags, a four-line fix and a trivial local file
trigger gave an observed sanitizer result inside the wake budget.
