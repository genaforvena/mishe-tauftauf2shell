# Frontier brief: libfontenc setCode() row-size overflow — CVE-2026-109908 (libfontenc2shell)

**STAGED 2026-11-23 W154; EXTENDED W155; CLEAN-ARCHIVE REPLAY W156; WITNESS
VERDICT AND PLAIN CRASH FOLDED W172.** The W154 direct-call harness evidence
stands unchanged.
W155 built the real library at the pinned commits and release tags, reached the
parser through the exported `FontEncFind()` API and through a **live loopback
Xvfb `OpenFont` path**, and settled the version discrepancy against upstream
tags. W156 added a from-scratch rebuild script and replayed it from a clean
`git archive`. The independent witness replay (tape #2845 + #2862, verdict
#2867) ESTABLISHED rungs 1-4 at the direct-call CODE/HARNESS scope and rung 3
on the live ASan `OpenFont` path, with no counterexample and no grade change;
rung 5 remains UNKNOWN. The `SIZE 256 258` plain-build negative stands; W172
found a separate plain-build crash at `SIZE 256 1024`.
Byte-exact pins and hashes: `lab/frontier/libfontenc2shell/PINS.sha256`.
Full commands, controls and negative results:
`lab/frontier/libfontenc2shell/PROVENANCE.md`; compact W155 matrix:
`lab/frontier/libfontenc2shell/realpath/evidence/summary.txt`.

## 1. Verified ground truth

- Advisory: GHSA-98gj-rwr5-8j74 / CVE-2026-109908, published 2026-11-18, High
  7.8, CVSS:3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-122 —
  https://github.com/advisories/GHSA-98gj-rwr5-8j74. Claim: a heap buffer
  overflow while reading X.Org libfontenc encoding (`.enc`) files lets a local
  attacker who can inject enc files into the X server crash it or escalate
  privileges. Discovery credited to Adam Bedard (TrendAI ZDI), ZDI-CAN-31888.
  A remote path is **not** claimed.
- Affected text is preserved verbatim: advisory "before 1.11.0", upstream fix
  tag `libfontenc-1.1.10`. W155 evidence resolves which upstream releases
  carry the fix, not the advisory's typo: `git tag --contains 5920c6e` lists
  only `libfontenc-1.1.10`; `libfontenc-1.1.9` predates the fix. Rebuilt
  1.1.9 faults on the crafted input, 1.1.10 does not. Both version strings
  remain in the record; nothing is silently reconciled.
- Upstream fix commit
  `5920c6ee144fffff84b62f5b479171f734f15316` (2026-09-16) adds
  `if (index > 0xFFFF) return 0;` to `setCode()` and corrects the column check
  from global `value1` to the `from` parameter. Vulnerable parent:
  `7418fa7a77d1faf795ae40ea92f9ec2828e2a0b9`. Source:
  https://gitlab.freedesktop.org/xorg/lib/libfontenc.git. Upstream regression
  test `be6a0eb` includes the `SIZE 256 258` / `0xff00` case.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; the pinned bytes live in
`src/encparse.c.{vuln,fixed}` and are included verbatim under `#line` control
in the W154 generated drivers. W155 builds the same upstream commits as shared
libraries; its ASan and gdb reports cite the real source lines directly.

`setCode(from, to, row_size, ...)` computes the destination index at
`encparse.c.vuln:460` as `(from >> 8) * row_size + (from & 0xFF)` when
`row_size != 0`. `from` is bounded by `0xFFFF`, but `row_size` comes straight
from the attacker-controlled `SIZE` line and is not bounded by the 256 columns
of the allocation. The allocation is capped at `0x10000` `unsigned short`
entries (`:469`, `:472`), yet the column check at `:458` tests the stale global
`value1` instead of `from`. With `SIZE 256 258` and mapping `0xff00 0x5a5a`,
`index = 255 * 258 = 65790`, and `(*enc)[index] = to` at `:495` writes two
chosen bytes 508 bytes past the 131072-byte buffer. The same stale-variable
bug skips valid `CODE_RANGE_LINE` and `CODE_UNDEFINE_LINE` mappings because the
loop advances `from` while `value1` stays at the range start.

Fixed `encparse.c.fixed:458-462` checks `(from & 0xFF) >= row_size` per call
and rejects `index > 0xFFFF` before allocating or storing.

## 3. Experiments

### 3.1 W154 direct-call harness (unchanged)

Two generated C drivers include the complete pinned `encparse.c`, with real
zlib `gzFile` parsing of a temporary `.enc` and harness-only backend stubs.
Commands: `cd lab/frontier/libfontenc2shell/harness && ./run.sh && ./check.sh`.
Results: `PASS=50 FAIL=0`, normalized trace
`bfdd7987e86276e59b580e2f2a960c1a760f389625ced38a065bfaba4de37fa2`, gcc and
clang ASan `WRITE of size 2` at pinned `:495`, 508 bytes past a 131072-byte
region, and debugger readback of chosen `0x5a5a` at the destination.

### 3.2 W155 real library, public API

`realpath/run.sh` builds `load_via_public_api.c` against plain and ASan shared
libraries at `7418fa7`, `5920c6e`, 1.1.9 and 1.1.10. It calls the exported
`FontEncFind(charset, fontfile)`, the entry point libXfont2 uses, with a real
`encodings.dir` index and crafted/safe `.enc` files under
`realpath/tmp/fonts/`. The call chain in the ASan report is
`FontEncFind:738 -> FontEncLoad:780 -> FontEncReallyLoad:962 ->
FontEncReallyReallyLoad:941 -> parseEncodingFile:672 -> setCode:495`.
Vulnerable parent and 1.1.9 fault on `SIZE 256 258`; `5920c6e` and 1.1.10 do
not; safe input faults nothing in any build. A NULL font filename makes this
version's directory branch fopen the directory and return NULL, so the replay
passes a font filename exactly as the X path does.

### 3.3 W155 live X server

`realpath/xlive/run-live.sh` starts a loopback-only Xvfb with an ASan-instrumented
pinned library preloaded ahead of the ASan runtime, and a client opens a Type1
font whose XLFD registry is `crafted-1`. `xlive/fontenc-trace.c` logged the
live server calling `FontEncFromXLFD`, `FontEncFind` and `FontEncReallyLoad`
with that charset and the font file path
(`realpath/evidence/live/tracer-xvfb.out`). Matrix:

| library | input | client | ASan log |
| --- | --- | --- | --- |
| `7418fa7` | safe (`SIZE 256 256`) | rc 0 | 0 |
| `5920c6e` | safe | rc 0 | 0 |
| `7418fa7` | crafted (`SIZE 256 258`) | rc 1, X connection broken | 1 |
| `5920c6e` | crafted | rc 0 | 0 |
| 1.1.9 | crafted | rc 1 | 1 |
| 1.1.10 | crafted | rc 0 | 0 |

The vulnerable report (`realpath/evidence/live/asan-vuln-crafted.out`) is a
`heap-buffer-overflow`, `WRITE of size 2` at `encparse.c:495`, 508 bytes after
a 131072-byte region, with frames through `/usr/bin/Xvfb` `OpenFont` and
`libXfont2.so.2`. The live setup controls a font path and a Type1 font's
`CHARSET_REGISTRY` property, modelling the advisory's local attacker, not a
remote client.

### 3.4 W172 plain-build Xvfb crash

A single mapping takes `first == last == index`, so no identity ramp precedes
the store and a larger attacker-chosen `SIZE` row count moves the chosen
`0x5a5a` store far past the 65536-entry allocation. With the uninstrumented
pinned vulnerable library preloaded into a live loopback Xvfb, `SIZE 256 1024`
(index 261120) faults in `setCode` and the server aborts (`client_rc=1`,
`xdpyinfo_rc=1`, 3/3 repeats). `SIZE 256 258` still survives plain (508 bytes
landing in glibc usable slack), as do fixed `5920c6e` and 1.1.10 at row 1024;
1.1.9 crashes like the vulnerable parent. Safe input is clean throughout.
`realpath/xlive/run-plain-crash.sh` regenerates the matrix;
`realpath/evidence/plain-crash.txt`, `plain-crash-backtrace.txt` and
`row-sweep.txt` hold the results. This is an availability impact in an
uninstrumented live server, not pointer or control-flow control; rows 512 and
16384 fault in the public-API harness but not in Xvfb, so address placement
remains process-specific.

For the ASan-silent rows 512 and 16384, a gdb breakpoint at `:495` and
`__asan_describe_address(*enc + index)` report "wild memory access
suspected" — no live object, pointer or control-flow target
(`realpath/evidence/gdb-asan-destination.txt`). Those cases stay UNKNOWN,
not rung 4 object control and not passes.

### 3.5 W180 runtime font-path injection (X protocol)

The earlier live matrix configured the crafted font directory with `-fp` at
server startup. `realpath/xlive/run-xset-fp.sh` instead starts a loopback Xvfb
with an unrelated font path, injects a writable temp font directory into the
running server with `xset +fp` and `xset fp rehash`, and only then writes the
malicious `crafted-evil.enc` (`SIZE 256 258` / `0xff00 0x5a5a`). Opening the
corresponding Type1 font from another X client produces the same ASan
`WRITE of size 2` at `encparse.c:495`, 508 bytes past the 131072-byte region,
through `FontEncFind` and `OpenFont`. The vulnerable build's no-xset and safe
controls and both fixed controls produce no ASan report. Timeline, matrix,
client outputs, xset outputs and raw ASan log are in
`realpath/evidence/xset-fp/`; exact commands and scope limits are in
`PROVENANCE.md` W180. This establishes runtime injection into an already
running X server from a writable directory without a server restart; it does
not establish that an unprivileged OS user can access a production X display
or that the production server is privileged — both stay UNKNOWN.

### 3.6 W181 two-mapping identity-ramp write

A single mapping skips the identity ramp at `:488-493` (`§3.4`); a second
mapping with a larger index does not. With `SIZE 256 1024` and mappings
`0x00ff 0x0001` (index 255) then `0xffff 0x1234` (index 261375), the vulnerable
real library writes 195840 contiguous 16-bit index-derived values past the
65536-entry buffer at `encparse.c:492`. The public-API matrix gives vulnerable
plain `rc=139` (SIGSEGV) and vulnerable ASan `WRITE of size 2` at `:492`, 0
bytes after the 131072-byte region; the in-bounds two-mapping control, fixed
`5920c6e` and 1.1.10 all return 0 with no ASan report. Under brk the plain
build faults at `:492` with `rax` at the exact `[heap]` mapping end after 67176
OOB entries. Evidence and reproduction: `realpath/evidence/ramp/README.txt`,
`PROVENANCE.md` W181. The ramp values are indices, not chosen data, and no
live object, saved pointer or control-flow target was observed: this widens
the OOB write but does not change the grade.


### 3.7 W183 chosen-byte overwrite of a live object pointer (public API)

W181's ramp wrote index-derived values into wilderness. A seven-mapping
`.enc` gives a chosen 2-byte store at a chosen OOB offset *after* the parser
has allocated its per-mapping `FontEncSimpleMapRec` objects
(`encparse.c:641-658`). With `SIZE 256 258`, `0xff00` reaches index 65790
(+508 bytes) and `0xfe10`..`0xfe13` reach indices 65548..65551
(+24..+30 bytes). Each mapping's first CODE resets `first/last`, so there is
no identity ramp: one chosen store per mapping. The four +24..+30 stores
replace all four 16-bit halves of mapping2's live `sm->map` data pointer.

With `MALLOC_MMAP_THRESHOLD_=262144` and ASLR disabled (`setarch -R`), the
real vulnerable library's mapping2 `map` changes from its in-bounds target
(holding chosen `0x1111`) to `0x55555558257a`, +26 bytes past the buffer,
where another of the chosen stores placed `0x5558`. The public
`FontEncRecode(254, mapping2)` returns 21848 (`0x5558`) instead of 4369
(`0x1111`): an observed read through the redirected live-object pointer.
Controls: vulnerable `SIZE 256 256` safe input leaves the pointer and value
unchanged; fixed `5920c6e` rejects every out-of-range mapping (`map=(nil)`,
`len=0`, `recode=0`); vulnerable ASan reports `WRITE of size 2` at
`encparse.c:495`, 508 bytes past the 131072-byte region from `reallocarray`
at `:477`. Inputs, probe, runner, raw outputs and gdb layout are in
`realpath/evidence/ptrctrl/`; reproduce with `sh .../ptrctrl/run.sh`.

This is rung 4 at the real-library public-API boundary: chosen bytes at
chosen offsets plus full overwrite of one live object's data pointer and an
observed read through it. It is not a function pointer or saved return
address, and the target is an absolute heap address that needs the fixed
ASLR-off layout. No control-flow diversion, marker execution, command, X
server process, wire delivery or privileged context was exercised.

## 4. Feasibility, constraints and preserved negative results

- The advisory's vector is local. No remote wire delivery was exercised. A
  display-access X client can inject a font path into a running server and
  supply a post-start `.enc` from a writable directory (§3.5); whether an
  unprivileged OS user can reach a production X display, and whether that
  server is privileged, remain UNKNOWN.
- **Plain-build impact for the upstream regression input (`SIZE 256 258`) is
  not demonstrated**: the uninstrumented vulnerable Xvfb keeps running and
  `xdpyinfo` answers (`realpath/evidence/live/client-plain-vuln.out`). W172
  found a distinct plain crash at `SIZE 256 1024` (§3.4); the two inputs must
  not be collapsed.
- Heap-neighbour study (`realpath/evidence/gdb-heap-layout*.out`): default
  glibc places this 131072-byte request in an mmap chunk (size field
  `0x21002`, `malloc_usable_size=135152`), so 508 bytes past the nominal end
  is inside usable slack, not a neighbouring object. With
  `MALLOC_MMAP_THRESHOLD_=262144` it is a brk chunk followed by the top chunk
  (`0x20011`, next size `0x20cd1`); for a **single** mapping no live object is
  at the destination, and `reallocarray` at `:469` and the store at `:495`
  have no intervening allocation in that parse path. W183 (§3.7) preserves
  this negative result for one mapping but shows that **seven** mappings let
  the parser itself allocate live `FontEncSimpleMapRec` objects after the
  buffer before the later stores, so the destination is no longer only
  wilderness.
- The 16-bit `sm->first` truncates 65790 to 254, so only the chosen value,
  not the chosen index, survives into the copied map. W183 adds pointer
  control over one live object's data pointer, but no control-flow diversion,
  marker side effect or command was observed. The independent witness replay
  (#2867) confirmed the earlier scopes; it did not add live-object control or
  a remote path, and W183 has not been witness-replayed. The row-1024 plain
  crash is service loss, not execution. Rung 5 is UNKNOWN.

## 5. Grade and handoff

Grade at this wake: **rung 3 confirmed in a live X server process** under ASan
with attacker-request-driven chosen bytes at a chosen offset; rung 4 includes
both the local chosen-store demonstration and W183's chosen-byte overwrite of
a live parser object's data pointer at the real-library public API, observed
through a public `FontEncRecode` read, but only under a fixed ASLR-off layout;
a **plain-build crash (availability impact) is demonstrated** in a live Xvfb
at `SIZE 256 1024`; rung 5 UNKNOWN. Two independent verdicts are folded:
#2867 established rungs 1-4 CODE/HARNESS and live rung 3 from a clean
`git archive` at `6ee557d` (5/5 pins, `PASS=50 FAIL=0`, exact trace, eight
rebuilt libraries, six live Xvfb cases, fresh `WRITE of size 2` at
`encparse.c:495` 508 bytes past the 131072-byte region, and gdb readback of
chosen `0x5a5a` at index 65790); #2914 ESTABLISHED the row-1024 plain crash
at its labeled availability-only scope from a clean archive at `3f44109`
(all nine matrix lines matched, built `encparse.c` hashes match
`PINS.sha256`, faulting instruction is the chosen store itself). No
counterexample survived either replay. The upstream regression input
`SIZE 256 258` still survives in a plain build; the row-1024 crash is
service loss, not execution.

Next bounded experiment: W183 observed a live data pointer but no saved
pointer or control-flow target, so the same boundary as before still applies:
only on an observed saved pointer or control-flow target, consider a benign
marker with vulnerable, fixed and safe-input controls. Alternative evidence:
establish the OS-level unprivileged-to-privileged X display precondition on a
real deployment (W180 established runtime X-protocol injection only), or
remove the fixed-layout requirement for W183. Neither is assumed here. Both
witness verdicts are folded; the witness owes no further evidence on the
earlier scopes or the row-1024 matrix, and has not replayed W183. Full
commands, negatives and the setup-error counterexample are in `PROVENANCE.md`
W155/W156/W172/W180/W181/W183.
