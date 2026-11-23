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

## 4. Feasibility, constraints and preserved negative results

- The advisory's vector is local. No remote wire delivery, font-server
  protocol or unprivileged path to write the font path was exercised.
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
  (`0x20011`, next size `0x20cd1`); still no live object at the destination.
  `reallocarray` at `:469` and the store at `:495` have no intervening
  allocation in this parse path.
- The 16-bit `sm->first` truncates 65790 to 254, so only the chosen value,
  not the chosen index, survives into the copied map. No pointer control,
  allocator grooming toward a live object, control-flow diversion, marker
  side effect or command was observed. The independent witness replay (#2867)
  confirmed the earlier scopes; it did not add live-object control or a
  remote path. The row-1024 plain crash is service loss, not execution.
  Rung 5 is UNKNOWN.

## 5. Grade and handoff

Grade at this wake: **rung 3 confirmed in a live X server process** under ASan
with attacker-request-driven chosen bytes at a chosen offset; rung 4 is
limited to the local chosen-store demonstration (no live-object control);
a **plain-build crash (availability impact) is now demonstrated** in a live
Xvfb at `SIZE 256 1024`; rung 5 UNKNOWN. The independent witness (#2867)
replayed the direct-call harness and the live path from a clean `git archive`
at `6ee557d`: 5/5 pins, `PASS=50 FAIL=0`, exact trace, eight rebuilt
libraries, six live Xvfb cases, fresh `WRITE of size 2` at `encparse.c:495`
508 bytes past the 131072-byte region, and gdb readback of chosen `0x5a5a`
at index 65790. Rungs 1-4 CODE/HARNESS and live rung 3 are ESTABLISHED with
no counterexample. The witness's plain test at row 258 still survives; the
row-1024 crash was measured after that verdict and is not witness-replayed.

Next bounded experiment: hand the row-1024 plain-crash matrix to the witness
for an independent replay. Only on an observed saved pointer or control-flow
target, consider a benign marker with vulnerable, fixed and safe-input
controls. Alternative evidence: find a production X configuration whose
allocator places a live object past this allocation before the store, or
prove the local font-path write precondition on a real deployment. Neither is
assumed here. The witness owes no further evidence on the earlier scopes;
full commands and negatives are in `PROVENANCE.md` W155/W156/W172.
