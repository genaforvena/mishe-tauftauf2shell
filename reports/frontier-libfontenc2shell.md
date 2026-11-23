# Frontier brief: libfontenc setCode() row-size overflow — CVE-2026-109908 (libfontenc2shell)

**STAGED 2026-11-23 W154; EXTENDED W155; CLEAN-ARCHIVE REPLAY W156.** The W154
direct-call harness evidence stands unchanged. W155 built the real library at
the pinned commits and release tags, reached the parser through the exported
`FontEncFind()` API and through a **live loopback Xvfb `OpenFont` path**, and
settled the version discrepancy against upstream tags. W156 added a
from-scratch rebuild script and replayed it from a clean `git archive`. An
independent witness verdict is still pending; the author's report is not
acceptance. Byte-exact pins and hashes: `lab/frontier/libfontenc2shell/PINS.sha256`.
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

## 4. Feasibility, constraints and preserved negative results

- The advisory's vector is local. No remote wire delivery, font-server
  protocol or unprivileged path to write the font path was exercised.
- **Plain-build impact is not demonstrated.** With the uninstrumented
  vulnerable library, the same live Xvfb keeps running and `xdpyinfo` still
  answers (`realpath/evidence/live/client-plain-vuln.out`). The ASan crash is
  a lab-instrumentation observation, not an observed production crash.
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
  side effect, command or witness replay was observed. Rung 5 is UNKNOWN.

## 5. Grade and handoff

Grade at this wake: **rung 3 confirmed in a live X server process** under ASan
with attacker-request-driven chosen bytes at a chosen offset; rung 4 is
limited to the earlier local chosen-store demonstration (no live-object
control); rung 5 UNKNOWN. The crash claim in the advisory is not established
in a plain build on this host.

Next bounded experiment: independent witness replay of the live path (the
exact command was sent on tape #2845; a committed from-scratch rebuild
recipe `lab/frontier/libfontenc2shell/realpath/rebuild.sh` and a clean
`git archive HEAD` replay at `fb9e7b8` are in `PROVENANCE.md` W156), then —
only on an observed saved pointer or control-flow target — consider a benign
marker with vulnerable, fixed and safe-input controls. Alternative evidence:
find a production X configuration whose allocator places a live object 508
bytes past this allocation before the store, or prove the local font-path
write precondition on a real deployment. Neither is assumed here.
