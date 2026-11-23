# Frontier brief: libfontenc setCode() row-size overflow — CVE-2026-109908 (libfontenc2shell)

**STAGED 2026-11-23 W154 — direct-call harness evidence, a live registered
two-pane window (inner socket index 115, name `libfontenc2shell`) and a staging
DM to the operator exist; operator admission and an independent witness verdict
are pending.** Byte-exact pins and hashes: `lab/frontier/libfontenc2shell/PINS.sha256`;
harness provenance including preserved negative results:
`lab/frontier/libfontenc2shell/PROVENANCE.md`. Frontier owns no further work on
this target.

## 1. Verified ground truth

- Advisory: GHSA-98gj-rwr5-8j74 / CVE-2026-109908, published 2026-11-18, High
  7.8, CVSS:3.1 `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, CWE-122 —
  https://github.com/advisories/GHSA-98gj-rwr5-8j74. Claim: a heap buffer
  overflow while reading X.Org libfontenc encoding (`.enc`) files lets a local
  attacker who can inject enc files into the X server crash it or escalate
  privileges. Discovery credited to Adam Bedard (TrendAI ZDI), ZDI-CAN-31888.
  A remote path is **not** claimed.
- Affected: libfontenc before 1.1.10 per the upstream fix tag; the advisory
  text says "before 1.11.0". Both strings are preserved verbatim; the numeric
  version discrepancy is UNKNOWN, not silently reconciled.
- Upstream fix commit
  `5920c6ee144fffff84b62f5b479171f734f15316` (2026-09-16) adds
  `if (index > 0xFFFF) return 0;` to `setCode()` and corrects the column check
  from global `value1` to the `from` parameter. Vulnerable parent:
  `7418fa7a77d1faf795ae40ea92f9ec2828e2a0b9`. Source:
  https://gitlab.freedesktop.org/xorg/lib/libfontenc.git. Upstream regression
  test `be6a0eb` includes the `SIZE 256 258` / `0xff00` case. No target by
  this name is in the plant's do-not-duplicate list, brief set or registry.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; the pinned bytes live in
`src/encparse.c.{vuln,fixed}` and are included verbatim under `#line` control
in the generated drivers.

`setCode(from, to, row_size, ...)` computes the destination index at pinned
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

## 3. Cheapest local experiment

Two generated C drivers include the complete pinned `encparse.c` for each
variant, with `#line` numbers preserved. Harness-only stubs supply four font
backend callbacks and allocator macros; the parser's real zlib `gzFile` API
reads a temporary crafted `.enc` file. No X server, font path, process, socket
or network is involved. Seven scenarios cover normal encodings, three
boundaries, the chosen-byte overflow and both loop variants.

Commands: `cd lab/frontier/libfontenc2shell/harness && ./run.sh && ./check.sh`;
then the `gdb` commands recorded in `PROVENANCE.md`.

## 4. Rung-4 feasibility and risks

Favorable: the index arithmetic, allocation cap and store are all in verbatim
pinned bytes; the fixed pin rejects the same input; both gcc and clang ASan
classify the write at the pinned line; plain-build debugger readback shows
attacker-chosen `0x5a5a` at a chosen out-of-bounds index. The overflow distance
is a direct function of the two attacker-controlled `.enc` numbers.

Constraints: the advisory's attack vector is **local** and requires the X
server to read an attacker-supplied encoding file. This harness calls the
parser directly with a temporary file; no real X server, font path,
`encodings.dir`, process boundary, allocator grooming, ASLR study, pointer or
control-flow diversion, command execution or witness replay was exercised.
The 16-bit `sm->first` field truncates 65790 to 254, so only the chosen value
survives into the copied map; the raw index survives in the debugger evidence.
Whether a real X server can be made to ingest this `.enc` file, and which heap
objects lie 508 bytes past this allocation, remain UNKNOWN.

## 5. Observations

- Harness `PASS=50 FAIL=0` three consecutive runs; normalized trace
  `bfdd7987e86276e59b580e2f2a960c1a760f389625ced38a065bfaba4de37fa2`
  (PID, address, absolute path and build id excluded). Raw outputs in
  `lab/frontier/libfontenc2shell/harness/evidence/`.
- Rung 1/2: vulnerable `oob-chosen ok=1 row=258 first=254 len=1
  chosen=0x5a5a`; fixed `first=0 len=0 chosen=0x0000`. Range and undefine
  controls also separate vulnerable from fixed (`first=0 len=0` vs
  `first=4 len=3`, and `first=0 len=1` vs `first=0 len=7`).
- Rung 3: gcc and clang ASan each report `heap-buffer-overflow`, `WRITE of
  size 2` at pinned `encparse.c.vuln:495`, `508 bytes after 131072-byte
  region` allocated at `:469`. Fixed ASan builds complete all seven cases
  cleanly.
- Rung 4: `evidence/gdb-chosen.out` shows
  `FROM=65280 TO=5a5a INDEX=65790 ENCSIZE=65536` at `:495`, bytes `00 00`
  before the store and `00 00 5a 5a` after it at the destination, with `5a 5a`
  at the out-of-bounds index. `evidence/gdb-fixed-reject.out` shows the fixed
  pin's `:461` guard firing with `ENCSIZE=0` before allocation.

## 6. Ceiling / handoff

Direct call with stubbed backend callbacks and a temporary `.enc` file; no
real libfontenc build, X server, font path, X protocol, wire delivery,
allocator study, pointer control, ROP chain, command, marker side effect or
witness verdict. The `0x5a5a` bytes are chosen data, not execution.

A dedicated target mind should first build pinned `7418fa7` and `5920c6e`
(plus the 1.1.9/1.1.10 releases to settle the numeric version discrepancy),
drive the upstream regression `.enc` file through the real
`FontEncLoad`/X server path under ASan, and identify which allocations sit
past the 131072-byte region in a live process before considering any pointer
or benign marker test. Only an observed saved pointer or control-flow
diversion would change the ceiling.
