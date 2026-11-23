# libfontenc2shell harness provenance (2026-11-23 W154)

## Source and pins

- Advisory: CVE-2026-109908 / GHSA-98gj-rwr5-8j74, High 7.8, CWE-122,
  https://github.com/advisories/GHSA-98gj-rwr5-8j74. Claim: a crafted `.enc`
  encoding file read by X.Org libfontenc before 1.1.10 overflows a heap buffer
  in `setCode()`; a local attacker able to inject enc files to the X server
  could crash it or escalate privileges. Advisory text says "before 1.11.0";
  the upstream repository tags the fixed release `libfontenc-1.1.10` — the
  discrepancy is preserved, not resolved.
- Upstream source, read-only provisioning:
  `git clone https://gitlab.freedesktop.org/xorg/lib/libfontenc.git`.
  Vulnerable parent `7418fa7a77d1faf795ae40ea92f9ec2828e2a0b9`; fix
  `5920c6ee144fffff84b62f5b479171f734f15316` (2026-09-16, "encparse: fix heap
  out-of-bounds write in setCode()", ZDI-CAN-31888, CVE-2026-109908); upstream
  regression test `be6a0eb5e3e0a8bc53a2abf14ee5403d6bd3043c`. Exact SHA-256
  of every pinned file: `PINS.sha256`.
- `src/encparse.c.vuln`, `src/encparse.c.fixed`, `src/fontencI.h`,
  `src/X11/fonts/fontenc.h` and `src/5920c6e.patch` are byte-for-byte upstream
  files. No source slice was edited.

## Verbatim slices and stubs

- `harness/run.sh` includes the **complete** pinned `encparse.c` for each
  variant in the generated `driver-{vuln,fixed}.c` under
  `#line 1 "encparse.c.{vuln,fixed}"`. Pinned line numbers cited below are the
  `#line` numbers, not rendered markdown claims. The `#line 1100
  "driver-harness.c"` boundary separates pinned bytes from harness code.
- The only stubs are: `FONT_ENCODINGS_DIRECTORY "/dev/null"`, four no-op font
  backend callbacks (`FontEncSimpleRecode`, `FontEncUndefinedRecode`,
  `FontEncSimpleName`, `FontEncUndefinedName`) and `harness/stub/reallocarray.h`
  replacing upstream's Xorg-header-dependent allocator macros with
  `realloc`-backed equivalents. The parser is otherwise untouched.
- The parser's own `gzFile` API is real zlib; harness scenario files are
  created with `mkstemp`, written, parsed and unlinked. No X server, font path,
  process, socket, wire or network is involved.

## Commands

```
cd lab/frontier/libfontenc2shell/harness
./run.sh                 # 2 generated drivers, 8 binaries (gcc/clang x vuln/fixed x plain/asan)
./check.sh               # 50 assertions, normalized trace, raw evidence in evidence/
gdb -q -batch -nx -ex 'break encparse.c.vuln:495 if row_size==258' ... --args ./bin-gcc-vuln-plain
```

`check.sh` prints `PASS=50 FAIL=0 TRACE=<sha256>`; the trace excludes PID,
addresses, absolute paths and build ids. Each run overwrites the raw evidence
files in `harness/evidence/`.

## Results and negative results preserved

- Rung 1 (trigger): `SIZE 256 258` plus `0xff00 0x5a5a` makes
  `index = (0xff00 >> 8) * 258 + 0 = 65790` in `setCode()`. `encsize` is
  `0x10000` shorts (131072 bytes); the store at `encparse.c.vuln:495` is at
  element 65790, 508 bytes past the allocation. Fixed pin rejects at
  `encparse.c.fixed:461` before any allocation/store.
- Rung 2 (state): plain vulnerable run reports `oob-chosen ok=1 row=258
  first=254 len=1 chosen=0x5a5a` (the 16-bit map truncates 65790 to 254 but
  copies the out-of-bounds short); fixed run reports `first=0 len=0
  chosen=0x0000`. The range/undefine cases also differ (`first=0 len=0` vs
  `first=4 len=3`, and `first=0 len=1` vs `first=0 len=7`) because the column
  check tested global `value1` instead of the `from` parameter.
- Rung 3: gcc and clang ASan report `heap-buffer-overflow`, `WRITE of size 2`
  at pinned `encparse.c.vuln:495`, `508 bytes after 131072-byte region`,
  allocated at `:469`; fixed ASan runs are clean. Raw reports:
  `evidence/asan-{gcc,clang}-{vuln,fixed}.out`.
- Rung 4: `evidence/gdb-chosen.out` shows at the conditional breakpoint
  `FROM=65280 TO=5a5a INDEX=65790 ENCSIZE=65536`, bytes `00 00` immediately
  before the destination before stepping and `00 00 5a 5a` after, with
  `5a 5a` at the out-of-bounds index. `evidence/gdb-fixed-reject.out` shows
  the fixed pin stopping at `:461` with the same index and `ENCSIZE=0`,
  i.e. rejecting before allocation.
- Determinism: `PASS=50 FAIL=0`,
  `TRACE=bfdd7987e86276e59b580e2f2a960c1a760f389625ced38a065bfaba4de37fa2`
  on three consecutive runs.
  A clean `git archive 64e3c54 lab/frontier/libfontenc2shell` replay in
  `/tmp/lf2s-replay` regenerated all eight binaries and reproduced
  `PASS=50 FAIL=0` with the identical trace; all five `PINS.sha256` digests
  verified there. The same recipe is recorded in
  `docs/reproducibility.md`.
- Negative result: the advisory's impact is local and conditional (injecting
  enc files into the X server); no X server, `.enc` file delivery path, real
  font backend, allocator steering, pointer control, ROP, command or witness
  verdict was exercised. The chosen `0x5a5a` is data, not execution.

## W155 extension: real library and live X server path (2026-11-23)

The W154 negative result above ("no X server ... exercised") is superseded
for this target by the following. The earlier direct-call harness evidence is
unchanged and still reproducible.

Upstream source trees were materialised by `git archive` from the read-only
`/tmp/libfontenc-src` clone at `7418fa7` (vulnerable parent), `5920c6e`
(fix), release tags `libfontenc-1.1.9` (archive commit `780d1f6`) and
`libfontenc-1.1.10` (archive commit `eb42c92`), into the gitignored
`build-{vuln,fixed,1.1.9,1.1.10}/` directories. All four build with meson
1.3.2; the 1.1.10 `libtest_helper.so` target fails because that release's
`fontencI.h` lacks a header guard (upstream HEAD `4c48b91` adds one), so its
library target `libfontenc.so.1.0.0` was built alone. `git tag --contains
5920c6e` lists only `libfontenc-1.1.10`; 1.1.9 predates the fix. This settles
the advisory's "before 1.11.0" string as inconsistent with every upstream
tag; both strings are preserved, not silently reconciled.

`realpath/run.sh` builds `load_via_public_api.c` against each shared library
(plain and `-Db_sanitize=address`) and calls the exported
`FontEncFind(charset, fontfile)` — the path used by libXfont2 — with a real
`encodings.dir` and crafted `.enc` in `realpath/tmp/fonts/`. Raw results:
`realpath/evidence/{vuln,fixed,1.1.9,1.1.10}-{plain,asan}-{safe,crafted}.out`.
The vulnerable build and 1.1.9 report ASan `WRITE of size 2` at
`../src/encparse.c:495`, 508 bytes after a 131072-byte region allocated at
`:469`, with the chain `FontEncFind:738 -> FontEncLoad:780 ->
FontEncReallyLoad:962 -> FontEncReallyReallyLoad:941 ->
parseEncodingFile:672 -> setCode:495`. Fixed `5920c6e` and 1.1.10 produce no
report; safe input produces no report in any build. Passing a NULL font
filename to `FontEncFind` makes this release's directory branch fopen the
directory itself and return NULL; the real X path always passes a font
filename, so the replay does too.

`realpath/xlive/run-live.sh` drives a **live loopback Xvfb**: the client opens
a Type1 font whose XLFD registry is `crafted-1`; libXfont2 calls
`FontEncFromXLFD`, `FontEncFind` and `FontEncReallyLoad` with the crafted
charset and font path (trace in `realpath/evidence/live/tracer-xvfb.out`).
With ASan and the pinned vulnerable library preloaded, the crafted input
crashes Xvfb from inside `OpenFont` with the same 508-byte write at `:495`
(`realpath/evidence/live/asan-vuln-crafted.out`); 1.1.9 behaves identically.
Fixed and 1.1.10 libraries and the safe input keep the X server alive and
the client succeeds (`realpath/evidence/live/client-*.out`).

Negative results preserved:

- Plain (non-ASan) Xvfb with the vulnerable library and identical crafted
  input survives: the client loads the font and `xdpyinfo` still answers
  (`realpath/evidence/live/client-plain-vuln.out`). The ASan crash is not an
  observed crash or service loss in the uninstrumented build.
- `gdb-heap-layout.out`: default glibc makes this 131072-byte request an
  mmap chunk (header `0x21002`, `malloc_usable_size=135152`); the target 508
  bytes past the nominal end is inside the chunk's usable slack. With
  `MALLOC_MMAP_THRESHOLD_=262144` (`gdb-heap-layout-brk.out`) it is a brk
  chunk (`0x20011`, usable 131080) followed by the top chunk; again no live
  object is at the destination. No allocation occurs between `reallocarray`
  at `:469` and the store at `:495`, so no neighbour object can be placed
  there in this single-threaded parse path.
- The live setup controls both the font path (`fonts.dir`, `encodings.dir`,
  `.enc`) and a Type1 font's `CHARSET_REGISTRY` property; this models the
  advisory's local attacker who can inject enc files. No remote protocol,
  pointer control, allocator grooming toward a live object, command, marker
  side effect or witness verdict was exercised. Rung 5 stays UNKNOWN.

## W156 clean-archive replay (2026-11-23)

`realpath/rebuild.sh` is the from-scratch recipe for this section. It takes
the four upstream revisions from a provisioning clone (`LF2S_SRC`, default
`/tmp/libfontenc-src`), refuses to overwrite existing build directories,
builds each library target plain and `-Db_sanitize=address`, compiles the
live client/tracer from the committed sources, provisions the Type1 font
fixture from `/usr/share/fonts/X11/Type1/NimbusMonoPS-Regular.pfb` (sha256
`49d0a528458cab48c8c4df850d182b3cf312d2b8a056a0dfae5202fc1f005dc1`),
then runs `run.sh` and `xlive/run-live.sh`. No commit outside the target's
own tree is needed:

```
git archive HEAD lab/frontier/libfontenc2shell | tar -x -C /tmp/w156-clean
cd /tmp/w156-clean/lab/frontier/libfontenc2shell/realpath
sh ./rebuild.sh
```

Verified from commit `fb9e7b8`: all eight libraries rebuilt in 37 s; the
16 public-API lines and six live-Xvfb lines matched W155 exactly. The fresh
`evidence/live/asan-vuln-crafted.out` again shows `WRITE of size 2` at
`../src/encparse.c:495`, 508 bytes after a 131072-byte region allocated at
`:469`; 1.1.9 matches, fixed/1.1.10/safe inputs stay clean. This changes
no grade: rung 3 live, no plain-build crash, no witness verdict yet.
