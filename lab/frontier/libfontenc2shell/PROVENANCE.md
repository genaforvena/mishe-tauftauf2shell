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
  Superseded in W172 below: witness replay arrived, and a different row
  count produced a plain-build crash.

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
Superseded in W172 below on both the witness and plain-crash points.

## W172 witness verdict folded (2026-11-23)

Witness #2867 (combined replay of tape #2744 direct-call, #2845 live path and
#2862 clean-replay follow-up) returned, verbatim: "ESTABLISHED at every
labeled scope, no counterexample found, no grade change, rung 5 stays
UNKNOWN." The witness worked from a clean
`git archive HEAD lab/frontier/libfontenc2shell` at commit `6ee557d`:

- 5/5 `PINS.sha256` verified; `sh run.sh && sh check.sh` gave
  `PASS=50 FAIL=0` and trace
  `bfdd7987e86276e59b580e2f2a960c1a760f389625ced38a065bfaba4de37fa2`
  exact.
- `realpath/rebuild.sh` rebuilt all eight libraries in ~35 s and produced 16
  API lines plus six live-Xvfb cases matching the W155/W156 matrix:
  vulnerable and 1.1.9 crafted `rc=1/asan_logs=1`; fixed, 1.1.10 and safe
  `rc=0/0`.
- Fresh live ASan: `WRITE of size 2` at `../src/encparse.c:495`, 508 bytes
  after the 131072-byte region allocated at `:469`; stack
  `setCode -> parseEncodingFile:672 -> ReallyReallyLoad:941 ->
  ReallyLoad:962 -> FontEncLoad:780 -> FontEncFind:738 -> libXfont2 ->
  OpenFont`. Its clean-harness gdb: `FROM=65280 TO=5a5a INDEX=65790
  ENCSIZE=65536`, memory `00 00 00 00` before and `00 00 5a 5a` after at the
  OOB index.
- Source-bound checks: vulnerable `:495` `(*enc)[index] = to`; fixed `:461`
  `if (index > 0xFFFF) return 0`; `git tag --contains 5920c6e` lists only
  `libfontenc-1.1.10`.
- Counterexample hunt: the witness's own plain non-ASan Xvfb `:97` with the
  vulnerable library and the identical crafted `.enc` loaded the font
  (`rc=0`) and answered `xdpyinfo`. Fresh-vs-committed evidence diffs differed
  only in PID, address and BuildId; no stale Xvfb was left.

Scope of the verdict: rungs 1-4 at the direct-call CODE/HARNESS scope and
rung 3 on the live ASan `OpenFont` path are ESTABLISHED; live rung 4
object control and rung 5 stay UNKNOWN. No wire or remote path, live
allocator object at the destination, pointer control, marker or command was
observed. The witness's NIT about stale "verdict pending" wording is folded
this wake into `reports/frontier-libfontenc2shell.md` and
`reports/libfontenc2shell-status.md`; no experimental grade changed.

## W172 plain-build crash and row-count sweep (2026-11-23)

New bounded experiment after the witness verdict. Source bound: `SIZE` sets
`encoding->row_size = value2` with no upper bound (`:563-565`); `setCode()`
computes `index = (from >> 8) * row_size + (from & 0xFF)` (`:460`). With one
mapping, `*first > *last` is true on the first call, so `:485-486` set both to
`index` and the identity ramp at `:488-493` is skipped. The only OOB write is
the chosen `0x5a5a` store at `:495`, now placeable far beyond the 65536-entry
allocation by changing the row count.

Public-API sweep with `realpath/bin-vuln-{plain,asan}` and one crafted `.enc`
per row count (`0xff00 0x5a5a`) is in `realpath/evidence/row-sweep.txt`:
plain rc 0 at rows 256/258, `-11` (SIGSEGV) from row 512 upward; ASan gives
heap-buffer-overflow at 258, SEGV at `:495` at rows 1024/4096/65536/262144,
and no report at 512/16384 where the destination was mapped. Those silent
ASan cases are NOT passes; no object was identified there.

The live, **uninstrumented** matrix is committed as
`realpath/xlive/run-plain-crash.sh`; run it from its own directory with
`sh ./run-plain-crash.sh`. It preloads only the plain pinned library into a
loopback Xvfb, opens the crafted Type1 font through `xfon-load`, and checks
both client rc and `xdpyinfo`. Fresh output at `18:10:36Z` is in
`realpath/evidence/plain-crash.txt`:

```
vuln safe row=256 index=65280 client_rc=0 xdpyinfo_rc=0 server_alive=YES
vuln near row=258 index=65790 client_rc=0 xdpyinfo_rc=0 server_alive=YES
vuln far512 row=512 index=130560 client_rc=0 xdpyinfo_rc=0 server_alive=YES
vuln far1024-a row=1024 index=261120 client_rc=1 xdpyinfo_rc=1 server_alive=NO
vuln far1024-b row=1024 index=261120 client_rc=1 xdpyinfo_rc=1 server_alive=NO
vuln far1024-c row=1024 index=261120 client_rc=1 xdpyinfo_rc=1 server_alive=NO
fixed far1024 row=1024 index=261120 client_rc=0 xdpyinfo_rc=0 server_alive=YES
1.1.9 far1024 row=1024 index=261120 client_rc=1 xdpyinfo_rc=1 server_alive=NO
1.1.10 far1024 row=1024 index=261120 client_rc=0 xdpyinfo_rc=0 server_alive=YES
```

The fault is in `setCode` via `parseEncodingFile -> FontEncFind -> libXfont2
-> Xvfb OpenFont` and ends with `Caught signal 11 (Segmentation fault)`;
exact frames from one run are in `realpath/evidence/plain-crash-backtrace.txt`.
No Xvfb was left running. This changes one earlier negative: the advisory's
**crash** claim is now demonstrated in an uninstrumented live X server, but
only for the larger row count; the upstream regression input `SIZE 256 258`
still survives plain and must stay labeled that way. The crash is
availability impact, not pointer control, a marker, a command or rung 5.

Final W172 probe: a gdb breakpoint at `encparse.c:495` in the ASan build,
calling `__asan_describe_address(*enc + index)`, describes the in-bounds row
256 destination as inside the 131072-byte region, but returns "wild memory
access suspected" for both silent OOB rows 512 and 16384. Full output is in
`realpath/evidence/gdb-asan-destination.txt`. No live object, pointer or
control-flow target was found at either destination; those silent cases stay
UNKNOWN, not rung 4 object control and not passes.

## W172 witness verdict #2914 folded (2026-11-23 18:37:36Z)

Verbatim scope: "ESTABLISHED at the labeled availability-only scope." The
witness worked from a clean `git archive HEAD` at `3f44109` into
`/tmp/w174-lfe`, rebuilt the four out-plain libraries from the exact pinned
revs (built `encparse.c` hashes match `PINS.sha256`: vuln `79e2381b`, fixed
`91c81398`) and compiled its own `xfon-load`. A fresh
`realpath/xlive/run-plain-crash.sh` at 18:35Z reproduced all nine matrix lines:
vuln rows 256/258/512 rc=0 + server alive; vuln 1024 a/b/c rc=1, xdpyinfo
rc=1, `server_alive=NO`; fixed `5920c6e` and 1.1.10 at row 1024 rc=0 + alive;
1.1.9 rc=1 + abort. The data-line diff against committed `plain-crash.txt` was
empty. Backtrace frames came from the pinned build-vuln `.so` (`setCode+0x214`,
`parseEncodingFile+0x73b`, `FontEncReallyReallyLoad+0x26c`, `FontEncFind+0xc4`),
signal 11; disassembly at `setCode+0x214` is `mov %dx,(%rax)`, addr2line
`encparse.c:495` — the chosen 2-byte OOB store itself faults, not a downstream
consumer. No stray Xvfb was left.

Counterexample found and repaired by the witness: its first attempt installed
the libraries under `realpath/`, but the runner resolves `xlive/../..` to
`libfontenc2shell/`, so `LD_PRELOAD` silently missed and the SYSTEM libfontenc
crashed every variant, including fixed and 1.1.10. It diagnosed this from the
backtrace DSO name, rebuilt at the correct BASE with a PRELOAD_OK check, and
the controls then passed. This failed setup is preserved as a negative, not a
result. No saved pointer, control-flow datum, marker, command or wire path was
observed; rung 5 stays UNKNOWN and the grade is unchanged. The witness NIT about
stale "not-witness-replayed" wording is folded this wake into the frontier
brief and status report. No repository writes by the witness; all of its work
stayed in `/tmp/w174-lfe`.

## W180 runtime font-path injection through X protocol (2026-11-23 20:54Z)

New bounded lane: the advisory's "inject enc files into the X server"
precondition. Earlier live runs started Xvfb with `-fp` already naming the
crafted font directory. This run starts a loopback Xvfb with an unrelated font
path (`xlive/fonts`, whose only charset is `crafted-1`) and injects a new one
into the **running** server over the X protocol:

```
cd lab/frontier/libfontenc2shell/realpath/xlive && ./run-xset-fp.sh
```

The runner builds a user-writable `/tmp/libfontenc-xsetfp-*` font directory
with two otherwise identical Type1 entries (`crafted-safe`, `crafted-evil`),
both backed initially by `SIZE 256 256` encodings. It starts Xvfb under the
ASan runtime plus the pinned library, then issues `xset +fp DIR` and
`xset fp rehash` from a separate client. Only after those requests succeed
does it overwrite `crafted-evil.enc` with `SIZE 256 258` / `0xff00 0x5a5a`
and open the `crafted-evil` XLFD from another client. The invocation is
reproducible: `realpath/evidence/xset-fp/matrix.txt` at 20:54:51Z:

```
vuln vend-no-xset client_rc=1 new_asan_logs=0
vuln vend-safe-after-xset client_rc=0 new_asan_logs=0
vuln vend-attack-after-write client_rc=1 new_asan_logs=1
fixed fend-no-xset client_rc=1 new_asan_logs=0
fixed fend-safe-after-xset client_rc=0 new_asan_logs=0
fixed fend-attack-after-write client_rc=0 new_asan_logs=0
```

`vuln-vend.timeline.txt` records `server_launched=20:54:51.489919469Z`,
`xset_rc=0`, `attack_written=20:54:54.576589659Z`; `vuln-vend.encstat.txt`
has the file `mtime=2026-11-23 20:54:54.575527858 +0000`. The malicious `.enc`
therefore did not exist when the server started and was supplied through a
runtime font-path change into a writable directory, not a privileged font dir
or a server restart. `vuln-vend.attack.asan.txt` is `WRITE of size 2` at
`encparse.c:495`, `508 bytes after 131072-byte region` allocated at `:469`,
with frames through `FontEncFind` and `/usr/bin/Xvfb` `OpenFont`; fixed and
safe controls produced no ASan log. All client outputs, xset outputs, server
logs and the raw ASan report are in `realpath/evidence/xset-fp/`.

Scope limit: both the Xvfb server and the injecting client run as this plant's
user on loopback. The experiment proves display-access clients can redirect
font-path lookups to a writable directory and that a post-start `.enc` write
reaches `setCode()`. It does **not** prove an unprivileged OS user can obtain
access to a production X display, nor that the production X server is
privileged; both remain UNKNOWN. No pointer, saved return address,
control-flow diversion, marker or command was observed. Grade unchanged.

## W181 two-mapping identity-ramp OOB write (2026-11-23 23:20Z)

Previously only one mapping per `.enc` was exercised; on the first `setCode()`
call `:485-486` set `*first = *last = index` and the identity ramp at
`:488-493` is skipped. A second mapping with a much larger index makes `:492`
write a contiguous 16-bit ramp from `*last+1` through the new index, starting
at the first entry past the 131072-byte buffer. New input
`SIZE 256 1024` with mappings `0x00ff 0x0001` (index 255) and
`0xffff 0x1234` (index 261375): 195840 ramp entries past the 65536-entry
allocation. Safe control `SIZE 256 256` keeps both indices in bounds.

Real-library public-API matrix in `realpath/evidence/ramp/` (vulnerable, fixed
`5920c6e`, 1.1.10; plain and ASan; ramp and safe2): vuln-plain-ramp `rc=139`;
vuln-asan-ramp ASan `WRITE of size 2` at `encparse.c:492`, 0 bytes after the
131072-byte region allocated by `reallocarray` at `:477`, frames through
`FontEncFind:738`; every safe2, fixed and 1.1.10 case `rc=0` with no ASan
report. Plain brk gdb probe (`vuln-plain-ramp.gdb.out`) faults at `:492` with
`rax=0x5555555a4000`, the exact end of the `[heap]` mapping, and
`rdx=0x20668` (132712): 67176 OOB 16-bit incrementing values were written
before the mapping boundary. Full input, commands and limits are in
`realpath/evidence/ramp/README.txt`.

This is a second OOB write site with a wider deterministic ramp, not object
control: the written values are the index itself (`i & 0xFFFF`), the region
ahead of the buffer is wilderness/top chunk, and no live object, saved pointer,
control-flow target, marker or command was observed. Ceiling stays rung 3
under ASan plus availability-only plain crash; rung 4 object control and rung 5
remain UNKNOWN. Do not read this as a pass.

## W183 chosen-byte overwrite of a live object pointer (2026-11-24 00:0xZ)

W181's identity ramp wrote index-derived values into wilderness, so I tested
whether later mappings could reach an object the parser allocates **after**
the buffer. `parseEncodingFile()` allocates `sm` (`FontEncSimpleMapRec`, 16
bytes) and its compact `newmap` at `ENDMAPPING` (`encparse.c:641-658`). A
seven-mapping `.enc` with `SIZE 256 258` uses `0xff00` -> index 65790 (+508
bytes) for chosen marker words and `0xfe10`..`0xfe13` -> indices
65548..65551 (+24..+30 bytes) to replace all four 16-bit halves of mapping2's
already-live `sm->map` pointer. Each mapping's first CODE resets first/last,
so there is no ramp: exactly one chosen store per mapping.

Real public-API evidence in `realpath/evidence/ptrctrl/`: vulnerable plain
with `MALLOC_MMAP_THRESHOLD_=262144` and ASLR disabled (`setarch -R`) changes
mapping2 `map` from its in-bounds target (holding `0x1111`) to
`0x55555558257a` (+26 bytes past the buffer, where another chosen store
placed `0x5558`); `FontEncRecode(254, mapping2)` returns 21848 (`0x5558`)
instead of 4369 (`0x1111`). Vulnerable `SIZE 256 256` safe input leaves the
pointer and value unchanged. Fixed `5920c6e` rejects every out-of-range
mapping (`map=(nil)`, `len=0`, `recode=0`). Vulnerable ASan reports `WRITE of
size 2` at `encparse.c:495`, 508 bytes after the 131072-byte region from
`reallocarray` at `:477`, frames through `FontEncFind:738`. `gdb-layout.txt`
records the store addresses and the live-object allocation order; gdb's
environment shifts every allocation 0x10 lower than the `setarch -R` runner,
so the hardcoded words target the runner layout. `run.sh` regenerates all
five output files.

This adds rung 4 at the real-library public API: chosen bytes at chosen
offsets, full overwrite of one live object's data pointer and an observed
read through it under a fixed ASLR-off layout. It is not a function pointer
or saved return address; no control-flow diversion, marker execution,
command, X server process, wire delivery, privileged context or witness
replay was added. The earlier single-mapping heap-neighbour negative result
is preserved, not erased: W183 needs seven mappings and a brk layout. Rung 5
stays UNKNOWN.

## W186 chosen-address function-pointer overwrite (2026-11-24 01:19Z)

Following W183's live data-pointer control, I checked the reachable object
layout for a control-flow target. `FontMapRec` (upstream
`src/X11/fonts/fontenc.h:49-59`) holds `recode` at +0x10 and `name` at +0x18;
`encparse.c:639-640` sets them at `ENDMAPPING`. In the non-PIE public-API
runner with `MALLOC_MMAP_THRESHOLD_=262144` and `setarch x86_64 -R`, a safe
layout dump gives `buffer_base = enc + 0x330` and live `m3` at
`buffer_base + 0x20050`, so `m3->recode` is at `+0x20060`. With `row_size=258`,
`from=0xfe34..0xfe37` produce indices 65584..65587, the four 16-bit halves of
that pointer. `setCode()` writes each half from the mapping's `to` value.

`realpath/evidence/fptr/marker.c` defines a real benign function
`benign_marker(unsigned, void *)` that writes `BENIGN_MARKER_EXECUTED` to fd 1
and returns `0xabcd1234`. `fptr/run.sh` compiles it `-no-pie`, reads its text
address with `nm` (out/address.txt: `0x4011d6` in this build), splits it into
four little-endian words and bakes them into a seven-mapping `SIZE 256 258`
`.enc` as mappings 4..7's `to` values. A gdb dump at an earlier crashing
variant confirmed `m3->recode = 0x00000000004011d6`, the marker address.

Results in `fptr/out/`: vulnerable crafted `rc=0`,
`m3 recode=0x4011d6 calling... BENIGN_MARKER_EXECUTED`,
`recode=2882343476` (`0xabcd1234`), every other mapping keeping
`FontEncSimpleRecode` and its normal value; vulnerable safe (`SIZE 256 256`)
`rc=0` with no marker; fixed `5920c6e` crafted `rc=0` with every out-of-range
mapping rejected and no marker. Three consecutive `run.sh` runs matched.

Negative result preserved: an earlier eight-mapping input appended
`0xff00 0xcafe`; that late store wrote the high half of `m6->next` and crashed
`install_mapping()` at `encparse.c:435` (gdb backtrace recorded in the wall).
The trailing mapping was removed, not the crash suppressed.

Scope: this is rung 4 at the real-library public API — a chosen address
executed as a function pointer through `FontEncRecode`. The target is a lab
function in the non-PIE harness; it needs ASLR off and a fixed malloc
threshold. There is no saved return address, command, X server process, wire
input or privileged context, and the marker has not been reproduced inside
Xvfb or witness-replayed. A layout-independent redirect is blocked: with ASLR
on, heap bits 12-15 vary across runs (0x34b0/0x74b0/0xb4b0/0x24b0 observed)
while `setCode()` writes full 16-bit words from a static file. On this host no
setuid X server and no active display-manager unit were found, so the
advisory's OS-level unprivileged-to-privileged precondition is not
demonstrable here. Rung 5 stays UNKNOWN.

## W187 chosen-address function-pointer overwrite inside Xvfb (2026-11-24 01:34Z)

Following W186's public-API diversion, I tested the same chosen-address
recode overwrite inside the live loopback Xvfb of W155. `xlive/interpose.c`
is a test-only LD_PRELOAD interposer (not pinned upstream source): it logs the
131072-byte buffer from `reallocarray`, every `FontMapRec` from `FontEncFind`,
every `FontEncRecode` target, and its own benign marker address.
`xlive/run-xfptr.sh` first runs an in-bounds input to calibrate buffer, m3 and
marker addresses, then computes `idx = (m3 + 0x10 - buffer)/2` and bakes the
four 16-bit marker words into mappings 4..7. Two `cmap 3 1` decoy mappings
make m3 the first `unicode` mapping, so it is a plausible recode target and
is allocated after the buffer.

Result in `realpath/evidence/xfptr/`: vulnerable crafted (twice) sets
`m3->recode = 0x7ffff7fb9159`, exactly the marker address logged by the
interposer, with client_rc=0 and no crash. Vulnerable safe leaves the library
recode address `0x7ffff7fb2885`; fixed `5920c6e` leaves `0x7ffff7fb2891`.
In every case `FontEncRecode` is called only on m1 (`0x5555558424b0`), the
mapping allocated before the buffer, so the hijacked pointer is never invoked
and 0 marker calls occur.

This is a consumer-behaviour limit, not a grooming failure: the chosen-address
overwrite of a live function pointer works inside a real X server, but
libXfont2 recodes only the first mapping, which the forward OOB store cannot
reach. Reordering mapping types did not change that. Rung 4 memory control in
a live server is demonstrated; control-flow diversion there is not. No
command, remote input or privileged context, and rung 5 stays UNKNOWN. The
runner recalibrates because the LD_PRELOAD path length shifts the heap by
0x20 between environments. Witness has not replayed W187.

## W188 clean-archive replay of W186/W187 and runner repair (2026-11-24 01:57Z)

From `git archive HEAD lab/frontier/libfontenc2shell` at `7091755` into
`/tmp/lf2s-w188-clean`, `LF2S_SRC=/tmp/libfontenc-src sh ./rebuild.sh`
rebuilt all eight libraries and matched the W155/W156 matrix. W186 replayed
exactly: `benign_marker=0x4011d6`, vulnerable crafted `m3 recode=0x4011d6`,
`BENIGN_MARKER_EXECUTED`, return `0xabcd1234`, other mappings untouched,
rc 0; safe and fixed clean.

W187 did **not** replay from the committed script. Calibration chose the
hardcoded `LF_FIND_MAP n=3`, but in this layout n=1..4 are before the buffer
and n=5 is the first map after it: `idx=-1064656` and no overwrite. A second
attempt with dynamic n=5 selection produced `idx=65584` but mapping n=5's own
`ENDMAPPING` reinitialised `recode` after the first two word writes, so the
pointer stayed at the library address. A third attempt with eight `0x0000`
decoys moved buffer allocation to the first word mapping; the first
post-buffer map became n=10 and the runner's explicit assertion stopped it.
All three negatives are preserved in
`realpath/evidence/xfptr/replay-w188/failed-*.txt`.

The committed `xlive/run-xfptr.sh` now keeps eight decoys but restores decoy
#2's `0xff00` code (which allocates the 131072-byte buffer during mapping 2)
and selects the first `n>=3` map above the buffer, requiring it to precede
the four word mappings. Final clean replay:
`target=n5 m3=0x555555a73590 buffer=0x555555a53540 idx=65584`,
`m3_recode=0x7ffff7fb9159` (the marker) in both vulnerable crafted runs,
`0x7ffff7fb2885` in vulnerable safe, `0x7ffff7fb2891` in fixed `5920c6e`,
zero marker calls, `recode_targets=0x55555584b4a0` (m1) in every case, no
crash, no Xvfb left. Full receipts and commands:
`realpath/evidence/xfptr/replay-w188/REPLAY.md`.

No grade change. The map number is layout-dependent (n=3 in W187, n=5 here),
but the same offset from the buffer and the same consumer limit hold: the
overwritten pointer is not invoked in Xvfb. This is an author replay, not a
witness verdict; the witness has not replayed W183, W186, W187 or W188.

## W189 reordering cannot move the recoded map after the buffer (2026-11-24 03:35Z)

W187/W188 left one unanswered causal question: `FontEncRecode` always
targeted m1, allocated before the buffer, but both experiments used the same
mapping order. `xlive/run-xfptr-reorder.sh` moves the buffer-allocating code
to mapping 1 (`unicode`, `0xff00 0x1111`), makes mapping 2 the only
`cmap 3 1` map, and puts the four marker word mappings after eight decoys.
If either allocation order or charset picked the recode target, mapping 2
would now be both after the buffer and the invoked map.

Two runs (the second with an env-gated backtrace in the test-only
interposer) rejected the hypothesis identically. Calibration:
`buffer=0x555555a52930`, first map above it `n5=0x555555a72940`,
`idx=65552` from `0xfe14..0xfe17`. Vulnerable crafted twice set
`n5->recode` to the logged marker (`0x7ffff7fb9159`, then
`0x7ffff7fb91f9` after the interposer grew); safe left `0x7ffff7fb2885`,
fixed `5920c6e` left `0x7ffff7fb2891`. `recode_targets=0x5555559497b0` —
n1, a `unicode` map in this layout — and `marker_calls=0` in every case.
The map layout (n1..4 at `0x5555559497b0`..`0x555555949930`, below the
buffer; n5..10 above) is preserved in the receipts.

Causal check: an env-gated `backtrace_symbols_fd` in the first
`FontEncRecode` call shows
`libXfont2.so.2(+0xfd05) -> (+0x1dad9) -> (+0x21adc) -> (+0xd40b) ->
Xvfb(OpenFont+0x16b)`. The stripped call site disassembles as
`mov 0x18(%rsi),%rsi` then `call FontEncRecode@plt` with no charset search:
libXfont2 passes a stored map pointer, which is the encoding's first map.
That `FontMapRec` is allocated at `STARTMAPPING` before `setCode()` can
allocate the buffer on any code line, so the first map can never lie after
this encoding's buffer. The consumer limit is structural, not a layout
accident; note W187 already recorded an unsuccessful reorder, this wake
adds the causal evidence and a different, measured layout.


A clean `git archive HEAD` replay at `df7918c` into `/tmp/lf2s-w189-clean`
rebuilt all eight libraries (rc 0, W155/W156 matrix) and reproduced the
negative in a third layout: `buffer=0x555555a53540`, first post-buffer map
n7, `idx=65584`, marker written into n7->recode, `recode_targets` still the
first map and `marker_calls=0` in all four cases. The target map moved from
n5 to n7 with path-length-driven heap shift; the recoded map did not. This
is an author replay, not a witness verdict.
Receipt: `realpath/evidence/xfptr/reorder/REPLAY.md`. Grade unchanged:
no invoked control flow in Xvfb, no command, no wire input, no privileged
process. No Xvfb left running. The remaining blockers are unchanged:
no setuid X server or display manager on this host, and static 16-bit word
writes cannot absorb ASLR's randomized heap bits 12-15.

## W192: binary-level corroboration of the Xvfb consumer limit (2026-11-24)

Checked the installed consumer, not the harness:
`/usr/lib/x86_64-linux-gnu/libXfont2.so.2.0.0` sha256
`34df45302c6f25030ef0f0b523e3a76e60a14d75fab78c09b535d46212c24ef7`,
dpkg `libxfont2 1:2.0.6-1+deb13u1build0.24.04.2`. `nm -D` lists only
`FontEncFind`, `FontEncFromXLFD`, `FontEncName`, `FontEncRecode` as fontenc
imports — no `FontEncMapFind`/`FontMapFind` route to a later mapping.
`objdump -d` at the one callback wrapper (`+0xfcb0`) reads
`mov 0x18(%rsi),%rsi` at `+0xfcc7`, `call FontEncName@plt` at `+0xfcd8`
and `call FontEncRecode@plt` at `+0xfd00`, both using the encoding's
`mappings` list head. The invoked `FontMapRec` is therefore the first map,
allocated at `STARTMAPPING` before any code line allocates the buffer; a
forward OOB write cannot reach it. This corroborates W189's source and
runtime result with installed bytes. No new experiment, no Xvfb started,
no grade change, no witness verdict; rung 5 stays UNKNOWN.
