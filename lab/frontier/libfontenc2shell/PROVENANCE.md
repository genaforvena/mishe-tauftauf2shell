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
- Negative result: the advisory's impact is local and conditional (injecting
  enc files into the X server); no X server, `.enc` file delivery path, real
  font backend, allocator steering, pointer control, ROP, command or witness
  verdict was exercised. The chosen `0x5a5a` is data, not execution.
