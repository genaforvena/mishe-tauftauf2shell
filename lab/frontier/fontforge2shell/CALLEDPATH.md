# W27 — the called-pointer lane inside the real 1 KiB window (2026-11-25)

## Question and decision rule

W26 corrected the negative-glyph reach to `encs-1024..encs-4` and left one
explicit UNKNOWN: a live, subsequently called pointer could occupy that window
in a different heap state. This wake measures the only heap-resident candidate
family found by source review, and tests whether a file-derived write can turn
it into a branch at a chosen address.

Decision rule: a candidate counts only if (a) a called function-pointer slot or
called-pointer descriptor lies inside the measured 1 KiB window, (b) the pinned
parser can write it with file-derived bytes, and (c) a later call reaches the
chosen address. Otherwise the lane stays closed for the measured builds.

## Source-bound candidates

`ptype /o Encoding` in both real headless builds gives:

| field | offset in `Encoding` | value at the store |
| --- | --- | --- |
| `tounicode` | 72 | live `iconv_t` descriptor |
| `fromunicode` | 80 | live `iconv_t` descriptor |
| `tounicode_func` | 88 | NULL |
| `fromunicode_func` | 96 | NULL |

`Encoding.tounicode_func` and `fromunicode_func`
(`splinefont.h:752-753`) are the only direct function-pointer fields in a heap
object reachable here; `encoding.c:2592-2593` and `:2636-2637` call them. A
source-wide grep finds no assignment to either field — only a `==NULL`
comparison at `encoding.c:773` — so local input cannot make them non-NULL in
this tree.

FontForge's other callback tables are static, not heap: `noui_interface`
(`nouiutil.c:150-189`), `noui_bc` (`bitmapchar.c:940-946`) and the scripting
`builtins[]` array (`scripting.c:8353-8359`) all live in static storage. The
live called-pointer path is glibc `iconv`: `UniFromEnc` calls
`iconv(encname->tounicode, ...)` at `encoding.c:2578`, which reaches
`__gconv` and calls through `__gconv_step.__fct`. The gconv step pointers were
measured in W26 at `encs-66616 .. encs-33632`, outside the 1 KiB reach.

## Measurements (live tree, 20:0xZ)

Both builds were stopped at `fvimportbdf.c:1751 if glyph < 0` on the pinned
`truncated.pcf`:

```
pie    encs=0x555555c48280 encname=0x555555c47f80 delta=-768
nopie  encs=0xa92070      encname=0xa91d70      delta=-768
tounicode=(live) fromunicode=(live) tounicode_func=(nil) fromunicode_func=(nil)
offsets 72 80 88 96
```

The `Encoding`/`encs` distance is argv-sensitive (an earlier invocation with a
different command-file path measured `-832`), so `replay-w27.sh` derives the
write target from each transcript with `w27-target.py` rather than hardcoding
it. All three gdb invocations in a lane use the same command-file path so the
measured distance applies to the write run.

A no-condition trace at `:1750` shows `i=0 glyph=0`, `i=1 glyph=1`,
`i=2 glyph=2`, `i=3 glyph=-1` in both builds: once the file ends, `getc()`
keeps returning EOF, so only one negative offset is writable per import (the
EOF index plus repeated `encs-4` writes). `callpath.pcf` was generated with the
derived index `-174`, `min2=min1>>8=0x4142`, `min1=0x43`, giving the pinned RHS
`0x00414243` at `encs-696`, the measured `tounicode` slot.

After the store:

```
pie    tounicode 0x555555c345b0 -> 0x555500414243   iconv cd=0x555500414243
nopie  tounicode 0xa7e3a0       -> 0x414243         iconv cd=0x414243
```

The PIE high dword is inherited from the old pointer; the non-PIE high dword is
zero, so the non-PIE descriptor is fully file-chosen. The real call chain was
observed: `iconv (cd=0x414243, ...)`, called from `UniFromEnc` at
`encoding.c:2578`, from `SCBuildDummy`, from `_SFMakeChar`. Execution then
faults in glibc `__gconv` at `gconv.c:45` while reading the descriptor's
`__nsteps`/`__steps` — before any indirect call through `__gconv_step.__fct`.
The chosen address is dereferenced as data, never called. This is the same
class as W14's data dereference, now at a live called-pointer descriptor.

## Decision and limits

No branch at a chosen address, no benign marker, no command and no r5. The
single 4-byte file-derived write per import cannot fabricate the nested
`__gconv_info`/`__gconv_step` chain that glibc would need before calling
anything; the direct function-pointer fields are NULL with no assignment site;
the actual step pointers stay out of reach. This closes the called-pointer
candidate family for these two headless builds at the measured store state. It
does not close a GUI process, another loader, a different build configuration,
or a second-stage overflow that reaches a called pointer; those remain UNKNOWN.

`sh replay-w27.sh` = 23/23 PASS, rc 0, final line
`REPLAY_W27_OK: 23 checks, 0 failed`. Normalized transcript hashes (only `^W27`
lines, so volatile PID lines are excluded):

```
686cf6af93bc290e19450c6ecdd998e1f456c8fcf79bbd90ff686c3dce1e0f16  gdb-w27-pie.out
c259f977eabd3f20b31dbe9393310d765eca087cdb5728d17a062b15066dc743  gdb-w27-nopie.out
1268fefa2e8bb4b8faeb941c262a95286a4fd91c3ce718c682f49351c61a7378  gdb-w27-glyphs-pie.out
a61310d3646425356ffd63a579b8c5340deab671992e17fbf17a26a19016bcb4  gdb-w27-glyphs-nopie.out
462f15a3639881f0fb2bc99944850bff6501a344bacb5096a0a86070092576e1  gdb-w27-callpath-pie.out
42438481fe1952363efb82854de39892f60c373d438c0e7e8d952f34fa6a97e6  gdb-w27-callpath-nopie.out
```

Prerequisites: `build-plain` and `build-nopie` from `replay-real.sh` /
`replay-nonpie.sh`. No network, no loopback service, no clean-archive rebuild
this wake; the result is author-side and live-tree only.
