# W187 — negative SIZE index that writes the low half of the chunk size

## Claim and mechanism

CVE-2026-126970 / GHSA-4qjr-2gjm-9gc6, pinned parent slice
`../pins/sch_io_altium.cpp.vuln.slice` (verbatim lines 5883-5923):
`ind = wxAtoi(remaining)` from the `SIZE` key suffix; with no lower bound,
the store `aFontSizes[ind-1] = scaled` writes out of bounds for `ind <= 0`.

Earlier lanes used `ind = 0` (`SizeZ`), whose write at `data()[-1]` lands at
byte offset -4 from the vector buffer — the **upper** half of the 64-bit glibc
chunk size word. Those runs abort with `double free or corruption (out)` and
a size >= 2^32, which is far larger than the process heap. Sections 5-6 of
`../../../reports/frontier-kicad2shell.md` already recorded `ind = -1` with
an unallocated vector (SEGV) and an 8-byte-before write with a stubbed scale
whose plain build exited 0; neither used the measured real KiCad scale nor a
real GUI process.

This lane tests `ind = -1` (`Size-1`). Its write at `data()[-2]` lands 8 bytes
before the buffer: the **low** half of the same chunk size word. The real
KiCad 8.0.8 conversion is `trunc(7.2 * value) * 254` IU; `value = 9` gives
`64 * 254 = 16256 = 0x3f80`. That is aligned and small enough to be inside a
real heap, so the >= 2^32 structural ceiling does **not** apply to this
offset. It clears PREV_INUSE (the value is always even: 254 * integer), so
`free()` attempts backward consolidation using `prev_size` from the previous
chunk's payload. That is a different fault mode, not a survivable corruption.

## Harness lane (fast, deterministic)

`sh run.sh` rebuilds eight binaries from the shared verbatim pins. Its wx stub
differs from `../harness/run.sh` in one documented way: `MilsToIU(v)` returns
`((int)v) * 254`, matching the real KiCad 8.0.8 scale measured in W183. The
`low` scenario adds `SIZE+1=10` (`atoi("+1") = 1`, sorts before `SIZE-1`, so
the vector has an allocation), then `SIZE-1=9`.

`sh check.sh` rebuilds, runs 16 invocations (g++/clang++ x vuln/fixed x
plain/asan x baseline/low), writes normalized transcripts to `evidence/` and
asserts 41 properties. Result at this wake:

```
PASS=41 FAIL=0
trace=999e6733e903364be0f7bd8ded350c0ac979fff5d9b2fe837d27e05794264796
```

Observed: gcc and clang ASan both report `WRITE of size 4`, `8 bytes before a
4-byte region`, top frame pinned `:5919`, allocation from `resize` at `:5915`.
Both vulnerable plain builds abort with `double free or corruption (!prev)`.
Both fixed builds (verbatim guard `if( ind < 1 ) continue;`) skip the key,
report `rc=0 size=1 first=18288`, and have no ASan finding. The baseline
valid-key case is clean in every build; the adjacent canary allocation is
unchanged in all surviving cases.

## Real-process lane (KiCad 8.0.8, Xvfb, native deb)

`fixtures/w187-size-1.SchLib` is a 13-byte same-length patch of the committed
`../realprocess/fixtures/w183-sizez-138889.SchLib` CFB `FileHeader` stream at
byte offset 0x2ae (686): `SizeZ=138889|` -> `Size-1=9|||||`. The repeated `|`
delimiters produce empty properties, harmless to the parser. No CFB sector,
FAT or stream-size change was needed. Sha256 in `../realprocess/PINS-w187.sha256`.

Driver `../provisioned/gui-import.sh <tag> <absolute-file> gdb` with a freshly
reset 75-byte `kicad8-config/8.0/local.kicad_sym`. Hostile run: Thread 1
`eeschema` receives `SIGSEGV`, with the faulting frame and four following
frames in the real `_eeschema.kiface`. Matched control
`w187-safe-size1.SchLib` changes only the key to `Size1=9` (same value, same
length): the process is `alive`, its gdb log has zero signal or allocator
markers. Logs and rc files are in `../realprocess/evidence/w187-*.{log,rc}`.
`sh ../realprocess/real-check-w187.sh` verifies the four hashes and the
differential: `PASS=9 FAIL=0`.

The vendor build has no ASan. The observed SIGSEGV is attributed to the host
key by the matched control, but no debugger-forced instruction or chosen
pointer was observed, so the exact faulting instruction is not source-bound.

## Negatives preserved

- An earlier throwaway scenario used key `SIZE+` intending `ind = 1`.
  `atoi("+")` is 0, so no vector was allocated and the write faulted at a
  null-derived address; that run is not the heap case. `SIZE+1` is required.
- With a throwaway stub that rounded mils after multiplication, the written
  word was `0x404b` (IS_MMAPPED bit set) and glibc reported
  `munmap_chunk(): invalid pointer`. This was a stub artifact: the measured
  real scale is `0x3f80`. The committed lane uses the measured scale.
- All four pinned downstream `aFontSizes` reads are guarded (`> 0 && <=
  size()`) and the corrupted word is not an element of the vector; none of
  them reads the corrupted metadata.
- Every possible `scaled` from this formula is even, so PREV_INUSE is always
  cleared. Combining `ind=-3` (low half of `prev_size`) with `ind=-1` still
  meets glibc's safe-unlink checks on a normal heap; no pointer control was
  observed, and no such combination was executed in this wake.

## Ceiling and replay

Rung 4 only: an ASan-confirmed 4-byte OOB write at a second, file-reachable
offset in the real process, with a distinct fault mode and a matched safe
control. No ASan vendor build, no consumer read, no pointer or control-flow
target, no benign marker, no wire delivery, no command, no witness replay and
no rung 5. Replay: `cd lab/frontier/kicad2shell/lowindex && sh check.sh`, then
`sh ../realprocess/real-check-w187.sh`. The GUI recipe above needs Xvfb,
xdotool and the provisioned KiCad 8.0.8 tree; all triggers are local files in
the lab, no network target.
