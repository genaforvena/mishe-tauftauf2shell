# FUNCPATH — two-import function-pointer lane (W28, 2026-11-25)

## Question

W27 closed the single-write called-pointer lane: `Encoding.tounicode_func`
(`encoding.c:2593`) and `fromunicode_func` (`:2637`) are the only direct
function-pointer slots in the heap object inside the reachable 1 KiB window,
both calloc-NULL with no assignment site. `UniFromEnc` reaches those call
sites only when `tounicode` / `fromunicode` are NULL; in the attacked
`Encoding` they are live iconv descriptors. This wake asks whether two
imports can first zero `tounicode` and then set `tounicode_func` to a chosen
non-PIE address, producing an indirect call at a file-chosen address.

## Decision rule

A positive needs all of: (a) the first negative write zeroes `tounicode`
without killing the process; (b) a later negative write lands on
`tounicode_func` (+88) of the *same* `Encoding` in the real process; (c) a
real call reaches the chosen address. Otherwise the lane stays closed at the
measured state; no claim of a branch, marker or r5.

## Source facts

`encoding.c:2560` selects the iconv branch when `encname->tounicode` is
non-NULL; `:2592-2593` calls `tounicode_func(enc)` only in the `else` branch.
`encoding.c:2617` / `:2636-2637` are the symmetric `fromunicode` pair.
There is no assignment to either function-pointer field in the pinned tree
(`replay-w28.sh` asserts this), so only the OOB write can populate one.

## Inputs and measurement

`make-funcpath-case.py` derives two truncated PCFs from `truncated.pcf`:

- `funczero.pcf`: `glyph=-174` (`encs-696`), RHS `0`, zeroes `tounicode`.
- `funcptr.pcf`: `glyph=-170` (`encs-680`), RHS `0x406ec0`, the non-PIE
  `putchar@plt` address (chosen only as a recognizable mapped target).

`import-funcpath.ff` imports both in one process. In the non-PIE headless
build the first import survives: plain rc 0, and gdb at
`fvimportbdf.c:1751 if glyph < 0` sees
`glyph=-174 encs=0xa92070 encname=0xa91d70 delta=-768`,
`tounicode` live and `tounicode_func=(nil)`. After that write the second
import reaches the same breakpoint with `glyph=-170 encs=0xa93370`, but
`delta=-5632`: its `encs` chunk is 5632 bytes from the `Encoding`, so the
negative write cannot reach `tounicode_func`. `tounicode` is now `(nil)` on
the shared `Encoding`, but `tounicode_func` stays NULL and no call at
`encoding.c:2593` occurs (`W28CALL` absent from the transcript).

A sweep of 0..8 benign complete-table imports between the two attacking
imports gives second-import `encs` distances of 5632, 12448, 20976, 12096,
35568, 35424, 49056, 53200 and 63696 bytes; `encname` stays at `0xa91d70`.
Every case is outside the 1 KiB negative-glyph reach. The same failure
occurs with `New()` between the imports: `encs=0xa81740`, `delta=+67120`.
The `funcptr.pcf` value is therefore never installed as a pointer.

`sh replay-w28.sh` = 11/11 PASS, rc 0, final line
`REPLAY_W28_OK: 11 checks, 0 failed`. Normalized hashes:

```
9e2735c0a773506cb14237567d5df4a9ea21c86be64ec9a5ffdac27923434fe1  funczero.pcf
b0ee11863282f72f71510a4973606ddc2a378e20077421c684ce25a2eb1c3657  funcptr.pcf
04183cf9250dd1cfcd30fb5eba07d6799d5927951b252260e7586e422f97a4b4  gdb-w28-sweep.out
```

## Decision and limits

Closed as a bounded author-side negative for these two headless builds at
the measured state. No indirect call, branch at a chosen address, benign
marker, command, r5 or grade change. The descriptor-zero half is real and
survives; the second half is unreachable because each import reallocates
`encs` far from the cached `Encoding`. UNKNOWN remains: a loader or build
where the second `encs` reuses the first chunk, a GUI process, a different
allocator groom that places the `Encoding` inside the second window, or a
second-stage overflow reaching a called pointer. Author-side, unwitnessed;
no replay demand and no change to the queued #4165 offer.
