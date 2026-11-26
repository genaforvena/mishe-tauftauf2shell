# FROMPATH — the symmetric fromunicode pointer is written but never called (W30, 2026-11-26)

Author-side, unwitnessed. Bounded negative; no grade change, no r5.

## Question and decision rule

W27 overwrote `Encoding.tounicode` (`encs-696`) with a chosen mapped address and
observed `iconv(cd=0x414243)` from `UniFromEnc` (`encoding.c:2578`) faulting in
glibc `__gconv` before any `__gconv_fct` call. W28 closed the two-import
`tounicode_func` lane. The untested symmetric field is `Encoding.fromunicode`
at `encs-688` (`+80`), used by `EncFromUni` at `encoding.c:2623-2624`, with
`fromunicode_func` at `encs-672` called at `:2637`.

Decision rule: keep a positive only if the real process (a) installs a chosen
mapped address into `fromunicode`, and (b) reaches `iconv()` with that address
as `cd` or reaches the guarded `fromunicode_func` call. Otherwise record a
negative with the exact call sites checked.

## Input and measurement

`make-frompath-case.py` derives `frompath.pcf` (291 bytes, sha256
`f4513ca207a8742821ce76a9cc307e065cbc3183fa34e6cd570e277fccdf9a2b`) from the
pinned `truncated.pcf`: `min2=max2=0x4142`, `min1=max1=0x43`, one trailing
index byte `0x54`. With `tot=1`, `i=0`, the pinned RHS is `0x00414243`; the
low byte plus EOF gives `glyph=0x54-256=-172`, i.e. `encs-688`.

`gdb-w30-frompath-nopie.out`, non-PIE `build-nopie`, script
`import-frompath-save.ff` (`New(); Import(frompath.pcf); Save(...)`):

- before the store: `glyph=-172 fromunicode=0xa89d80` (live iconv descriptor),
  `tounicode=0xa7e3a0`, `encname=0xa91d90`, `encs=0xa92090`;
- after the store: `fromunicode=0x414243`, `tounicode` unchanged;
- breakpoints armed on `iconv if $rdi == 0x414243` and on `EncFromUni`; the
  inferior runs to normal exit without hitting either (`W30F exited`, no
  `W30F iconv-hit` / `W30F EncFromUni-hit` line).

Plain non-PIE runs of both `import-frompath.ff` (import only) and
`import-frompath-save.ff` (import + Save) exit 0; the patched non-PIE build
exits 0 on the same file and keeps the `glyph>=0` guard in its source. An
earlier import-only gdb run (`gdb` output in this wake's transcript) showed
the only `iconv` hits were `cd=0xa7e3a0`, the intact `tounicode` descriptor,
called from `UniFromEnc` at `encoding.c:2578`.

`sh replay-w30.sh` = 12/12 PASS, rc 0, final line
`REPLAY_W30_OK: 12 checks, 0 failed`. The gdb transcript contains live heap
addresses and is provenance only, not a stable hash oracle; the PCF hash and
the marker lines are the assertions.

## Decision and ceiling

The chosen address is installed in a real heap object but is never a call
destination on the measured import/Save path: `EncFromUni` (`encoding.c:2598`,
call sites `:2015`, `:2028`, `:2657`, `fvfonts.c:769`, `fvimportbdf.c:232/:2248`,
`sfd.c:7130`, `scripting.c:2716`) is not reached by this scripted headless
import. No indirect call, branch at a chosen address, marker, command, r5 or
grade change. This closes the symmetric single-write variant named in the W27
handoff for these builds and this consumer sequence. UNKNOWN remains for a
script or GUI consumer that actually invokes `EncFromUni` after the poisoned
import; even then, W27's observation predicts a fault inside glibc `__gconv`
before `__gconv_fct`, not a called chosen address. Do not infer code execution
from a written pointer field.
