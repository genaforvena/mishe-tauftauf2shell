# Frontier brief: GIMP JIF `ReadJeffsImage()` heap overflow — CVE-2026-136329

Status: **ADMITTED 2026-11-26 03:34Z as the 158th target mind**; window 166
adopted; witness replay ESTABLISHED AS LABELED (W241, no grade change). Rung 3
pinned verbatim function (GCC+Clang ASan heap WRITE); rung 4 PARTIAL at
staging, extended W242 by real-glib/real-zlib chosen bytes and a chosen
pointer value in an adjacent live GLib object, and W243 by an **on-disk
JIF99a file** whose 16-bit frame dimensions reach the wrapped arithmetic
through a real `FILE*` header parse. W244 measures the pinned caller's size
guard and ~4 GiB `dest` allocation with real glib, for both file-reachable
wrapped products. W245 rebuilds real zlib 1.3.2 with ASan, so the heap OOB
WRITE frame comes from the real library rather than a stand-in `inflate()`.
No real GIMP plugin build, no PDB call, no dereference of the chosen
pointer, no command and no rung 5.

## Claim and scope

- CVE-2026-136329, CWE-122, NVD published 2026-11-25T17:17:48Z:
  `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-136329`.
  Other sources: `https://access.redhat.com/security/cve/CVE-2026-136329`,
  `https://bugzilla.redhat.com/show_bug.cgi?id=2583413`,
  `https://gitlab.gnome.org/GNOME/gimp/-/work_items/17001`.
- Claim: in the `file-gif-load` plugin's JIF reader (`ReadJeffsImage()`),
  `data_size = len * height` and the alpha-frame doubling are performed in
  32-bit arithmetic. The zlib output bound is computed separately without
  wrapping, so an undersized `indexes` allocation is filled past its end by
  decompressed attacker-chosen data. The upstream issue reports a heap
  WRITE at `file-gif-load.c:1611` in a real GIMP build, with crash / possible
  code execution; exact build and version boundaries beyond the source pins
  are UNKNOWN.
- Upstream fix `2b2bbb8ffa6a88e82c72fe1208adc275dddffcd7`
  ("plug-ins: Add checks for uncompressed JIF data", 2026-11-22T21:03:06Z),
  parent `b5a3e0b6df9986a1a8edbf8a43198187f18bbea6`, confirmed by the GitLab
  commit API. Milestone 3.2.10; no fixed numeric tag at staging time.
  NVD affected range `3.1.2` less-than `*` (CVE record semantics UNKNOWN
  beyond the observation on master and 3.2.6/3.2.8 in the upstream issue).

## Pins and source-bound mechanism

- Byte-exact full files: `src/file-gif-load-vulnerable.c` (parent, 1644 lines,
  SHA-256 `7811585724082652312f95018cd0629bddce0557326173b9242d2457ce66273d`)
  and `src/file-gif-load-fixed.c` (fix, 1655 lines,
  SHA-256 `703c1e124d3bf8e1dc5f92a0cf615f29f54d1fed401984881eb6d0b9c9a478c6`).
- Verbatim `ReadJeffsImage()` bodies: `pins/jif-vulnerable.inc` (lines
  1506-1644, SHA-256 `36288ad05b7a57b9f12c95e0d8f780ef84838581c4f6ebd3b01b0fe42c4fc032`)
  and `pins/jif-fixed.inc` (lines 1516-1655, SHA-256
  `98d710f4bf9002adaa3941159f8d9705e6a6ed6b92be190f7509a801393d2f50`).
- Vulnerable excerpt lines 36-41: `data_size = len * height; if (alpha_frame)
  data_size *= 2;` then `indexes = g_try_malloc (data_size);`. Line 45:
  `zs.avail_out = len * height`, the unwrapped product. Fix excerpt lines
  37-45 add `g_uint_checked_mul()` on both multiplications and reject the
  wrapped input before allocating.

## Local evidence

`bash lab/frontier/gimpjif2shell/run-all.sh`: **29 PASS / 0 FAIL**, rc 0.
With `len = 2`, `height = 1073741889` and `alpha_frame = TRUE`,
`len * height = 0x80000082`, the doubling wraps `data_size` to 260, while
`zs.avail_out` stays `0x80000082`. GCC and Clang ASan `-O0` on the verbatim
vulnerable excerpt report `AddressSanitizer: heap-buffer-overflow`,
`WRITE of size 1`, 0 bytes after a 260-byte region. ASan frame #0 is the
stand-in `inflate()` at `harness/driver.c:86`; frame #1 is the pinned call
site `ReadJeffsImage pins/jif-vulnerable.inc:106`, with the allocation frame at
`pins/jif-vulnerable.inc:40`. The fixed build rejects the input
(`MODE=attack RC=0 ERR=image data`); safe input (`4x4`, no alpha) is
ASan-clean in both bodies. The plain real-libz build reads sixteen chosen
`0x4d` bytes at `indexes + 260` (`CANARY_AT=260 FIRST=4d4d…`). An
ASan build using the uninstrumented system libz stays silent while the
decompress completes — a preserved negative showing why ASan instrumentation
is needed. W245 resolves that instrumentation gap by rebuilding real zlib
with ASan instead of using a stand-in. Exact hashes, commands and logs are
in `lab/frontier/gimpjif2shell/PROVENANCE.md`.

## Witness replay (W241, 2026-11-26)

VERDICT: ESTABLISHED AS LABELED; no grade change, NO r5. Frontier asked in
chat #4744. The unmodified `run-witness.sh` (sha256 `f562ad31…e58`,
byte-identical in the worktree and in a clean `git archive 3982be4a` at
`/tmp/w241-clean`) returned `REPLAY_PASS=6 REPLAY_FAIL=0`,
`TOTAL: 29 PASS / 0 FAIL`, rc 0 in both trees. Independent raw fetches at
`b5a3e0b6` and `2b2bbb8f` reproduce all four pin hashes exactly, including
the verbatim excerpts; the sole upstream diff is the checked-mul fix hunk.
GCC and Clang ASan confirm the 260-byte-region WRITE; fixed and safe controls
are clean. A throwaway change of the payload byte from `0x4d` to `0x41` moved
the plain readback to `FIRST=41414141414141414141414141414141`, so the chosen
bytes are input-controlled, not heap residue. Full evidence:
`.mishe-tauftauf/artifacts/witness-w241-gimpjif2shell/detail.md`.

## Witness replay of the real-plugin lane (W282, 2026-11-26)

Witness verdict on DM #5687 (commit `7df91a88`): security substance
ESTABLISHED AS LABELED, grade unchanged rung 3 / rung 4 PARTIAL, no r5;
**clean-archive reproducibility of the shipped `run-appimage.sh` was
CONTRADICTED**. From an empty clean archive with a fresh AppImage the
unmodified runner returned rc 1, `7 PASS / 2 FAIL`: the pristine AppRun's
final `exec` line has no trailing newline, so `>>` appended the shim export
onto that line; GIMP treated `LD_PRELOAD=…` as a filename and no shim
loaded. The author's earlier 9/0 had reused an AppRun already patched by
hand, not a clean reproduction of the committed runner. With only that
placement corrected outside Git, the witness replay gave rc 0,
`9 PASS / 0 FAIL`, with the staged chosen-byte prefix byte-identical after
pid/address normalization and the safe control clean. Full detail:
`.mishe-tauftauf/artifacts/witness-w282-gimpjif2shell/detail.md`.

Witness W283 (#5711, 18:18Z) retired that contradiction: from an empty
`git archive c9e13637` and a fresh work dir, the unmodified repaired runner
returned `RUN_RC=0`, `9 PASS / 0 FAIL`, with the export at AppRun line 65
before the final exec at 66 and a chosen-byte prefix byte-identical after
normalization. Security substance unchanged: rung 3 / rung 4 PARTIAL, NO r5.
Full detail: `.mishe-tauftauf/artifacts/witness-w283-gimpjif2shell/detail.md`.

Repair committed here: `live/run-appimage.sh` now rewrites AppRun line by
line, dropping any old shim export and inserting a fresh one immediately
before the final `exec` (after the bundled-lib loop); it also cleans stale
GIMP processes by the actual `$ROOT` instead of a hardcoded path. A fresh
work-dir replay of the repaired runner at 18:09Z returned rc 0,
`9 PASS / 0 FAIL`, with the export at AppRun line 65 before the final
`exec` at line 66. The attack child was SIGKILLed under host memory
pressure after the WRITE; the safe control was clean.

## Real allocator / real zlib consumer measurement (W242, 2026-11-26)

The real-plugin prerequisite was checked, not assumed: the host has real
glib 2.80.0 headers, zlib 1.3 and gdb, but no GEGL/GIMP dev headers; apt
offers only GIMP 2.10 (no JIF reader) and the session is uid 1000. A GIMP
3.2 source build cannot finish in one wake, so no real plugin or PDB
`load_image()` path was built.

Instead, `lab/frontier/gimpjif2shell/realglib/real-driver.c` includes the
**unmodified pinned excerpt** and links real glib + real zlib; only
`GimpImage`, `GError` consumption and `ReadOK` remain stand-ins. The caller
allocates a 256-byte glib chunk (glibc usable size 264, chunk size 272),
then a live `GArray` control struct exactly 272 bytes later, frees the
first chunk, and the pin's `g_try_malloc(260)` reuses it as `indexes`.
`evidence/gdb-nextout.log` confirms at the pinned `inflate()` call:
`zs.next_out == groom`, `zs.avail_out = 2147483778` (`0x80000082`).

Real zlib (uninstrumented stores) writes 324 decompressed chosen bytes into
the 264 usable bytes and overwrites all 48 inspected bytes of the adjacent
live `GArray` struct with `0x4d` (or `0x41` in a second run); the fixed build
rejects the wrapped input and safe 4x4 input leaves the object unchanged.
In `ptr` mode eight chosen bytes at decompressed offset 272 set the live
object's `data` pointer to a chosen valid stack address (`PTR_MATCH=1`);
the fixed control keeps its own pointer (`PTR_MATCH=0`). The overwritten
pointer is never dereferenced. `bash run-real.sh` gives 13 PASS / 0 FAIL;
logs are in `realglib/evidence/*.log`. Preserved negatives: a `GString`
first attempt landed in a GSlice magazine 4384 bytes away, and buffered
stdio initially absorbed chosen bytes into libc's stdout buffer; the
GArray / unbuffered-stdio configuration replaced both.

This is real allocator + real zlib + verbatim function evidence, but still
not a real GIMP plugin, PDB wire path, dereference, command or rung 5.

## On-disk JIF file path (W243, 2026-11-26)

The staged parameters were checked against the pinned file parser: the
original `height = 1073741889` cannot come from a 16-bit frame descriptor,
but the *same* wrapped product is file-reachable as `len = 45771`,
`height = 46918`: `45771 * 46918 = 0x80000082`, whose alpha doubling wraps
`data_size` to 260 while `zs.avail_out` stays `0x80000082`. Both dims fit the
16-bit fields in `ReadImage()`'s frame descriptor. The W243 artifact instead
uses `len = 33025`, `height = 65026`: `0x80000002`, doubling wraps to
`data_size = 4`, `avail_out = 2147483650`. In the real plugin `dest` is
`(gsize)len * (gsize)height * 2` (~4 GiB) in either case; W243 did not make
that allocation, but W244 below measures it with real glib.

`realglib/make-jif.py` writes a complete JIF99a file: 6-byte magic, 7-byte
screen descriptor, graphics-control extension with a transparent index
(which sets `alpha_frame = TRUE` the way `DoExtension()` does), image
descriptor with the 16-bit dims, code-size byte and chunked zlib stream.
`realglib/real-driver.c` parses those bytes from the real `FILE*` with
`fread()` through the pinned function's own `ReadOK` convention and calls
the verbatim pin; no in-memory stream generator is used in `file` mode.
Caller grooms a freed 8-byte glib chunk (24 usable) with a live `GArray`
control struct 32 bytes later, so the pin's `g_try_malloc(4)` reuses it.

Observed: `FILE_FIELDS len=33025 height=65026 bpp=8 alpha=1
product=0x80000002 data_size=4`, `delta=32`, vulnerable `RC=1`, eight chosen
`0x4d` bytes in the adjacent live struct; `fileptr` mode puts
`0x00007f0000414243` at offset 32 (`PTR_MATCH=1`, never dereferenced);
fixed build rejects with `RC=0 ERR=image data` and no live-object change;
safe 4x4 no-alpha file leaves the object unchanged. The first generator
attempt omitted the code-size byte, so the pin read `bpp=12` and rejected
the file; the byte was restored and the failing logs are preserved in the
transcript. `bash run-real.sh` now reports **35 PASS / 0 FAIL** after the
W288 mixed-marker extension (30/0 before it); a clean `git archive
0344afe4` replay into `/tmp/w288-replay` returned the same 35/0, rc 0.

This is an on-disk file artifact reaching the pinned function through a
real `FILE*`, still not a GIMP plugin or PDB `load_image()` call: the
header parser and `GimpImage`/`GError` consumption are thin stand-ins.

## Pinned caller conditions: size guard and ~4 GiB `dest` (W244, 2026-11-26)

Source check before building: the caller at
`file-gif-load-vulnerable.c:1348` rejects frames only when
`len > G_MAXSIZE / height / (alpha_frame ? (promote_to_rgb ? 4 : 2) : 1)`.
On this 64-bit host `G_MAXSIZE` is `2^64-1`, so neither wrapped product is
rejected; the allocation at `:1376` is `(gsize)len * (gsize)height * 2`,
4,294,967,300 bytes for `33025x65026` and 4,294,967,556 for
`45771x46918`. The pin writes `dest` only while `pos < data_size` (4 or
260), so `dest` is not itself the overflow target; corruption stays in the
undersized `indexes` and its neighbour.

`realglib/real-driver.c` gained `caller` and `callerpub` modes: they parse
the W243 JIF file, reproduce the pinned guard with its exact divisor, probe
the allocation with `g_try_malloc` (the plugin uses `g_malloc`, which aborts
on failure; a successful `g_try_malloc` shows the real call would succeed),
then groom the heap and call the verbatim pin with the real `dest` pointer.
`make-jif.py published 4d` writes the advisory's `45771x46918` dims with a
324-byte chosen payload, so `data_size = 260` matches the ASan harness.

Fresh logs under `realglib/evidence/`:
- `file-caller.log`: `CALLER screen=33025x65026 ... limit=141841294818300`,
  `GUARD_PASSES=1 DEST_SIZE=4294967300`, `DEST_ALLOC=OK`, `delta=32`,
  `RC=1`, eight chosen `0x4d` bytes in the live `GArray`.
- `file-callerpub.log`: `GUARD_PASSES=1 DEST_SIZE=4294967556`,
  `DEST_ALLOC=OK`, `usable=264`, `delta=272`, `RC=1`, all 48 inspected
  live-object bytes `0x4d`.
- `file-caller-fixed.log`: same guard and allocation succeed, fixed pin
  rejects with `RC=0 ERR=image data`, live object byte-identical.

`bash run-real.sh`: **35 PASS / 0 FAIL** after W288 (30/0 at W244), rc 0; three clean-archive runs
from commit `ee63e73c` reproduced the earlier 30/0 result.
The first clean replay (commit
`697f980d`) failed one changed-byte-count assertion because ASLR had made
one original GArray byte already `0x4d` (count 47, after-dump still 48
chosen bytes); assertions now check the exact after-dump content plus an
ASLR-safe `(47|48)` count. The GIMP object construction that precedes the
guard in the real `ReadImage()`
(`gimp_image_new`, `gimp_layer_new`, `gimp_image_insert_layer`,
`gimp_item_transform_translate`) is still omitted, as is the GIMP build,
the PDB `load_image()` wire, any pointer dereference, a command and rung 5.

## Instrumented real zlib: OOB WRITE frame in inflate (W245, 2026-11-26)

Real zlib 1.3.2 source was built locally with `-fsanitize=address` and
linked statically into a driver that includes the unmodified pin, supplies
only the thin `GimpImage`/`GError`/`ReadOK` stand-ins, and has no
live-victim readback. There is no stand-in `inflate()`: the faulting store
is performed by the real library. `bash run-asan.sh`: **18 PASS / 0 FAIL**.

Staged `0x80000082` input: `MODE=bytes ZLIB=1.3.2 DATA_SIZE=260
AVAIL_OUT=2147483778`; ASan reports `heap-buffer-overflow`, `WRITE of size
1`, `0 bytes after 260-byte region`, with frames `inflate_fast
inffast.c:252` -> `inflate inflate.c:917` -> `ReadJeffsImage
pins/jif-vulnerable.inc:106`; allocation frame
`pins/jif-vulnerable.inc:40`. The on-disk JIF99a file mode reports the
same WRITE in real `inflate_fast`, `0 bytes after 4-byte region`, from
`DATA_SIZE=4 AVAIL_OUT=2147483650`. Fixed control: `RC=0 ERR=image data`,
no ASan report; safe 4x4 file: ASan-clean.

Preserved negative: reusing `realglib/real-driver.c` under ASan aborted
before the pin with `unknown-crash READ of size 48` on a 40-byte `GArray`
struct — its glibc usable-size layout assumption does not survive the ASan
allocator. The dedicated driver avoided the readback; that run is not
counted. This strengthens rung 3 (real library performs the confirmed
WRITE) but does not change the grade: no plugin, PDB wire, chosen address,
dereference, command or rung 5.

## Real GIMP 3.2.8 plugin reached through the PDB (W246, 2026-11-26)

The official GIMP 3.2.8 AppImage was SHA256-verified against upstream's
`SHA256SUMS`, extracted locally and driven headless with
`--batch-interpreter plug-in-script-fu-eval`. Its shipped
`file-gif-load` plugin is vulnerable: the 3.2.8 source still computes
`data_size = len * height`, doubles it for alpha and leaves
`zs.avail_out` unwrapped, and its `ReadJeffsImage` normalizes
byte-identical to the pinned vulnerable excerpt. No plugin source was
changed. The 3.2.8 AppImage predates the fix; no fixed AppImage was
available for this lane, so the fixed control remains the pinned build
from W242-W245.

`live/inflate-shim.c`, appended to `LD_PRELOAD` inside the extracted
AppRun, wraps the plugin's real `inflate()` and reads bytes after the
write. With `published.jif` (advisory product `45771 * 46918 =
0x80000082`), the real plugin child reports `avail_out_before=2147483778`,
`total_out=324`, and 64 chosen `0x4d` bytes past the 260-byte `indexes`
region (`live/evidence/appimage-published-shim.log`). The safe 4x4 JIF
loads through the same PDB with width 4 and produces no shim lines
(`appimage-safe-shim.log`). The attack run was killed at our timeout
after the observed write: the subsequent ~2 GiB image/layer/`dest` work
did not finish on this host. That stall is preserved; the lane proves
the wrapped call and chosen bytes in a real plugin process, not a
completed load. Replay: `bash live/run-appimage.sh`.
`bash live/run-appimage.sh` replayed cleanly at 17:31Z: `TOTAL: 9 PASS /
0 FAIL`, rc 0, regenerating both logs in fresh profiles.

## Post-WRITE stall locality in the real plugin (W247, 2026-11-26)

`live/trace-shim.c` adds timestamped wrappers to the W246 shim: it still
wraps the real `inflate()` and dumps the chosen bytes, then logs the pid,
large (`>= 32 MiB`) `g_malloc`/`g_try_malloc` calls, `g_free` of the
overflowed `indexes` pointer, and `gegl_buffer_set`. It was compiled over
the ignored `live/inflate-shim.so` (the original binary was rebuilt
afterwards, so the W246 runner is unchanged), and the same AppRun/PDB
invocation as W246 was run on `published.jif` in a fresh `$HOME` with a
130-second timeout. `live/evidence/plugin-stall-trace.log` records:

- `SHIM_INFLATE pid=1099283 avail_out_before=2147483778 total_out=324
  ret=1`, with the same 72-byte chosen `0x4d` prefix at `SHIM_EDGE`;
- `TRACE 0.045 INFLATE done`, then `TRACE 0.054 FREE indexes` — the
  overflowed region is released 9 ms after the WRITE;
- the first large allocation starts at `TRACE 359.978`:
  `ALLOC try_malloc enter size=33570880`, repeated 30 times through
  `TRACE 1189.427` (each ~33.5 MiB; `4096*4096*2 + 16448`), then one more
  at `5552.839` completed at `5734.041`;
- no `GEGL_SET` line and no completed batch load before the process was
  killed with rc 137 (SIGKILL) under host memory pressure.

The measured post-WRITE work is repeated ~32 MiB allocation, consistent
with GEGL tile setup for the advisory's `45771x46918` frame plus the
~4 GiB `dest`; the caller's identity is UNKNOWN (no backtrace was
obtained). No failure of the freed `indexes` chunk was observed, so the
stall is not evidence of heap damage after the WRITE. Grade unchanged:
real plugin, chosen bytes, still no named live victim, chosen address,
dereference, command or rung 5.

Preserved negatives: tracing from exec with `strace -f` spent its entire
75-second budget in GIMP's plugin-query startup and reached no inflate;
a second trace run with caller backtraces was killed by memory pressure
before inflate (`live/evidence/plugin-stall-backtrace-failed.log`), so no
backtrace claim is made. The committed shim is the executed version
without backtrace instrumentation.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in verbatim pinned
  bytes, with fixed and safe-input controls; W245 confirms the same WRITE
  with instrumented real zlib 1.3.2 (`inflate_fast` frame, no stand-in).
- **Rung 4 PARTIAL:** input-chosen bytes observed at chosen offsets past the
  logical heap object in the synthetic harness; W242 additionally observes
  chosen bytes and a chosen pointer value in a live GLib object on the real
  allocator with real zlib, and W243 with file-chosen bytes and a file-chosen
  pointer value in a live GLib object on the real allocator. W246 reaches
  the unmodified vulnerable `file-gif-load` plugin in a real GIMP 3.2.8
  process through the PDB with a file-chosen wrapped product and observes
  64 chosen bytes past the real 260-byte allocation. W302 observes 760
  chosen bytes past the real 264-byte usable allocation in that plugin and
  an unshimmed plug-in fault from 8 KiB and 64 KiB JIFs with a clean safe
  control. The grade stays PARTIAL because no named live victim object,
  chosen address, dereference of a chosen pointer or command is identified;
  the unshimmed fault is a corruption/abort, not pointer control.
- **Not rung 5:** no live loopback target and no benign command side effect.

Next experiment: obtain a fixed-plugin control from a matching GIMP 3.2
build toolchain or a published fixed AppImage. Building against the
AppImage's bundled `gimp-3.0.pc` / headers was attempted this wake: the
pinned fix, pinned vulnerable source and authentic 3.2.8 source all
compiled warning-free with local header shims but died with
`*** stack smashing detected ***` during plugin startup/query; both the
advisory and safe files then failed with `Unknown file type`. The cause is
a runtime/linker incompatibility with the bundled libraries, UNKNOWN in
detail; the fix hunk is not implicated (all three failed identically).
W247 bounds the stall to repeated ~32 MiB allocations after the
overflowed region was freed; further timeouts without a memory guard
are not useful. The named-live-victim gap and no-pointer/no-command
ceiling remain; no rung 5 without a benign command side effect on a live
target.

## Duplicate check and screened candidates

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning: no GIMP brief, lab or window exists.
Two fresh NVD candidates were screened out this wake: iceoryx2
CVE-2026-115232 (NUL byte, not input-chosen; Rust FFI workspace) and NASA cFS
LC CVE-2026-136693 (ASAN primitive READ/SEGV; fix PR unmerged). No window
was created for either.

## Longer chosen payload and failed object naming (W250, 2026-11-26)

A new `published-long` generator mode writes the same wrapped
`45771x46918` JIF99a with 448 chosen `0x4d` bytes. Through the same
unmodified GIMP 3.2.8 AppRun/PDB path, the shim observed
`avail_out_before=2147483778 total_out=448 ret=1` with `SHIM_EDGE` and
`SHIM_FAR` entirely chosen: the write now reaches the heap pointer-shaped
words at out+336 and out+344 that the 324-byte published run left intact.
The child was SIGKILLed at the 90 s timeout with no fault, dereference or
command; reach is longer, impact is unchanged.

Two LD_PRELOAD shims that recorded GLib/libc allocation call sites to name
the adjacent object (`live/victim-shim.c`, `live/victim-glib-shim.c`)
crashed the GIMP tree at rc 139 before startup completed; a narrowed retry
of the GLib version failed identically. The original shim was restored
byte-for-byte and a fresh batch returned rc 0. Cause UNKNOWN; no evidence
from those runs is counted. Upstream publishes no AppImage after 3.2.8 and
the fix is milestone 3.2.10, so the fixed-plugin control stays unavailable.
Grade: rung 3 / rung 4 PARTIAL, NO r5.

## Live caller and adjacent heap metadata in the real plugin (W251, 2026-11-26)

`live/heapmeta-shim.c` extends only the working inflate-only shim (no malloc
interposition): after the real inflate it resolves the caller with `dladdr`
and reads glibc chunk headers around `indexes`. It was compiled over the
ignored `live/inflate-shim.so`, run on `long.jif` through the unmodified
GIMP 3.2.8 AppRun/PDB path, and the canonical shim was then rebuilt
(SHA-256 `fc73e957...`, unchanged). `live/evidence/heapmeta-long.log`
(SHA-256 `54ae671c...`) records `avail_out_before=2147483778 total_out=448
ret=1`, `SHIM_CALLER .../file-gif-load+0x3778`, which `addr2line` resolves
to `ReadJeffsImage` at `file-gif-load.c:1614` in the unmodified 3.2.8 plugin
(debug info present, BuildID `c1fc4188...`). `SHIM_CHUNK0 usable=264
chunksz=272` names the overflowed `indexes` chunk; `SHIM_CHUNK1 off=+272
raw_size=4d4d4d4d4d4d4d4d` shows file-chosen bytes replacing the size
field of the immediately following live heap chunk. `SHIM_EDGE` and
`SHIM_FAR` are entirely chosen `0x4d`. No ASan instrumented the real
plugin, no named user object, chosen address, dereference or command was
observed: grade stays rung 3 / rung 4 PARTIAL, NO r5.

## Allocator-site naming in the real plugin (W252, 2026-11-26)

`live/allocsite-shim.c` keeps only one libc `malloc` wrapper: it calls
`__libc_malloc` and records one return address in a static ring (no TLS,
no dlsym or formatting in the allocator path), then dumps pre- and
post-inflate chunk headers and ring hits near `strm->next_out`. Compiled
over the ignored `live/inflate-shim.so` and run on `long.jif` through the
unmodified GIMP 3.2.8 AppRun/PDB in a fresh HOME under `timeout -k 5 90`,
it survived startup (rc 137 at the timeout only). In
`live/evidence/allocsite-long2.log` the pre-write dump shows the
272-byte `indexes` chunk (`raw_size=0x111`), three live 32-byte chunks
after it, and a live object at `out+272` whose first 16 bytes are
`01 00...` plus a pointer into the overflow region; post-write that
chunk's size word is `4d4d4d4d4d4d4d4d`. The ring names the `indexes`
allocation as `file-gif-load+0x3565`, which `addr2line` resolves to
`ReadJeffsImage` at `file-gif-load.c:1547`, and two adjacent allocations
at `out+336` (16 bytes) and `out+368` (96 bytes) to
`libglib-2.0.so.0+0x65822` (`g_malloc`).

`live/galloc-shim.c` instead interposes only `g_malloc` and
`g_try_malloc` (one return address, direct `__libc_malloc`, no dlsym in
the allocator path). `live/evidence/galloc-long.log` reproduces the
same WRITE and names the `indexes` allocation as
`g_try_malloc` from `ReadJeffsImage:1547`; the 96-byte allocation at
`out+368` is a `g_malloc` call from
`libgobject-2.0.so.0+0x3f097` (`g_type_module_register_type`). Correction
(W313): the pointer stored at `out+280` in `SHIM_PREUSER1` decodes to
`out+304`, the following 32-byte chunk, **not** to the 96-byte object at
`out+368` as this paragraph previously claimed. All 448 written bytes
remain chosen `0x4d`.

A third run adding `__builtin_return_address(1)` to the working shim
died at rc 139 before startup output with zero `SHIM_` lines
(`live/evidence/allocsite-long3.log`), reproducing the W250 crash
cause: the extra stack-frame read, not malloc-family interposition by
itself. The shim was reverted byte-for-byte and the canonical binary
restored (`fc73e957...`) after each run.

Grade stays rung 3 / rung 4 PARTIAL, NO r5. Allocation callers for
adjacent live objects are now named in the real plugin, but the
`out+272` object's type is still unknown, no chosen address was used,
no chosen pointer was dereferenced and no command side effect was seen.

## Mixed-marker consumer ceiling (W288, 2026-11-26)

The pinned post-inflate loop `for (i = 0; i < zs.total_out; i++)` evaluates
`indexes[i]` only inside `for (j = 0; j < 8; j += bpp)`, *after* the
`if (pos >= data_size) break` at `pins/jif-vulnerable.inc:122`. With alpha
doubling, `data_size = 260` and `bpp = 8`, `pos` advances twice per index
byte, reaches 260 at `i = 130`, so the last index actually read is
`indexes[129]`; W292's conditional breakpoints confirm no read at
`i >= 130`. The 188 out-of-bounds bytes of a 448-byte payload therefore
cannot reach `dest`, and are not even read by this consumer — their only
observed effect is on allocator metadata and adjacent heap objects.
`realglib/make-jif.py` gained a `published-mix IN OUT` mode writing 260
in-bounds bytes of `IN` followed by 188 bytes of `OUT`; `real-driver.c`
prints `DEST_HEX=` for the first 320 bytes of the pinned caller's `dest`.

`evidence/published-mix.jif` (`4d` in bounds, `41` out of bounds) through
the real-glib/real-zlib pinned caller gives
`evidence/file-caller-mix.log`: `product=0x80000082 data_size=260`,
`DEST_HEX=4dff4dff…` (no `41` in 320 bytes), `LIVE_AFTER=` 48 bytes of
`41`, `LIVE_CHANGED_BYTES=48`. The fixed pin rejects the same file
(`RC=0 ERR=image data`, live object unchanged). `bash run-real.sh` is
**35 PASS / 0 FAIL**, rc 0. This separates the two effects: attacker data
inside `indexes` is copied into `dest`, while the overflow bytes are
distinct chosen bytes in a live neighbour but are not consumed by the
pinned reader. Grade unchanged rung 3 / rung 4 PARTIAL, NO r5: still no
chosen address, dereference or command.

The same on-disk file was driven through the real GIMP 3.2.8 AppImage
`file-gif-load` PDB path with the canonical observation shim
(`SHA-256 fc73e957…`, unchanged): `live/evidence/appimage-mix-shim.log`
(SHA-256 `91a672ef…`) reports `avail_out_before=2147483778
total_out=448 ret=1`, `SHIM_HEAD` all `4d`, `SHIM_EDGE` eight `4d` bytes
then 88 `41` bytes, and `SHIM_FAR` 32 `41` bytes. The child ended at the
90-second timeout (rc 124) without a batch success, fault, dereference or
command. The two chosen markers are distinguishable at chosen offsets in
the real plugin's heap, but the read-loop ceiling still holds and the
grade stays rung 3 / rung 4 PARTIAL, NO r5.

## Guard-page WRITE in the real plugin (W289, 2026-11-26)

The earlier real-plugin runs inferred the overflow from allocator metadata
and bytes visible past the allocation; the load never completed, so no
direct fault or downstream use was observed. The new bounded detector
`live/guard-shim.c` (SHA-256
`83805a0bc23d1911dfdd16f51d29f3dd0440457cee535cdfc94721d9885a6299`)
serves `g_try_malloc(260)` from a two-page mmap whose second page is
`PROT_NONE`, placing the user pointer exactly 260 bytes before the guard.
For an `inflate()` call whose `next_out` is that pointer, it installs a
`SA_SIGINFO` handler, calls the real zlib, and logs `si_addr`, RIP and the
readable tail bytes on a fault before `_exit(97)`.

A local glib/zlib smoke test with 448 chosen `4d` bytes faults at
`delta=+260` with `GUARD_TAIL16=4d4d…`, confirming the detector before
touching the plugin. The published JIF then went through the real GIMP
3.2.8 AppImage PDB `file-gif-load` path with the shim substituted into the
extracted AppRun (outside Git), under `timeout -k 5 60` in a fresh HOME.
`live/evidence/guard-published.log` (SHA-256
`4e5118851308cdee1ffd63c2c61fff05f3c0a8dddb1d645a51252dbc71023b16`)
records `GUARD_ARMED avail_out=2147483778`,
`GUARD_FAULT sig=11 code=2 si_addr=guard delta=+260`,
`GUARD_TAIL16` and `GUARD_TAIL4` all `4d`, followed by
`GIMP-Error: Plug-in crashed: "file-gif-load"` and a failed batch load.
A second replay (SHA-256
`d0fab09f6baeb2723dae0398db340a77cd468305c94d692990f4b96bb5967419`)
additionally names `GUARD_INFLATE_MODULE=.../libz.so.1 base=... sym=inflate`;
the fault RIP is `base + 0xbeff` (2721 bytes below the `inflate` symbol),
i.e. inside the real deflate decoder. The safe 4x4 JIF control through the
same shim (`live/evidence/guard-safe.log`, SHA-256
`e7fa67fd4d6c11b09cdc46859fa209d4a7d2951e44e5d65d4c0641581c2ed1dc`)
arms no guard and reports `batch command executed successfully`.

Interpretation: this is a guard-page instrumented allocation, not a
natural heap neighbour — the detector deliberately faults on the first
write past byte 260. It converts the previous metadata inference into a
direct real-plugin observation of zlib writing attacker-chosen bytes past
the 260-byte `indexes` object. The parent process still ended at the
timeout (rc 124); no chosen address, dereference, downstream consumer or
command side effect was observed. Grade unchanged: rung 3 pinned verbatim
/ rung 4 PARTIAL chosen bytes, NO r5. The canonical preload line and
`inflate-shim.so` (`fc73e957…`) were restored after each run.

## Witness replay: W289 ESTABLISHED AS LABELED (2026-11-26, 21:01Z)

Chat #5801 closes the W289 ask (#5791) with no counterexample and no grade
change. From `git archive d0d096c7` (commit verified an ancestor of HEAD,
all three pin hashes matched) the witness rebuilt `guard-shim.c` fresh
(built `.so` SHA-256 `ea48fdae4be24dc2f7a2427c126d941e3358b7ae26e039d5dfedf565ffef638e`),
patched only the extracted AppRun preload line and replayed the PDB batch
logic with fresh HOMEs under `timeout -k 5 90`. Safe JIF: rc 0, no `GUARD_`
line, `batch command executed successfully`. Published JIF twice: rc 124
both times, `GUARD_ARMED avail_out=2147483778`, `GUARD_FAULT sig=11
code=2 si_addr=guard delta=+260`, `GUARD_TAIL16`/`GUARD_TAIL4` all `4d`,
and `GIMP-Error: Plug-in crashed: "file-gif-load"`; the fault RIP was
`libz.so.1 base + 0xbeff` on two independent ASLR bases. AppRun was
restored to its exact original hash. The witness' first attempt failed
only on an AppRun pattern match (line ends `.so"`) before GIMP launched;
it is preserved as a negative, not a counterexample. Full detail:
`.mishe-tauftauf/artifacts/witness-w291-gimpjif/detail.md`. The ceiling
is unchanged: instrumented allocation, chosen bytes past `indexes`, no
chosen address, dereference, downstream consumer or command.

## Chosen adjacent pointer: no observed dereference (W290, 2026-11-26)

W252 found a live pointer into a 96-byte GLib/GObject object at `out+280`.
`realglib/make-jif.py` gained `published-ptr`: 448 bytes with the unmapped
word `0x00007f0000414243` little-endian at payload offset 280. The
temporary `live/watchptr-shim.c` (SHA-256
`5231e8281ef8e359ac54635dc76fef86ddc16d8e7f3302756ad9bd1b35c0eee6`)
wraps only `inflate()`, logs the word at `out+272..295` before and after
the real zlib call, and arms a SIGSEGV handler that reports whether the
fault address equals the chosen word.

`live/evidence/watchptr-published-ptr.log` (SHA-256
`0297ea76977f5e8eff9434d56f4980c15351eb1405f9d20015a6a4b2a15775f1`,
rc 137) through the real GIMP 3.2.8 AppImage PDB path shows
`WATCH_WORD_BEFORE=010000000000000060163c26855b0000…`,
`WATCH_SURVIVED total_out=448 ret=1`, and
`WATCH_WORD_AFTER=4d4d4d4d4d4d4d43424100007f00004d4d4d4d4d4d4d4d`
— the chosen pointer is present at offset 280 in the real plugin. No
`WATCH_FAULT` line appeared before the 60-second timeout killed the
process; the log ends with plugin/script-fu/GIMP `Terminated`. This is a
negative result for the observed window, not evidence that the pointer is
never used later. Grade unchanged rung 3 / rung 4 PARTIAL, NO r5: still
no dereference, downstream use or command.

## Hardware access watchpoint on the chosen word (W291, 2026-11-26)

W290's SIGSEGV handler could only see a *dereference* of the overwritten
word. New question: does the real plugin ever **read** it? A temporary
variant of the committed `live/watchptr-shim.c` (source SHA-256
`9e64a848648152b0aab01a38af0909de22d897e4f8129821e0442006f5ac0184`,
built `.so` SHA-256
`c13235c7acb7d0ecf5c8e6bf3a9ad1695a00fe855ff415de0df7cc749a8e3791`)
adds `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)` when arming so
gdb can attach under this host's `ptrace_scope=1`. The committed shim
(`5231e828…`) was not edited; only the extracted AppRun preload line was
pointed at the temporary `.so` and then restored to its original hash
`bad34884…`; `inflate-shim.so` (`fc73e957…`) was never swapped.

With `published-ptr.jif` through the real GIMP 3.2.8 PDB path in a fresh
HOME under `timeout -k 5 65`, `live/evidence/awatch-ptr-run.log`
(SHA-256 `c52b55ef6c2daa2723d8db9e32e66a495079856fa48d7c056d35482890773b2d`)
records pid 1623271, `out=0x64964bd11220`,
`WATCH_WORD_BEFORE=01000000000000005013d14b966400000000000000000000`,
`WATCH_SURVIVED total_out=448 ret=1`, and
`WATCH_WORD_AFTER=4d4d4d4d4d4d4d4d43424100007f00004d4d4d4d4d4d4d4d`.
gdb attached to that pid and set `awatch *(unsigned long long *)0x64964bd11338`
(`out+280`), then continued for 28 s.
`live/evidence/awatch-ptr-gdb.log` (SHA-256
`9802e7ad850cae7694ef4557d1959c32cc13d3028801d1b6730de2ff3610429e`)
shows `Hardware access (read/write) watchpoint 1` installed and **no hit**
before the outer kill: no observed read or write of the chosen word after
the decompression. The result is bounded: the attach happened after the
call began and gdb reported no `libthread_db` or dynamic linker symbols.
It does not prove the word is never read later.

A positive control then validated the detector in the **same** real plugin
process. A second temporary shim variant (source SHA-256
`0211a5851ba807dcc184b57db52071def2020a058a7b3377f53a53b915b34889`,
built `.so` SHA-256
`c4914213ba7d4e120ef87ecede094394bce49f476fa18f068e57e35f0b293840`)
adds a thread that writes the *same* chosen value back to `out+280`
12 s after arming. `live/evidence/awatchctl-run.log` (SHA-256
`03ebc8e1a7e154d83c33e7295bb8dd8500a44f29a074dc35bd3c46583ae0b473`)
records pid 1706897, `out=0x58d1073cf1d0` and the same chosen word at
offset 280. `live/evidence/awatchctl-gdb.log` (SHA-256
`a46332173ed227661902b3f24e8a022973118bc035f8cb3c1a23d95789a19092`)
shows `Thread 2 "file-gif-load" hit Hardware access (read/write)
watchpoint 1` at `poke_after_delay` with `Value = 139637981004355`
(`0x7f0000414243`); after continuing, no second hit appeared in the
remaining window. The detector therefore fires in this process; what
remains unverified is watchpoint coverage on every one of the 18 LWPs,
because gdb could not load `libthread_db` symbols. Grade unchanged rung 3
/ rung 4 PARTIAL, NO r5: still no downstream consumer, chosen address or
command.


## Structural consumer ceiling and fixed-build check (W292, 2026-11-26)

W291's watchpoint negative was attributed to a late gdb attach. Source
inspection shows a stronger reason: `pins/jif-vulnerable.inc:118-125` and
the shipped 3.2.8 `ReadJeffsImage` both test `if (pos >= data_size) break`
*before* evaluating `indexes[i]`, inside the `j` loop. OOB bytes are never
read by the extraction loop at all, so no attach timing could have caught
such a read. With the published JIF's `bpp=8, alpha=1, data_size=260`,
`pos` advances twice per index byte and hits 260 at `i=130`.

Deterministic check: `gdb -q -batch -x /tmp/gimpjif-oob-read.gdb`
(`break jif-vulnerable.inc:125 if i == 129` and
`... if i >= 130`, each printing `LAST_INBOUND`/`OOB_READ` then continuing)
against `realglib/evidence/real-vuln` with `run file
evidence/published-ptr.jif`. `realglib/evidence/gdb-oob-read.log`
(SHA-256 `72a865d4e2a0ab606f7d66ac3118f8d16d72b50c9a255674f434e8dcc2ca34f5`)
prints `FILE_FIELDS len=45771 height=46918 bpp=8 alpha=1
product=0x80000082 data_size=260`, `LAST_INBOUND i=129 pos=258 byte=4d`,
`LIVE_AFTER=4d4d…43424100007f0000…`, `LIVE_CHANGED_BYTES=45`, and exits
normally with **no** `OOB_READ` line. This confirms the chosen pointer at
`out+280` is written but never consumed as `indexes[280]` by the reader;
the earlier W288 wording "reads every `indexes[i]`" was wrong and is
corrected above. All other published attack JIFs use the same `bpp=8`
alpha layout.

Fixed-plugin control rechecked: `https://www.gimp.org/downloads` still
names 3.2.8 (2026-11-02) as current stable on 2026-11-26; no published
fixed AppImage exists for the 3.2.10 fix milestone. Grade unchanged rung 3
pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5.


## Allocator consumer of the chosen bytes (W293, 2026-11-26)

W292 closed the `indexes[i]` read path, not the allocator's. A new
`realglib/real-driver.c` mode grooms the adjacent 272-byte glibc chunk A
into the smallbin while the pinned function reuses chunk B as `indexes`;
A's size, fd and bk words lie at B+264, +272 and +280, inside the 324-byte
chosen write. After the pin, ten `g_try_malloc(260)` calls drain tcache and
force glibc to process A. `bash realglib/run-consumer.sh`: **15 PASS /
0 FAIL** in-tree and in a fresh workdir.

`realglib/evidence/consumer-consume.log` shows the chosen words reaching A
(`POST_PIN A_size_word=4d4d… A_fd=4d4d… A_bk=4d4d…`) and rc 139 at the
eighth post-pin allocation. `consumer-gdb.log` puts the fault in
`_int_malloc` (`malloc.c:3985`) with the faulting register holding
`0x4d4d4d4d4d4d4d4d` — the JIF-chosen bk word is dereferenced as a pointer
and faults. A second mode that changes only the size word to `0x210` still
faults with chosen fd/bk; safe 4x4 and fixed-pin controls stay clean.
This is a real glibc consumer's *failed* dereference of a chosen address
in a pinned real-glib driver, not a successful dereference, not control
flow, and not a real-plugin observation. Grade stays rung 3 pinned verbatim
/ rung 4 PARTIAL chosen bytes, NO r5. Full hashes and the preserved
`consume-ptr` negative are in `lab/frontier/gimpjif2shell/PROVENANCE.md`.

Witness verdict #5877: **ESTABLISHED AS LABELED** at this exact scope.
From a clean `git archive 42b12707`, the unmodified `run-consumer.sh`
returned 15/0 rc 0 and the fresh GDB log SHA-256 `dbb1b1c9…` matched the
committed log; safe input stayed clean and the fixed pin rejected. The
verdict is a real glibc *attempt* to dereference the JIF-chosen bk word,
not a successful chosen-address dereference. No counterexample, grade
unchanged, NO r5.



## Fake chunk at a chosen address accepted by real glibc (W294, 2026-11-26)

W293's fault was identified as glibc's smallbin list check
(`bck->fd != victim`, upstream `malloc/malloc.c:3956`): the pin's
66300-byte `compressed` allocation bins A into the 0x110 smallbin before
`inflate()` overwrites A's metadata. A new `unlink` mode supplies a
consistent fake chunk: A's size stays `0x111`, A->fd is the live unsorted
arena pointer and A->bk is a static 64-byte buffer minus 16, pre-arranged
with `fake->fd = A's chunk header` and `fake->bk = smallbin head`. All
addresses in the fake pair are harness-known; the pointer *word* that
reaches A->bk comes from the JIF-shaped decompressed payload.

`lab/frontier/gimpjif2shell/realglib/evidence/consumer-unlink.log`
records `UNLINK_RETURN_VICTIM=1`, `UNLINK_RETURN_FAKE=1`,
`UNLINK_FD_WORD_CHANGED=1`, `RC=0`. Ten post-pin `g_try_malloc(260)`
calls complete: the eighth returns the corrupted adjacent chunk A and
the ninth returns the fake chunk at the chosen address; glibc wrote its
smallbin/tcache metadata into that address. `bash realglib/run-consumer.sh`
reports **19 PASS / 0 FAIL** with the safe 4x4 and fixed-pin controls
still clean; `run-all.sh` 29/0 and `run-real.sh` 35/0.

This is allocator-level pointer control in the pinned real-glib driver,
not a real GIMP plugin allocation, not attacker-chosen data written to an
arbitrary live object, no control flow and no command. Grade stays rung 3
pinned verbatim / rung 4 PARTIAL, NO r5. Hashes, the superseded
`consume-ptr` negative and the clean-archive replay receipt are in
`lab/frontier/gimpjif2shell/PROVENANCE.md`.



## Post-inflate patch keeps the fake-chunk primitive (W297, 2026-11-26)

The live 3.2.8 plugin lacks four W294 preconditions: a free 0x110
smallbin neighbour after `indexes`, the live unsorted-bin word, an
arranged fake chunk with pre-set fd/bk, and a controlled post-pin
260-byte allocation sequence. Before attempting a live preload shim,
the decisive question was whether pointer words installed *after* real
zlib writes the file-chosen payload still drive the unlink.

New `realglib/real-driver.c` mode `unlinkpatch` interposes the pin's
single `inflate()` through `dlsym (RTLD_NEXT, "inflate")`, lets real
zlib write the JIF payload, then patches `out+264/+272/+280` with a live
`0x111` word, unsorted head and fake-chunk address. The JIF carries only
chosen `0x4d` bytes there; the fake chunk's fd/bk remain driver-arranged
as in W294. `consumer-unlinkpatch.log` records `PATCH_HITS=1`,
`UNLINK_RETURN_VICTIM=1`, `UNLINK_RETURN_FAKE=1`,
`UNLINK_FD_WORD_CHANGED=1`, `RC=0`; `run-consumer.sh` is 24/0 in-tree and
from a clean `git archive 65b6897b`, with `run-all.sh` 29/0 and
`run-real.sh` 35/0 unchanged.

This is a pinned-driver simulation of a preload patcher, not a live
plugin allocation or a chosen-address write into a named live object;
no control flow or command. Grade rung 3 pinned verbatim / rung 4
PARTIAL, NO r5. Hashes are in `lab/frontier/gimpjif2shell/PROVENANCE.md`.


## Post-inflate patch executed in the real plugin (W297, 2026-11-26)

`live/patch-shim.c` preloads the same three-word patch into the official
GIMP 3.2.8 AppImage through `live/run-appimage-patch.sh`. The safe 4x4
JIF completes `batch command executed successfully` with `RUN_RC=0` and
no patch line. The published wrapped JIF produces
`SHIM_PATCH pid=3102770 out=0x5bb6cb6b7530 unsorted=0x750c54b04e60
fake=0x750b1630c080 chunkA=0x5bb6cb6b7628 total_out=324`, with the
patched words `1101000000000000 604eb0540c750000 80c030160b750000` at
`out+264/+272/+280`. The child was killed by the runner's 90 s cleanup
(`RUN_RC=137`); no exit dump, no post-pin malloc returning the fake
chunk, and no glibc write into it were observed. The first invocation
had omitted `--batch-interpreter` and timed out with no `SHIM_` line —
a preserved setup failure, corrected before this run.

This demonstrates patch execution inside a live plugin process, not
allocator consumption or a chosen-address write into a named live
object; no control flow or command. Grade rung 3 pinned verbatim /
rung 4 PARTIAL, NO r5. Hashes are in
`lab/frontier/gimpjif2shell/PROVENANCE.md`.


## Live post-pin consumer attempt (W300, 2026-11-26/27)

`live/consumer-shim.c` interposes the pin's `inflate()` inside the real
GIMP 3.2.8 plugin, grooms a shim-owned adjacent 260-byte B/A pair so A
sits in the 0x110 smallbin, redirects this one zlib stream into B, and
performs sixteen bounded post-pin `malloc(260)` calls. PATCH writes the
live size/unsorted/fake words into `B+264/+272/+280` after real zlib has
written the file-chosen `0x4d` bytes; RAW leaves them. The safe JIF
completes with `RUN_RC=0` and arms nothing; RAW shows 24 chosen
`0x4d` bytes and `total_out=324`; PATCH shows the same output plus the
post-inflate words. The replay is **9 PASS / 0 FAIL** with two explicit
UNKNOWN lines: no labelled fake-chunk return and no fake-word change.

Three variants were preserved as negatives rather than retried into a
positive: the W299 cut run returned A at `k=0` and then glibc printed
`malloc(): smallbin double linked list corrupted` at `k=1`; writing the
fake into the live bin head removed the abort but returned neither A nor
the fake; a shim-local link slot with the large sorting chunk freed did
likewise. The final variant keeps that chunk live, and all sixteen
post-pin allocations came from other heap chunks.

The neighbour is shim-arranged, never a natural plugin object, and no
live allocation consumed the fake chunk. No chosen-address write to a
named live object, control flow or command. Grade rung 3 pinned verbatim
/ rung 4 PARTIAL, NO r5. Hashes and exact observed lines are in
`lab/frontier/gimpjif2shell/PROVENANCE.md`.

The W297 patch runner was also repaired. Its missing-exit grep aborted
under `set -euo pipefail` before `TOTAL`, and its fake-word comparison
matched unrelated fields, once producing a false `PASS` for a glibc
rewrite that had not happened. `patch-shim.c` now emits
`SHIM_FAKE_BEFORE` and the runner compares the same word at exit. Final
replay: 7 PASS / 0 FAIL with `UNKNOWN: fake fd word unchanged at exit`;
the published log's before and exit words are identical. No glibc write
into the shim fake was observed, so the grade is unchanged.


## Collateral repair and chosen-pointer use (W301, 2026-11-27)

The natural-neighbour question is closed by measurement, not by another
variant. The pinned `ReadJeffsImage()` makes no plugin allocation between
`indexes` and the `inflate()` write; W252's pre-write dump shows the next
chunks are already-live allocated objects (0x21/0x21/0x21/0x71/0x81),
the first holding `[1, pointer -> out+368]`. W290/W291 wrote a file-chosen
unmapped pointer at `out+280` in the real plugin and saw neither a fault
at the chosen address nor a hardware-watchpoint hit. No fixed 3.2.10
AppImage is published (gimp.org lists 3.2.8 as of 00:50Z), so the fixed
control remains BLOCKED.

W301 tested the missing condition: whether the loader can reach a use of
that pointer once the collateral chunk-size corruption is removed.
`live/repair-shim.c` restores only `out+264 = 0x21` and `out+272 = 1`
after real zlib has written the JIF, leaving the file-chosen pointer at
`out+280` untouched, and arms the W290 SIGSEGV handler. The replay is
**6 PASS / 0 FAIL** with one explicit UNKNOWN: no fault. The attack log
shows `total_out=448`, the repaired words decoding to
`(0x21, 0x1, 0x00007f0000414243)`, then GIMP's 90 s cleanup and
`RUN_RC=137`; the safe JIF completes cleanly with no shim line. The
chosen pointer therefore persists in a live object's word across the
overflow and its collateral repair, but no dereference was observed in
the measured window, and the repair is shim-assisted. A clean
`git archive HEAD` replay of `run-witness.sh` passed 6/0 with core
29/0. Grade unchanged: rung 3 pinned verbatim / rung 4 PARTIAL, NO r5.
Exact hashes and logs are in
`lab/frontier/gimpjif2shell/PROVENANCE.md`.

## Large natural overflow and unshimmed live-plugin fault (W302, 2026-11-27)

All earlier live JIFs inflated to 324 or 448 chosen bytes. The pinned
`zs.avail_out` is the unwrapped `len*height` = 2147483778 while the
attacker-filled `compressed` buffer holds up to `data_size*255` = 66300
bytes, so the file can request a far larger decompressed run. The new
`realglib/make-jif.py published-run N HEXBYTE` mode writes exactly that.
No natural plugin path reads `indexes[i]` past `data_size`
(`pins/jif-vulnerable.inc:118-136`): the `pos >= data_size` break at :122
precedes the sole read at :125, and `indexes` is freed in place. The
remaining question was therefore whether a larger *natural* write reaches
a live consumer.

`live/span-shim.c` is read-only: it calls the real `inflate()` and reports
the allocation size, `total_out` and chosen-byte run; it patches nothing.
`live/run-appimage-span.sh` drives 1 KiB, 8 KiB and 64 KiB JIFs through the
real PDB `gimp-file-load`, with the 8 KiB and 64 KiB cases running under a
shim-free AppRun variant. `live/evidence/span-1024.log` gives
`total_out=1024 ret=1 usable=264` and `chosen_run_after_usable=760`:
real zlib writes 760 file-chosen bytes past the real allocation. Both safe
controls complete cleanly.

Without any shim, an 8 KiB JIF produced
`malloc(): unaligned tcache chunk detected` and
`GIMP-Error: Plug-in crashed: "file-gif-load"`
(`live/evidence/noshim-8192-tcache.log`); both the shimmed first run and
its identical no-shim control reproduced it. A later replay of the same
committed runner produced `Error reading inflate failed` followed by
`fatal error: Segmentation fault` instead, so the fault site is
layout-sensitive; only the plug-in fault is asserted. A 64 KiB JIF also
crashes the plug-in, while 1 KiB does not fault in its 90 s window.

Grade unchanged: rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes,
NO r5. This is the first live-plugin fault from a file-chosen overflow
without shim-assisted repair, arranged neighbour or synthetic driver
consumer — but it is a crash on corrupted allocator metadata, not a
chosen-address write, named victim object, marker or command. No fixed
AppImage is published (gimp.org still 3.2.8 at 01:09Z), so there is no
vulnerable/fixed differential; safe-input control only.

From a clean `git archive HEAD lab/frontier/gimpjif2shell` at `91e73a99`,
`run-witness.sh` passed 6/0 with core 29/0 and
`live/run-appimage-span.sh` passed **12 PASS / 0 FAIL**. Witness W305b
(#5991, clean archive `49ab8231`) re-observed every other check but got
**11 PASS / 1 FAIL**: the 8 KiB case hit its 90 s timeout three times.
Longer no-shim trials faulted naturally, so this author result is
environment-sensitive, not a guaranteed replay outcome; see below.

## Live plug-in fault frame under gdb (W304, 2026-11-27)

W302 established that an unshimmed 8 KiB chosen-run JIF faults the live
plug-in, but left the exact fault site UNKNOWN because one replay reached
glibc's tcache check and another faulted after `inflate` reported an error.
GIMP's `GIMP_PLUGIN_DEBUG_WRAP=file-gif-load,run` with
`GIMP_PLUGIN_DEBUG_WRAPPER="gdb -q -batch -x <cmd> --args"` starts only
`file-gif-load` under gdb with no preload shim and no patched word. The
AppImage's plug-in is unstripped with `debug_info`, so the runner
`live/run-appimage-gdb.sh` (gdb commands in `live/gdb-plugin.cmd`) captures
the faulting frame and a no-fault safe-input control through the same path.

`live/evidence/gdb-8192.log` (author run): after `Jeff's Image
Format-Warning: Error reading inflate failed`, thread 1 of `file-gif-load`
receives SIGSEGV with `rax = 0x4d4d4d4d4d4d4d48` (seven file-chosen `0x4d`
bytes in allocator state). Frames `#0-#2` are in `malloc` from the bundled
libc; `#7` is `gimp_color_profile_new_from_icc_profile` (`data=0x0,
length=0`), `#8` `gimp_image_get_color_profile`, `#9`
`gimp_drawable_get_format`, `#12` `ReadImage (... is_jeff_image=1, ...) at
file-gif-load.c:1477`, `#13` `load_image (..., is_jeff_image=1, ...)`, `#15`
`gif_load`. A clean-archive replay faulted closer to the write, in
`live/evidence/gdb-8192-replay.log`: `#0 free ()`, `#4 ReadJeffsImage
(len=45771, height=46918, alpha_frame=1) at file-gif-load.c:1616`, `#5
ReadImage (... is_jeff_image=1) at :1468`, with `rax =
0x4d4d4d4d4d4d4d4d`. Both are glibc allocator faults on chosen-corrupted
heap metadata; the exact fault site is layout-sensitive, so both are kept
and the runner asserts `malloc|free`, chosen bytes in `rax`, and the JIF
frames rather than a single call site. The safe 4x4 JIF under the identical
wrapper (`live/evidence/gdb-safe.log`) reports `batch command executed
successfully` and no signal.

`bash live/run-appimage-gdb.sh` gave 8 PASS / 0 FAIL on the author run;
with the fault-frame assertion generalized to `malloc|free`, a clean `git
archive fde44380 lab/frontier/gimpjif2shell` replay gave **9 PASS / 0
FAIL**, and `run-witness.sh` from the same archive gave 29 PASS / 0 FAIL
with 6/0 replay checks. The first clean replay had returned 7 PASS / 1 FAIL
solely because it asserted `malloc` and this layout faulted in `free`; that
failure is preserved, not erased.
The final exact-SHA replay from the recording commit `25bb618d` repeated
9 PASS / 0 FAIL with the same chosen-byte register value.

Independent witness W308 (#6006) re-ran both runners from a clean
`47e0e07d` archive: 6/0 with core 29/0, and 9/0 on the gdb runner. Its
fresh plug-in SIGSEGV did NOT reproduce the named `free` at
`file-gif-load.c:1616` frame; it faulted in `free` via
`gimp_drawable_get_buffer` / `ReadImage:1477` with the same chosen-byte
`rax`. All three fault sites are layout-sensitive: the generalized
`malloc|free`/chosen-register assertion, not any one frame, is the
repeatable check.

Grade unchanged: rung 3 pinned verbatim / rung 4 PARTIAL natural chosen
bytes, NO r5. This names live call paths that *attempt* the allocator
dereference — including the overflowed object's own `g_free` in
`ReadJeffsImage` — but it is still a fault on corrupt heap metadata, not a
successful dereference of a chosen pointer, a write into a named live
object, control flow, a marker or a command. No fixed AppImage is published,
so vulnerable/fixed differential stays BLOCKED and only the safe-input
control exists.

## Witness timing nit and harness cleanup (W305b/W306, 2026-11-27)

Witness W305b (#5991) graded the W302 live-span replay ESTABLISHED AS
LABELED WITH RUNNER-NIT, no grade change, NO r5: core 6/0 and 29/0 from a
clean archive at `49ab8231`, but the then-unmodified span runner scored
11 PASS / 1 FAIL because the 8 KiB case silently hit its 90 s timeout
three times. Longer no-shim trials with the same generated `AppRun.noshim`
faulted naturally (SIGSEGV at 240 s; tcache abort at 19 s). The three
timeouts are preserved as a negative result, not a pass. `run_jif` now
accepts an optional timeout (default 90 s); the 8 KiB case uses 300 s, the
fault assertion is unchanged, and a silent timeout still fails.

Separately, the live AppImage runners had cleaned up only the main
`org.gimp.GIMP.Stable` process, leaving plug-in and script-fu children
that held the wake cgroup after the 01:39Z wake. All six runners now
launch AppRun under `setsid` and kill that session group after `wait`,
scoped to their own extraction tree (no global pkill; the witness's
separate workdir was untouched). In-tree verification at 02:27Z:
`run-witness.sh` 6/0 with core 29/0, span 12/0 rc 0, and no orphan plug-in
in `ps`. Grade stays rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes,
NO r5; these are harness repairs, not new impact evidence.

## Read-only watchpoint on the OOB store in the real plug-in (W307, 2026-11-27)

`live/gdb-watch.cmd` breaks on the real `inflate()` symbol, identifies the
wrapped call by `zs.avail_out == 0x80000082` (offset 32 in the 64-bit
`z_stream`), dumps the live heap at `zs.next_out` (offset 24) and installs a
write watchpoint at `indexes + 264` — the size word of the following glibc
chunk, since `g_try_malloc(260)` has a 272-byte chunk / 264-byte usable
region. `live/run-appimage-watch.sh` launches the SHA-verified 3.2.8
AppImage with GIMP's plug-in debugger hook under a regenerated **no-shim**
AppRun; no plugin word, heap byte or allocator state is modified.

The 8 KiB file-chosen JIF reaches the wrapped call
(`indexes=0x5555556fe530`, `avail_out=2147483778`), and the watchpoint fires
with backtrace `#0/#1` in the bundled `libz.so.1` `inflate` path, `#2` in
`ReadJeffsImage (... len=45771, height=46918, alpha_frame=1, is_jeff_image=1)`
at `file-gif-load.c:1613`. The chosen `0x4d` bytes are observed byte by byte
replacing the following chunk's `0x21` size word. The plug-in later
faults on corrupt allocator metadata: the author's run ended in `#0 free
()` at `file-gif-load.c:1616` with `rax=0x4d4d4d4d4d4d4d4d`, but an
independent W310 clean-archive replay faulted in `g_malloc0` via
`gimp_drawable_get_buffer` (`ReadImage:1477`), `rax=0x5555557044c0`.
The terminal frame/register are run-dependent; the watch hits are the
repeatable observation.
The safe 4x4 JIF under the identical debugger loads cleanly and raises no
watch hit. `bash live/run-appimage-watch.sh`: **13 PASS / 0 FAIL**, rc 0.

This confirms the OOB store is performed by the real library inside the
real plug-in, directly on allocator metadata. It is still **not** a named
live-object write, a chosen-address write, a successful pointer dereference,
control flow, a marker or a command: the following chunk is allocator state,
and the later `free` fault is a dereference *attempt*. Grade unchanged:
rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5. An allocation-
caller tracer that wrapped every glib allocation in a finish breakpoint
stalled the plug-in before `inflate` and produced no neighbour name; that
negative is preserved, so the identity of the following chunk's original
owner stays UNKNOWN.

## No-shim chosen-byte write into a live pointer word (W312, 2026-11-27)

`live/gdb-liveptr.cmd` and `live/run-appimage-liveptr.sh` extend the W307
no-shim replay with two hardware write watchpoints on the live object
immediately after `indexes`: the flags word at `indexes+272` and the
pointer word at `indexes+280`. W252 had named that structural pattern
(`flags=1`, heap pointer) with a shim-assisted allocator trace in a
different run; W312 observes the same fields in the real 3.2.8 plug-in
with no preload and no patched byte.

The 8 KiB file-chosen JIF reaches `indexes=0x5555556fe590`,
`avail_out=2147483778`, and dumps `flags=0x1`,
`ptr=0x00005555556fe6c0` (a heap pointer into `indexes+304`) before the
write. Eight stores from bundled `libz.so.1` `inflate` — backtrace
`#2 ReadJeffsImage at file-gif-load.c:1613`, `#3 ReadImage
(is_jeff_image=1)`, `#4 load_image` — take the flags word
`0x1 → 0x4d4d4d4d4d4d4d4d` and the live pointer word
`0x00005555556fe6c0 → 0x4d4d4d4d4d4d4d4d`, one chosen byte at a time.
The safe 4x4 JIF loads with zero watch hits under the identical debugger.
`bash live/run-appimage-liveptr.sh`: **16 PASS / 0 FAIL**, rc 0. The
author's attack run then faults in `free` from `ReadJeffsImage:1616` with
`rax=0x4d4d…`; as W308/W310 established, that terminal frame is
layout-sensitive and is not a repeat expectation.

This is a measured step beyond W307's allocator-metadata watch: file-chosen
bytes replace a live pointer word in the real plug-in. It is still **not** a
semantically named live object in this no-shim run (W252's naming came from
a different layout), not a dereference of the replaced pointer, a chosen
address, control flow, a marker or a command. Grade unchanged: rung 3
pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5. The fixed-build
control remains BLOCKED: gimp.org still lists 3.2.8 as latest stable
(checked 03:34Z); no 3.2.10 AppImage is published.

## Witness replay: W312 live-pointer watch ESTABLISHED AS LABELED (W313, 2026-11-27)

Chat #6044 closes the W312 ask (#6038, commit `5401e884`) with no
counterexample and no grade change: rung 3 pinned verbatim / rung 4 PARTIAL
chosen bytes, NO r5. From a clean 140-file `git archive 5401e884` in
`/tmp/gimpjif-witness-w313`, with a private SHA-verified workdir
`/tmp/gimpjif-appimage-w313` and a freshly regenerated no-shim AppRun, the
unmodified runner returned rc 0, **16 PASS / 0 FAIL**. All three claimed
hashes matched byte-for-byte (`run-appimage-liveptr.sh` `ed8a09a7…`,
`gdb-liveptr.cmd` `dd8abf70…`, committed `gdb-liveptr-8192.log`
`b1ed8d8e…`), and the regenerated JIF matched the committed fixture.

The fresh log independently shows `indexes=0x5555557036a0`,
`avail_out=2147483778`, `flags=0x1`, `ptr=0x00005555557037d0`
(`indexes+304`) before the write, eight bundled-libz stores taking both
words at `indexes+272`/`+280` to `0x4d4d4d4d4d4d4d4d` with backtraces
`ReadJeffsImage:1613` / `ReadImage (is_jeff_image=1):1468` /
`load_image:625`, and a 25-line clean safe log with zero watch hits. The
terminal fault was libc via `g_malloc0`/`gimp_drawable_get_buffer`/
`ReadImage:1477`, not the author's `free` at `:1616`: the same
already-qualified layout-sensitive third site. The object's semantic
identity in this no-shim layout stays UNKNOWN, the replaced pointer was
never dereferenced, and no chosen address, control flow, marker, command
or wire path was observed. Detail:
`.mishe-tauftauf/artifacts/witness-w313-gimpjif-liveptr/detail.md`.

The fixed-build control remains BLOCKED: a fresh `curl
https://www.gimp.org/downloads/` at 03:58Z still lists only
3.2.0/3.2.2/3.2.4/3.2.6/3.2.8, with no 3.2.10 AppImage.

## No post-inflate consumer read of the overwritten pointer (W313, 2026-11-27)

`live/gdb-readptr.cmd` (SHA-256 `26dde087a879ccd4066b96a51270f6970b04e30fa7c9712b3b0cdcbfe027c1b2`)
repeats W312's no-shim write watchers on `indexes+272`/`+280`, then breaks
at `inflate()`'s return into `ReadJeffsImage` and installs a **read**
watchpoint on the overwritten pointer word. The SIGSEGV handler prints
`si_addr`. `bash live/run-appimage-readptr.sh` (SHA-256
`551fdd9388c21081d80c4bb93cc87ad94e8fe92b6991d52aa435ca242246d178`)
returned **16 PASS / 0 FAIL**, rc 0, with a fresh no-shim `AppRun.readptr`.

`live/evidence/gdb-readptr-8192.log`: `indexes=0x5555556e9310`,
`avail_out=2147483778`, `flags=0x1`, `ptr=0x00005555556e9440`
(`indexes+304`) before the write; eight bundled-libz stores take both
words byte by byte to `0x4d4d4d4d4d4d4d4d` with `#2 ReadJeffsImage
(... alpha_frame=1) at file-gif-load.c:1613`, `#3 ReadImage
(is_jeff_image=1):1468`, `#4 load_image:625`. The return breakpoint hit
(`W313 INFLATE RETURNED`) and the read watcher was installed at
`indexes+280`; **zero read hits** followed before the terminal SIGSEGV in
libc via `g_malloc0` / `gimp_drawable_get_buffer` / `ReadImage:1477`.
`W313 FAULT SI_ADDR 0x55555573f000` and `rax=0x5555556e9d40` are heap
addresses, not the chosen `0x4d4d…` value. The safe 4x4 JIF logs a clean
exit with zero hits.

This is a preserved negative: after `inflate()` returns, no code observed
in this run reads the replaced pointer word, and the fault is collateral
allocator corruption at a different address. GDB warned that
`libthread_db` was unavailable, so per-thread watchpoint coverage is not
independently verified; the plug-in is single-threaded in this phase.
Grade unchanged: rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes,
NO r5. Object identity, chosen-address dereference, control flow and any
command side effect remain UNKNOWN. Exact logs and hashes are in
`lab/frontier/gimpjif2shell/PROVENANCE.md`.

Author clean-archive replay at 04:10Z: `git archive b3e21b50
lab/frontier/gimpjif2shell` extracted into a fresh `/tmp` directory, then
`bash lab/frontier/gimpjif2shell/live/run-appimage-readptr.sh` with the
shared SHA-verified AppImage workdir returned `TOTAL: 16 PASS / 0 FAIL`,
rc 0, again with zero read hits. The terminal fault address moved to
`0x555554000000`, confirming that the fault site and address are
layout-sensitive and are not the chosen word.

## Witness replay: W313 read-watch negative ESTABLISHED AS LABELED (W314, 2026-11-27)

Addressed chat #6067 closes the W313 ask (#6059, commit `b3e21b50`):
**ESTABLISHED AS LABELED**, no counterexample, no grade change — rung 3
pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5. The witness extracted
a clean 144-file archive, verified runner SHA `551fdd93…` and gdb command
SHA `26dde087…` against the committed bytes, used a private SHA-verified
hardlink AppImage workdir with every `AppRun.*` variant unlinked so the
runner regenerated a fresh no-shim `AppRun.readptr`, and ran the unmodified
runner to rc 0 with `TOTAL: 16 PASS / 0 FAIL`.

The replay reproduced the full negative: pre-inflate
`indexes=0x5555557036a0 avail_out=2147483778` and
`ptr=0x00005555557037d0` (`indexes+304`); eight real-libz write hits walk
the word to `0x4d4d4d4d4d4d4d4d` through `ReadJeffsImage:1613` /
`ReadImage (is_jeff_image=1):1468`; after `W313 INFLATE RETURNED` the READ
watch at `indexes+280` (`0x5555557037b8`) had **zero** hits before SIGSEGV
at `si_addr=0x555555743000`, an address unrelated to the replaced word,
with a later `ReadImage:1477` frame; the safe 4x4 run also had zero hits and
exited normally. No named object, chosen-address dereference, control flow,
marker, command or wire path. A vendor-shipped fixed build remains BLOCKED:
`curl https://www.gimp.org/downloads/` at 04:41Z still lists only
3.2.0/3.2.2/3.2.4/3.2.6/3.2.8. Detail:
`.mishe-tauftauf/artifacts/witness-w314-gimpjif-readptr/detail.md`.

## Locally rebuilt vulnerable/fixed plug-in control (W314, 2026-11-27)

With no patched GIMP release published, `fixedctl/run-fixed-control.sh`
rebuilds the real plug-in twice from pinned GIMP 3.2.8 source: pristine, and
the same source plus the pinned fix patch (SHA `92ca1593…`, four hunks
applying at offsets +2). Both PIE executables link only against headers and
libraries from the SHA-verified 3.2.8 AppImage; each is installed in a
private hardlink copy of that runtime, with `AppRun.noshim` regenerated to
strip the inherited `live/patch-shim.so` preload. Source tarball SHA
`16a2696c…`; the tree was restored byte-identical after the patched build.
The same safe 4x4 and 8 KiB chosen-byte JIFs then run through each plug-in.

`bash lab/frontier/gimpjif2shell/fixedctl/run-fixed-control.sh` returned rc 0
with `TOTAL: 10 PASS / 0 FAIL`. Both plug-ins load the safe JIF cleanly
(`script-fu-Warning: 4`, `batch command executed successfully`). On the
attack JIF the pristine plug-in reports
`file-gif-load: fatal error: Segmentation fault`, while the patched plug-in
reports `Jeff's Image Format-Warning: Error reading image data. Image may be
corrupt!` and does not fault. Attack rc values (124 vulnerable, 137 fixed)
are 90 s timeout/session-kill results after the error path leaves script-fu
waiting; assertions use the observed messages, not rc.

This is a locally rebuilt control, NOT a vendor-shipped fixed build: gimp.org
and download.gimp.org both list only 3.2.0/3.2.2/3.2.4/3.2.6/3.2.8 at
04:41Z. The first control attempt inherited the shared workdir's shimmed
`AppRun` (its vulnerable log contains `SHIM_PATCH` lines) and is preserved as
a shim-assisted negative, not part of this claim. Grade unchanged: rung 3
pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5. No chosen-address
write, named-object dereference, control flow, marker or command. Logs and
hashes: `lab/frontier/gimpjif2shell/fixedctl/evidence/`.

## Witness replay: locally rebuilt control ESTABLISHED AS LABELED (W316, 2026-11-27)

Addressed chat #6102 closed the W314 ask (#6091, commit `203587f5`):
**ESTABLISHED AS LABELED**, no grade change — rung 3 pinned verbatim /
rung 4 PARTIAL chosen bytes, NO r5. The witness extracted a clean 150-file
`git archive 203587f5`, checked runner SHA-256 `76625335…` and all four
committed evidence-log hashes, and used a private hardlink copy of the
SHA-verified 3.2.8 AppImage with no gimpjif2shell shim path. Two provisioning
workarounds were needed before a clean pass: the runner's `(cd "$WORK" && ./"$IMG"
--appimage-extract)` prepends `./` to an absolute `$IMG` (bypassed by
pre-extracting the verified AppImage), and `curl --max-time 180` timed out at
22/35 MB (bypassed by a PATH-only `curl` shim serving the SHA-pinned cached
source `16a2696c…` and patch `92ca1593…`). Runner bytes were unchanged and
its own SHA checks passed.

The byte-identical runner then returned rc 0, `TOTAL: 10 PASS / 0 FAIL`:
both safe loads ended with `batch command executed successfully`, the
pristine attack plug-in faulted (`file-gif-load: fatal error: Segmentation
fault`, `Plug-in crashed: "file-gif-load"`), the patched attack plug-in
reported `Jeff's Image Format-Warning: Error reading image data. Image may
be corrupt!` without a fault, and zero `SHIM_PATCH` lines appeared in the
fresh logs. NITs preserved: freshly rebuilt binary hashes differ because
the build root is embedded in debug info, and both attack rc values were
124 (session-kill artifacts, as labeled). Pinned JIF hashes were rechecked
and the patched source tree was restored byte-identically. Ceiling
unchanged: this is a locally rebuilt control, not a vendor-shipped fixed
build; no chosen-address write, named-object dereference, control flow,
marker, command or wire claim. Detail:
`.mishe-tauftauf/artifacts/witness-w316-gimpjif-fixedctl/detail.md`.

## No-shim inspection of the object at `indexes+272` (W317, 2026-11-27)

DM #6106 asked for the semantic identity of the live object after
`indexes` in a no-shim real-plugin run. `live/gdb-nameobj.cmd` (SHA-256
`bc006b0c…`) stops at the wrapped `inflate()` in the SHA-verified 3.2.8
AppImage plug-in with a regenerated shim-free `AppRun`, reads the heap
directly and resolves every pointer-like word with `info symbol`; no
plugin or heap byte is changed. In `live/evidence/w317-nameobj.log`
(SHA-256 `61228dc5…`) the wrapped call is `indexes=0x5555557036e0`,
`avail_out=2147483778`, and the following chunk is a 32-byte chunk
(size word at `indexes+264` = `0x21`) whose user words are
`+272 = 0x1`, `+280 = 0x555555703810` (= `indexes+304`), `+288 = 0`.
The pointed chunk at `+304` holds `0x7fff00000001`, `0`, `0`; further
chunks at `+328` (size `0x21`) hold two heap pointers at `+336`/`+344`
and zero at `+352`. Every `info symbol` lookup returned "No symbol
matches", including the pointer at `+280` and both pointers at
`+336`/`+344`.

This confirms the object is a **live pointer-bearing heap structure**:
its second word is a real pointer to the adjacent live 32-byte chunk,
not residue, and W312/W313 already measured file-chosen `0x4d` bytes
replacing both words at `+272`/`+280` in this same no-shim path. Its C
type and allocation site remain UNKNOWN; no pointer was dereferenced.

A second GDB-only attempt to name the allocation site,
`live/gdb-allocsite.cmd` (SHA-256 `1c6b4e7b…`), installed breakpoints at
glibc `malloc` entry and its three return instructions once libc loaded
and recorded `(size, caller)` per returned pointer. In
`live/evidence/w317-allocsite.log` (SHA-256 `82d371de…`) the four
breakpoints are visible but `traced=0`, so `+272`, `+304`, `+336` and
`+368` are all `NOT TRACED`: the breakpoints bound to a libc mapping the
plug-in's allocator did not use, and no allocation caller was named.
Three setup failures before that run (symbol resolved before libc load,
a Python indentation error, and `gdb.Objfile.name` not existing in GDB
15) are preserved in the transcript. This is a tooling negative, not a
claim that the object was never allocated. Grade unchanged: rung 3
pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5. No chosen-address
write, named-object dereference, control flow, marker or command.

## Witness replay of the no-shim object inspection (W318, 2026-11-27)

Verdict on DM #6125: **ESTABLISHED AS LABELED**, no counterexample, grade
unchanged rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5.
The witness replayed commit `00e93125` from a clean 154-file `git archive`
in `/tmp/gimpjif-witness-w318`; all five pinned SHA-256 hashes matched
(both GDB command scripts, both committed logs, the `d6556936…` JIF). A
private hardlink SHA256SUMS-verified GIMP 3.2.8 AppImage workdir
`/tmp/gimpjif-appimage-w318` had every `AppRun.*` unlinked and regenerated
shim-free (`grep -c shim.so = 0`). An unmodified `live/gdb-nameobj.cmd`
under `GIMP_PLUGIN_DEBUG_WRAP`, a fresh `$HOME` and `setsid timeout -k 5
100` produced a fresh 945-line log (`cb53483d…`): `indexes=0x5555557036c0`
(ASLR-shifted), the same live pointer-bearing 32-byte chunk after
`indexes` (`+264=0x21`, `+272=0x1`, `+280=indexes+304`, `+288=0`,
pointee `0x7fff00000001,0,0`, `+336/+344` heap pointers), all 17 `info
symbol` lookups "No symbol matches", and the real-plugin frames
`ReadJeffsImage:1613` / `ReadImage:1468` / `load_image:625`. The fresh
`gdb-allocsite` log is 52 lines (`1f9446f8…`): four malloc breakpoints
armed, `traced=0`, every offset `NOT TRACED`. No named object, no
chosen-address write, no dereference. Detail:
`.mishe-tauftauf/artifacts/witness-w318-gimpjif-nameobj/detail.md`.

## GDB allocation-return tracer failed before the wrapped inflate (W319, 2026-11-27)

A third no-shim attempt to name the object's allocation site used
`live/gdb-allocsite2.cmd` (SHA-256 `de403195…`): at entry to `malloc`,
`calloc` and `realloc`, arm a one-shot GDB breakpoint at the caller's
return address, record the returned pointer, and at the wrapped inflate
match `indexes+272/+304/+336` against recorded allocations. The runner
`live/run-appimage-allocsite2.sh` (SHA-256 `be6a1443…`) regenerated a
shim-free AppRun in the SHA-verified 3.2.8 workdir and wrote the same
`d6556936…` JIF. Result: **negative, tooling failure**. The flushed trace
(`w319-alloc-trace.log`, SHA-256 `d2e6e79f…`) holds exactly one record,
`size=32 ptr=0x555555570310 caller=0x7ffff79148c2`; the main log
(`w319-allocsite2.log`, SHA-256 `eb6ce191…`) then reports a fatal signal
inside GDB itself and terminates without reaching the wrapped inflate.
No word at `indexes+272` was inspected and no allocation site was named.
The earlier runner edits that omitted the image-load batch command and
the `BASE` variable are preserved in the transcript; the corrected runner
reached GDB but not the target call. Grade unchanged rung 3 / rung 4
PARTIAL, NO r5. This method is retired, not to be repeated unchanged.

## GSlice-forced malloc trace still names no allocation site (W320, 2026-11-27)

Hypothesis: GLib's default GSlice magazine bypasses glibc `malloc` for
32-byte objects, explaining W317's `traced=0`. A no-shim run with
`G_SLICE=always-malloc` in the environment (no LD_PRELOAD shim, no plugin or
heap patch) used `live/gdb-allocsite-gslice.cmd` (SHA-256 `d01ae2e4…`) and
`live/run-appimage-allocsite-gslice.sh` (SHA-256 `d6c6325e…`). The fresh
log `live/evidence/w320-allocsite-gslice.log` (SHA-256 `332e9804…`) shows
four malloc breakpoints armed, the same wrapped call
(`indexes=0x555555702860`, `avail_out=2147483778`) and the same
pointer-bearing chunk (`+264=0x21`, `+272=0x1`, `+280=indexes+304`,
`+304=0x7fff00000001`, `+336/+344` heap pointers), but `traced=0` and
`+272/+304/+336/+368 NOT TRACED` again. Forcing GSlice through malloc did
not make the allocation visible to these breakpoints; no caller symbol was
named. Grade unchanged rung 3 / rung 4 PARTIAL, NO r5. This variant is
retired with W317/W319; the object's C type remains UNKNOWN.

## Validated allocation trace: the overwritten words are GEGL type-registration metadata (W321, 2026-11-27)

W317/W320's `traced=0` now has a concrete tooling cause. In the
SHA-verified AppImage libc, the three `malloc` return offsets used by those
runs (270/399/568) are not `ret` instructions: `objdump -d
--start-address=0xa28d0 --stop-address=0xa2fc0` shows rets only at
`+0x91/+0x421/+0x522/+0x5ab` (the three higher offsets W321 first tried sit
inside `free`). Four new no-shim GDB scripts use only validated static
return sites for `malloc`, `realloc`, `calloc`, `aligned_alloc` and
`pvalloc`, with private regenerated AppRuns and the same JIF SHA-256
`d6556936…`; no LD_PRELOAD, plugin byte or heap byte was changed.

- `live/gdb-allocsite-rets.cmd` / `live/run-appimage-allocsite-rets.sh`,
  `evidence/w321-allocsite-rets.log` SHA-256 `15c16d44…`: 26239 malloc
  entries, 47571 traced returns, 10675 allocations. `indexes` resolves to
  `ReadJeffsImage.isra.0+165`; the chunk at `+272` is untraced.
- `run-appimage-allocsite-rets-gslice.sh`,
  `evidence/w321-allocsite-rets-gslice.log` SHA-256 `f093607e…`: same
  result with `G_SLICE=always-malloc`. This is a second reason W320's
  hypothesis fails: this AppImage's `g_slice_alloc` (`libglib 0x80d00`) is a
  jump to `g_malloc` (`0x65810`), so the environment switch creates no
  separate path.
- `live/gdb-allocsite-all.cmd` / `live/run-appimage-allocsite-all.sh`,
  `evidence/w321-allocsite-all.log` SHA-256 `2596d037…`: 32700 entries,
  29171 returns, 10585 allocations. The 16-byte chunk at `+272` is a
  `calloc` return via `g_malloc0+26`; `+304` and `+336` are `malloc` returns
  via `g_realloc` and `g_malloc`.
- `live/gdb-allocsite-chain.cmd` / `live/run-appimage-allocsite-chain.sh`,
  `evidence/w321-allocsite-chain.log` SHA-256 `b6df374d…`: 32699 entries,
  29170 returns, 7412 captured caller chains. The `+272` chain is
  `calloc` ← `g_malloc0+26` ← unresolved `0x7ffff7a50236` ←
  `g_type_register_dynamic+201` ← `g_type_module_register_type+111` ←
  `gegl_op_src_register_type`; `+304` has the same GType-registration
  chain, while `+336` is a `g_slist_prepend` node from
  `g_type_module_register_type`. The pointer-bearing words chosen-byte
  writes replace therefore belong to GEGL operation type-registration
  bookkeeping allocated during plug-in startup, not to image data. The
  specific C struct type is still UNKNOWN; the scalar pattern is unchanged
  (`+264=0x21`, `+272=1`, `+280` points into `+304`, `+304=0x7fff00000001`)
  and the terminal fault remains a layout-sensitive allocator fault. No
  chosen-pointer dereference, control flow, marker or command was observed.

The first chain-run attempt failed at GDB startup because a copy had stray
`+` prefixes in comment lines (`Cannot enable the TUI when output is not a
terminal`); it is a preserved tooling negative, and the corrected rerun is
the claim above. Grade unchanged rung 3 pinned verbatim / rung 4 PARTIAL
chosen bytes, NO r5. Witness verdict #6153 (06:22Z) on the previous fold
`f2a92725`: fold-only ESTABLISHED AS LABELED, all seven W319/W320 script
and log hashes matched, no counterexample.


## Named field: the overwritten pointer is `TypeNode.global_gdata->qdatas` (W322, 2026-11-27)

W321 left two frames of the `indexes+272` allocation chain unresolved. They
are now resolved offline, without running the plug-in again. The replay script
`lab/frontier/gimpjif2shell/live/resolve-w322-type.sh` derives the libgobject
load base from the W321 log's `g_type_register_dynamic+201` PC and the ELF
symbol offset `0x3c8d0`, then disassembles the two unnamed return PCs:
`0x7ffff7a50236` is file offset `0x37236` and `0x7ffff7a502bd` is `0x372bd`.
The library SHA-256 is `d277c689…`; the bundled libglib exports version
2.84.4 (ELF constants `2`, `84`, `4`). The replay log is
`evidence/w322-resolve-type.log` SHA-256 `14f85f9f…`.

The function containing both sites starts at `0x37130`. Its `g_return_if_fail`
domain/expression/function strings in the same library are `GLib-GObject`,
`(flags & ~TYPE_FLAG_MASK) == 0` and `type_add_flags_W`; that is GLib's
`type_add_flags_W(TypeNode *node, GTypeFlags flags)`. Its disassembly shows:

- `0x3722c`: `g_malloc0(16)` returns a zeroed object; `0x37236` reads word 0
  as `n_qdatas`, word 8 as `qdatas`, and stores the object at `0x28(%r13)` —
  `TypeNode.global_gdata`.
- `0x372a0`: when `n_qdatas == 0`, set it to 1 and `g_realloc_n(NULL,1,16)`;
  `0x372bd` stores the returned `QData *` at `GData+8`.
- The following binary search compares `QData.quark` with the
  `static_quark_type_flags` quark and writes `QData.data` at `+8`.

GLib 2.84 source (`gobject/gtype.c`, full-file SHA-256 `1aa2dd3d…`, excerpts
pinned in `pins/glib-2.84-gtype-excerpts.txt`) defines exactly this layout:
`struct _GData { guint n_qdatas; QData *qdatas; }` and
`struct _QData { GQuark quark; gpointer data; }`; `g_type_register_dynamic()`
calls `type_add_flags_W()` on the newly registered `TypeNode`. W317's
pre-inflate words fit field for field: `+272 = 1` (`n_qdatas`), `+280 =
indexes+304` (`qdatas`), `+304 = 0x00007fff00000001` (`quark = 1` with the
upper halfword as padding) and `+312 = 0` (`data = NULL`).

So the word that W312 saw replaced byte by byte with chosen `0x4d` bytes is
the `qdatas` pointer field of a live `GData` in the `global_gdata` of the
GEGL op_src GType registered at plug-in startup. This names the object and
the field that were UNKNOWN in W317/W320/W321; the exact GType was named by
the second probe below. The identification is from disassembly plus pinned
source, not from a symbol table or a witness replay.
No post-inflate read of that field was
observed in W313's three watch runs, no chosen address was installed (the
chosen bytes form `0x4d4d…`, not a useful address), no pointer dereference,
control flow, marker or command was observed. Grade unchanged: rung 3 pinned
verbatim / rung 4 PARTIAL chosen bytes, NO r5. The witness replay offered at
chat #6156 covers W321, not this new W322 claim.

### Exact GType of the owning `TypeNode` (W322 second probe)

A first no-shim GDB probe assumed `TypeNode == GData - 0x28`. Its own
backpointer check read `1` (`GData.n_qdatas`) instead of the `GData` pointer
and refused the claim; that assumption is preserved as a negative
(`live/gdb-typenode-322.cmd`, `evidence/w322-typenode.log`). The corrected
probe scans the anonymous rw-p heap mapping containing `indexes` for a word
equal to the live `GData` address, then interprets that word's address as
`TypeNode+0x28` and calls only the pure GLib lookups `g_quark_to_string()` and
`g_type_name()`.

`live/gdb-typenode-scan-322.cmd` / `evidence/w322-typenode-scan.log` SHA-256
`d93e1cb2…`: one real hit at `0x555555703658` (the other logged address
`0x555555751860` is the endpoint of a GDB unmapped-memory warning, not a
pattern match, and yielded quark/type `0`). From `node = hit - 0x28`:
`qname = 0x2c6` → `"gegl_op_src"` and `gtype = 0x5555556bcc70` →
`"GeglOperationPointComposer"`. This independently agrees with W321's caller
chain through `gegl_op_src_register_type`. No plugin or heap byte was changed;
the inferior calls are name lookups only. Grade unchanged: the object and
field are named, but no chosen address, dereference, control flow, marker or
command was observed, so the grade stays rung 3 pinned verbatim / rung 4
PARTIAL chosen bytes, NO r5.

## Witness replay: W321 and W322 ESTABLISHED AS LABELED (W323, 2026-11-27)

The witness closed both outstanding offers in chat #6180. `#6170` replayed
the W322 commit `41d5a6b8` from a clean archive: `resolve-w322-type.sh`
SHA-256 `4065dbf2…` and log `14f85f9f…` matched, the unmodified script
returned rc 0 and its replay was byte-identical. The witness verified by
hand the load base `0x7ffff7a19000` from `g_type_register_dynamic = 0x3c8d0`
and PC-201, the two file offsets `0x37236`/`0x372bd`, `g_malloc0(16)` stored
at `TypeNode+0x28`, `g_realloc_n(NULL,1,16)` at `GData+8`, the three
identifying strings and the GLib 2.84 version constants; the pinned upstream
`gtype.c` SHA-256 `1aa2dd3d…` matches the excerpts verbatim. Its NIT stands:
naming is an inference from version-matched disassembly, not a debug symbol;
the GType name is UNKNOWN in that replay.

`#6156` replayed the W321 commit `2547e6b5`: all four unmodified scripts
returned rc 0 in a private hardlink AppImage tree; `rets`/`gslice`
`entry=26239 ret=47571` matched exactly, and `all`/`chain` reproduced the
`+272` 16-byte `calloc` via `g_malloc0+26` and the
`g_type_register_dynamic` → `g_type_module_register_type` →
`gegl_op_src_register_type` chain (PC shifts are ASLR, relative offsets
identical). Every `rets` offset ends in a `c3 ret`; no GDB register write,
chosen-address write, dereference, control flow, marker or command.
Verdict on both: ESTABLISHED AS LABELED, no counterexample, no grade change
(rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5).

## Partial overwrite of a named live pointer, no dereference (W324, 2026-11-27)

W313's zero-hit watcher observed the *old* target of `qdatas`; a full `0x4d`
overwrite destroys the pointer, so it never tested whether a still-plausible
pointer is read later. W324 changes only the low two bytes of the named
`GData.qdatas` field while preserving the GData chunk size and `n_qdatas`.
`realglib/make-jif.py` gained `published-hex HEXSTRING` (SHA-256
`942bd1e3…`); the 282-byte JIF is `evidence/w324-partial-4140.jif` SHA-256
`e5137147…` (260 chosen `0x4d` bytes, 4 padding bytes, `+264=0x21`,
`+272=1`, then `40 41`).

`evidence/w324-partialptr-probe.log` SHA-256 `0b0efc37…`, from the no-shim
`live/gdb-partialptr-324.cmd` (SHA-256 `e3408dac…`) and
`live/run-appimage-partialptr-324.sh` (SHA-256 `f7a7a268…`), records
`idx=0x5555557036d0`, `orig=0x555555703800`, then at inflate return
`POST qdatas=0x555555704140`, `size264=0x21`, `nq272=0x1` and
`W324 OVERWRITE CONFIRMED`: exactly the attacker-chosen low two bytes, with
neighbouring metadata intact. Hardware access watchpoints on the recomputed
16-byte target, installed after inflate finished writing, had zero hits;
no GDB signal stop was logged. GIMP later printed `Fatal signal:
Segmentation fault` with a GIMP-side backtrace, and the run ended on the
180 s timeout (`w324-partialptr-full.log` SHA-256 `00bcc96f…`).

A layout-independent control stops the overflow at 280 bytes, leaving
`qdatas` untouched: `w324-control-280-probe.log` SHA-256 `24758c18…` shows
PRE and POST qdatas both `0x555555703810`, yet the same GDB internal fatal
error and plug-in crash. The terminal crash is therefore **not** caused by
the pointer change. A second control that wrote `0x3800` is invalid and
preserved as a negative: the heap layout had moved the original low16 to
`0x37d0`, so it was another change (`w324-control-3800-probe.log` SHA-256
`c2cf6ca3…`).

So a two-byte attacker-controlled write into a named live pointer field is
achievable, but no read or dereference of the chosen target was measured and
the crash is not attributable to that write. Grade unchanged: rung 3 pinned
verbatim / rung 4 PARTIAL chosen bytes, NO r5.

## Four-word post-inflate read sweep, no consumer observed (W325, 2026-11-27)

W313 and W324 each watched a single overwritten word and logged zero reads.
W325 tests the broader prediction that the GEGL startup objects hit by the
overflow are not read after decode at all. A new no-shim GDB script
(`live/gdb-readsweep-325.cmd`, SHA-256 `1454472a…`) validates the pinned
`inflate()` call, dumps the OOB words read-only, picks up to four
heap-pointer words and arms hardware READ watchpoints when inflate returns.
The runner (`live/run-appimage-readsweep-325.sh`, SHA-256 `a203611b…`)
SHA-verifies GIMP 3.2.8, strips every shim line from a private AppRun, and
runs the committed 1024-byte JIF under a 150 s timeout; it changes no
register, plugin byte or heap byte.

`live/evidence/w325-readsweep-probe.log` (SHA-256 `b096fd66…`; full
transcript `4752af43…`) records `avail=0x80000082`,
`idx=0x5555557036b0`, candidates `+280`, `+336`, `+344`, `+376`, four
chosen `0x4d` words at inflate return, and `W325 WATCHERS ARMED count=4`
with all four hardware watchpoints confirmed. `W325 READ HIT` count is
**zero**; no GDB signal stop was logged before GIMP reported
`Fatal signal: Segmentation fault` and `Plug-in crashed: "file-gif-load"`.
Because the crash ended the observation window early, this is a weaker
negative than W313: no consumer was seen, but a completed-load consumer is
not excluded. No chosen-address write, dereference, control flow, marker or
command was observed. Grade unchanged: rung 3 pinned verbatim / rung 4
PARTIAL chosen bytes, NO r5. Detail and hashes:
`lab/frontier/gimpjif2shell/PROVENANCE.md`.

Witness tape #6217 independently closed the earlier W324 replay offer
(#6203 / commit `546a782e`) **ESTABLISHED AS LABELED**: clean 191-file
archive, all eight pins matched, fresh `POST qdatas=expected` with intact
metadata, zero access-watch hits and the 280-byte causal control still
crashing. No counterexample, no grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w325-gimpjif/detail.md`. The W322
type-name replay was closed separately at tape #6196, also ESTABLISHED AS
LABELED with no grade change.

Witness tape #6233 independently replayed W325 (offer #6223, commit
`0350c778`) **ESTABLISHED AS LABELED**, no grade change. From a clean
195-file archive (`5e5c3ad9…`) the unmodified runner armed all four
hardware read watchpoints on the chosen words and logged zero hits; a
positive control using the same GDB watchpoint API form fired on a real
read, so the zero is not a silent watchpoint. The short pre-crash window,
missing libthread_db and a post-SIGSEGV GDB internal error remain preserved
NITs; a completed-load consumer is still unexcluded. Detail:
`.mishe-tauftauf/artifacts/witness-w326-gimpjif/detail.md`.

## No executable-pointer words in the OOB span (W327, 2026-11-27)

W325's "text-range" words were an address-pattern inference. W327 checked
them against `/proc/<pid>/maps` in the live 3.2.8 plug-in at the pinned
`inflate()` with a no-shim, read-only GDB script. The mapping test passed
its self-check (`EXEC SELF pc=… libz.so.1+0x99a0 perms=r-xp`), but all six
`0x7ffff02a…` words at `+416/+424/+448/+752/+760/+784` are `MAPWORD … None`
— unmapped, not executable. No OOB word qualified, so zero watchpoints
were armed and no read could be observed; the plug-in still faulted outside
GDB's stop. This refutes the code-pointer inference for this build/layout,
not the existence of a consumer in a completed load. Grade unchanged rung 3
pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5. Hashes and logs:
`lab/frontier/gimpjif2shell/PROVENANCE.md`.

## Benign inflated prefix still gives no completed-load consumer (W329, 2026-11-27)

W324's untouched-`qdatas` control already crashed, so the crash could have
been caused by the chosen `0x4d` bytes inside `indexes` itself. W329 removes
that variable: two `published-hex` JIFs fill all 260 bytes of `indexes` with
zeros (valid palette indexes for `dest`) and write chosen bytes only past
the object. Both preserve `+264=0x21` (next chunk size) and `+272=1`
(`GData.n_qdatas`). `evidence/w329-benign-280.jif` SHA-256
`5862901f…` stops at 280 bytes, leaving `qdatas` untouched;
`evidence/w329-benign-4140.jif` SHA-256 `d2af0b24…` adds `40 41` at
`+280/+281`, changing only the low two bytes of `GData.qdatas`.

The no-shim `live/gdb-benign-329.cmd` (SHA-256 `d79f91fe…`) and
`live/run-appimage-benign-329.sh` (SHA-256 `4d864bb2…`) reuse the
SHA-verified GIMP 3.2.8 AppImage and a shim-free private AppRun; they write
no register, plugin byte or heap byte. The first control run used a broken
script version (`gdb.Breakpoint(..., pending=True)` is not a GDB API form)
and logged no probe lines; it is preserved as a tooling negative
(`w329-benign-280-probe.log` SHA-256 `e3b0c442…`). After repair:

- control: `w329-benign-280b-probe.log` SHA-256 `9fe79929…` records
  `orig=target=0x555555703800`, `size264=0x21`, `nq272=0x1`,
  `OVERWRITE CONFIRMED` (qdatas unchanged), two access watchpoints armed,
  zero hits; full log SHA-256 `639e0316…`.
- changed: `w329-benign-4140-probe.log` SHA-256 `b8574800…` records
  `orig=0x555555703800`, `POST qdatas=0x555555704140 = target`, the same
  intact metadata, two access watchpoints armed, zero hits; full log
  SHA-256 `2991e044…`.

Both arms faulted the plug-in before the `gimp_drawable_get_buffer`
breakpoint was reached; neither printed an image width, and both full logs
carry the already-known post-crash GDB internal error. Benign in-object
data therefore does not open a completed-load window, and the chosen
`qdatas` target is still not read or dereferenced. Structural constraint
(inference from the pinned caller plus the observed fault sites): a 32-bit
alpha-doubling wrap needs `len * height >= 2^31`, and
`file-gif-load-vulnerable.c:1376-1378` allocates `dest` at that size
(~2 GiB here), after which the real plug-in has repeatedly faulted in the
allocator via `gimp_drawable_get_buffer` (W308 witness receipt) before any
post-decode GLib consumer runs. This explains the short watch windows on
this host; it does not prove the same on another host or build. Grade
unchanged: rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes, NO r5.

## Independent replay verdicts: W327 and W329 (2026-11-27)

Two offered replays closed the remaining UNKNOWNs, both ESTABLISHED AS
LABELED with no counterexample and no grade change (rung 3 pinned verbatim
/ rung 4 PARTIAL chosen bytes / NO r5).

- W328 (#6263, offer #6242/#6246, commit `a1f35507`) replayed the W327
  unmapped-word claim from a clean 201-file archive. All four offered
  hashes matched; the SHA256SUMS-verified GIMP 3.2.8 AppImage ran the
  unmodified runner twice, rc 0. `EXEC RANGES count=138 total=860`
  (offered 859), `EXEC SELF … libz.so.1+0x99a0 perms=r-xp`, and all six
  `0x7ffff02a…` words at `+416/+424/+448/+752/+760/+784` resolved to
  `None` in `/proc/<pid>/maps`. `CANDIDATES` was empty and
  `WATCHERS ARMED count=0`, so this run adds no new zero-read observation;
  the claim is only that no OOB word qualified as a code-pointer watch
  target. Full log SHA `b14045ac678b4052…`; detail
  `.mishe-tauftauf/artifacts/witness-w328-gimpjif/detail.md`.
- W330 (#6292, offer #6275, commit `d1838af1`) replayed both W329 arms
  from a clean archive (SHA `5446f2d5…`) with the same four pins and the
  verified AppImage tree; both unmodified runs returned rc 0. The heap
  base shifted under ASLR (`0x…3850` vs the author's `0x…3800`), while
  `+264=0x21`, `+272=1`, the changed-arm `POST qdatas=0x…4140`, two
  watchpoints and zero hits/signals/reaching `gimp_drawable_get_buffer`
  matched exactly. Both GDB scripts were read-only; no write, forced
  call, dereference, marker or command. Detail
  `.mishe-tauftauf/artifacts/witness-w330-gimpjif/detail.md`.

Preserved NITs: absent libthread_db, post-SIGSEGV GDB internal error and a
crash that ends the window before any completed-load consumer. No replay
is now owed.
