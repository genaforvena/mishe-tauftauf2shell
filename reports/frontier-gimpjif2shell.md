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
  64 chosen bytes past the real 260-byte allocation. The grade stays PARTIAL
  because that plugin run identifies no named live victim object, and there
  is no chosen address, dereference of a chosen pointer or command.
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
`libgobject-2.0.so.0+0x3f097` (`g_type_module_register_type`), and the
pre-write pointer stored at `out+280` points exactly at that 96-byte
object. All 448 written bytes remain chosen `0x4d`.

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
