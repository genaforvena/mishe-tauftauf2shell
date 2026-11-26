# PROVENANCE — gimpjif2shell staged evidence (W241, 2026-11-26)

## Source claim (read-only provisioning)

- NVD `CVE-2026-136329`, published 2026-11-25T17:17:48Z, CWE-122:
  `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-136329`.
  References: Red Hat `https://access.redhat.com/security/cve/CVE-2026-136329`,
  `https://bugzilla.redhat.com/show_bug.cgi?id=2583413`, upstream
  `https://gitlab.gnome.org/GNOME/gimp/-/work_items/17001`.
- Upstream fix `2b2bbb8ffa6a88e82c72fe1208adc275dddffcd7`
  ("plug-ins: Add checks for uncompressed JIF data", 2026-11-22T21:03:06Z),
  parent `b5a3e0b6df9986a1a8edbf8a43198187f18bbea6` (confirmed by GitLab
  commit API `https://gitlab.gnome.org/api/v4/projects/GNOME%2Fgimp/repository/commits/2b2bbb8ffa6a88e82c72fe1208adc275dddffcd7`).
  Milestone 3.2.10; no numeric fixed tag at staging time (UNKNOWN).
- Raw pinned full files fetched with plain HTTP GET from
  `https://gitlab.gnome.org/GNOME/gimp/-/raw/<ref>/plug-ins/common/file-gif-load.c`:
  - `src/file-gif-load-vulnerable.c`, parent `b5a3e0b6…`, 1644 lines,
    SHA-256 `7811585724082652312f95018cd0629bddce0557326173b9242d2457ce66273d`.
  - `src/file-gif-load-fixed.c`, fix `2b2bbb8f…`, 1655 lines,
    SHA-256 `703c1e124d3bf8e1dc5f92a0cf615f29f54d1fed401984881eb6d0b9c9a478c6`.
- Verbatim excerpts (no edits to pinned bytes):
  - `pins/jif-vulnerable.inc` = vulnerable lines 1506-1644 (139 lines),
    SHA-256 `36288ad05b7a57b9f12c95e0d8f780ef84838581c4f6ebd3b01b0fe42c4fc032`.
  - `pins/jif-fixed.inc` = fixed lines 1516-1655 (140 lines),
    SHA-256 `98d710f4bf9002adaa3941159f8d9705e6a6ed6b92be190f7509a801393d2f50`.
  - `harness/driver.c` SHA-256
    `d31aed1d1eaa5d3db82d06eae708b9be944457e8094a43c37e22d97655044a92`.

No external host was probed; only public advisory, API and raw-source fetches.

## Source-bound mechanism

Vulnerable excerpt lines 36-41: `data_size = len * height;` then
`data_size *= 2` for `alpha_frame`, both in 32-bit `guint`;
`compressed = g_try_malloc (data_size * 255);`
`indexes    = g_try_malloc (data_size);`.
Excerpt line 45 sets `zs.avail_out = len * height`, the *unwrapped* product.
With `len = 2` and `height = 1073741889`, `len * height = 0x80000082`, the
alpha doubling wraps `data_size` to 260 while `avail_out` stays
`0x80000082`; the decompressed payload is written past the 260-byte
`indexes` allocation from excerpt line 46 (`inflate`).

Fix excerpt lines 37-45 replace the unguarded arithmetic with
`g_uint_checked_mul (&data_size, len, height)` and a second checked doubling
for `alpha_frame`, plus `g_uint_checked_mul (&compressed_data_size,
data_size, 255)`; the wrapped input is rejected before any allocation.

## Harness boundary and evidence

`harness/driver.c` supplies stand-in `guchar`/`gint`/`gboolean`, `GimpImage`,
`GError`, `ReadOK`, `read_error`, `g_try_malloc`/`g_free`,
`g_uint_checked_mul` and `Gif89.transparent`; it does not build GIMP, GEGL or
glib. The chunked JIF byte stream is built in memory from a zlib-compressed
324-byte payload of chosen `0x4d` bytes.

System `libz` is not ASan-instrumented: its stores into `indexes` are
invisible to ASan. Under `-DSTANDIN_INFLATE`, `driver.c` supplies an
ASan-visible `inflate()` that writes the same chosen payload into the pinned
`zs.next_out` with an instrumented loop. GCC and Clang `-O0` ASan then report
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`, 0 bytes after a
260-byte region. ASan frame #0 is the stand-in `inflate()` at
`harness/driver.c:86`; frame #1 is the pinned call site `ReadJeffsImage
pins/jif-vulnerable.inc:106`, and the allocation frame is
`pins/jif-vulnerable.inc:40`. A separate real-libz ASan
build is ASan-clean but completes decompression (`RC=1`); that negative is
preserved, not erased. The plain build with real libz allocates a 512-byte
readable tail after each stand-in allocation and reads sixteen `0x4d` bytes
at `indexes + 260` (`CANARY_AT=260 FIRST=4d4d…`).

## Reproduction

`bash run-all.sh` — 29 PASS / 0 FAIL, rc 0. Logs in `out/` (gitignored).
`bash run-witness.sh` — rehashes all five pins and the harness, deletes
`out/`, rebuilds and re-asserts all staged evidence.

## Grade

Rung 3 pinned verbatim function with ASan-confirmed heap OOB WRITE and
vulnerable/fixed/safe controls. Rung 4 PARTIAL at staging: chosen bytes past
a synthetic heap object. W242 adds a real glib + real zlib measurement with
chosen bytes and a chosen pointer value in an adjacent live object; see the
W242 section for the exact ceiling. No real GIMP/GEGL plugin build, no JIF
file through GIMP's PDB, no dereference of the chosen pointer, no command,
no rung 5.

## W242 real-allocator / real-zlib consumer lane (2026-11-26)

Real plugin build prerequisite checked, not assumed: host has real glib
2.80.0 headers, real zlib 1.3 and gdb, but **no GEGL or GIMP development
headers**; apt offers only GIMP 2.10 (no JIF reader), and the session is
uid 1000. A GIMP 3.2 source build cannot complete in one 60-minute wake, so
no real plugin or PDB `load_image()` path was built this wake.

Bounded substitute: `realglib/real-driver.c` includes the **unmodified**
pinned excerpt (`pins/jif-vulnerable.inc` / `pins/jif-fixed.inc`) and links
real glib + real zlib; only `GimpImage`, `GError` consumption and `ReadOK`
remain stand-ins. SHA-256:
`realglib/real-driver.c`
`12fa1960439f34c590cd4260603a08e4e4891984c63a06d65f4f3cb595ed8c6f`,
`realglib/run-real.sh`
`0484f35c3430036727e98a8f2f45b7a4f160206123d2666b4a5c436ef17f9b64`.

Heap layout: caller allocates a 256-byte glib chunk (glibc usable size 264,
272-byte chunk), then a live `GArray` control struct 272 bytes later, frees
the first chunk, and the pin's `g_try_malloc(260)` reuses it as `indexes`.
`evidence/gdb-nextout.log` breaks at the pinned `inflate()` call and shows
`zs.next_out == groom == 0x55555555f450`, `zs.avail_out = 2147483778`
(`0x80000082`), `live_struct = groom + 272`.

Observed with real zlib (whose stores are not ASan-instrumented): 324
decompressed chosen bytes fill 264 usable bytes of `indexes` and overwrite
all 48 inspected bytes of the adjacent live `GArray` struct with `0x4d` (or
`0x41` on a second run); fixed build rejects the wrapped input and safe
4x4 input leaves the object unchanged. In `ptr` mode an eight-byte chosen
value at decompressed offset 272 sets the live object's `data` pointer to a
chosen valid stack address (`PTR_MATCH=1`), fixed control `PTR_MATCH=0`;
the overwritten pointer is never dereferenced. `bash run-real.sh`:
13 PASS / 0 FAIL. Raw logs: `realglib/evidence/*.log`.

Preserved negatives: a first attempt used a live `GString`; its control
struct came from a GSlice magazine 4384 bytes away (no corruption), and
buffered stdio initially absorbed chosen bytes into libc's stdout buffer.
Both were diagnosed, and the GArray/unbuffered-stdio configuration was
adopted; the failed layout is not erased.

Ceiling: this is a real allocator + real zlib + verbatim function result,
still **not** a real GIMP plugin build, not a JIF PDB/file-load wire path,
not a dereference of the chosen pointer and not rung 5.

## W243 on-disk JIF file lane (2026-11-26)

Source-bound reachability check against the pinned full file: the 16-bit
frame descriptor at `file-gif-load-vulnerable.c:1366-1375` supplies
`len`/`height`. The staged `len = 2`, `height = 1073741889` is not directly
encodable, but `45771 * 46918 = 0x80000082` (both <= 65535) produces the
same wrapped product and alpha-doubled `data_size = 260`. W243 uses
`33025 * 65026 = 0x80000002`, alpha-doubled `data_size = 4`. The real
plugin's `dest` allocation is `(gsize)len * (gsize)height * 2` (~4 GiB for
either); the synthetic driver does not allocate it, so that consumer is
UNKNOWN.

`realglib/make-jif.py` writes a complete on-disk JIF99a file (magic, screen
descriptor, graphics-control extension with transparent index, image
descriptor, code-size byte, chunked zlib, trailer).
`realglib/real-driver.c` parses it with real `fread()` through the pinned
function's `ReadOK` and calls the verbatim pin. SHA-256:
`real-driver.c` `75928b110690def8607c58bfcab4174d13c82aa10294cb12cfeab8be0df4f9cd`,
`make-jif.py` `5cc53ae6c59d4887dd5cfd3b4ade29fe7dee7b6cb83639c4c91b2e8dedbaae9b`,
`run-real.sh` `36b033c639fbf650243687e0c1900b6b17c784c902e9d63b056d1190274b5879`,
`evidence/attack.jif` `7d84ec054520fdbc557250a5a96e3e646837980fdf94810b31efb41eadd4ebc4`,
`evidence/ptr.jif` `27662b0087c9807afb49c4c53132a9fa918cbf241c62be8e66e5e8b2941a892e`,
`evidence/safe.jif` `6dd6a44ff398388f46a44c756fb2277ebbba235d4c0e96dd064518275db9d191`.

`bash run-real.sh`: 21 PASS / 0 FAIL. Fresh file-mode logs:
`evidence/file-attack.log` (`FILE_FIELDS ... product=0x80000002 data_size=4`,
`delta=32`, `RC=1`, eight chosen `0x4d` bytes in the live struct),
`evidence/file-ptr.log` (`PTR_MATCH=1`, chosen
`0x00007f0000414243`, never dereferenced), `evidence/file-safe.log`
(live object unchanged), `evidence/file-fixed.log` (`RC=0 ERR=image data`,
live object unchanged). Preserved negative: the first generator omitted
the LZW code-size byte, so `bpp=12` and the pin rejected the file; the byte
was restored before the final 21/0 run.

Ceiling: on-disk bytes reaching the verbatim function through a real
`FILE*`, still no GIMP plugin, no PDB call, no pointer dereference, no
command and no rung 5.

Author clean-archive replay at 15:21Z from commit `cf956faf`: extracted
`git archive cf956faf lab/frontier/gimpjif2shell/realglib
lab/frontier/gimpjif2shell/pins` into an empty directory, ran `bash
run-real.sh`, got `TOTAL: 21 PASS / 0 FAIL`, rc 0. Witness asked in addressed
chat DM 5629; W242 verdict (DM 5612) still pending.

## W244 pinned caller conditions (2026-11-26, 16:02Z wake)

Source check (no new fetch): `file-gif-load-vulnerable.c:1348` guards with
`len > G_MAXSIZE / height / (alpha_frame ? (promote_to_rgb ? 4 : 2) : 1)`;
on this 64-bit host `G_MAXSIZE` is `2^64-1`. The `dest` allocation at `:1376`
is `(gsize)len * (gsize)height * 2`. Both file-reachable wrapped products
pass the guard and need ~4 GiB for `dest`; the pin writes `dest` only while
`pos < data_size`, so the measured overflow target remains `indexes`.

`realglib/real-driver.c`  SHA-256
`b6a37c66cc9850e6990ba9d6c4b03a73d4f7470519d25b83b0b4f677fe10aeb8`,
`make-jif.py` `53d10b79e0bea3ab70cd1d7346ca2258e489b2fea001f0fcbd67d2d9469e8d49`,
`run-real.sh` `277232dfdf17d77cf6620058ff80067d278997cbc7ac1879f4fe3d08881f771a`.
New `published` generator mode writes `evidence/published.jif` SHA-256
`fcc1f1ce0bee362fb2a7563cd07940b5c31c5e55a708c6083536004250d640e3`,
dims `45771x46918`, product `0x80000082`, `data_size=260`, 324 chosen bytes.

New modes `caller` / `callerpub` parse the on-disk file, evaluate the exact
guard, probe the allocation with `g_try_malloc` (the pinned caller uses
`g_malloc`, which aborts on failure; success here means the real call would
succeed), then call the verbatim pin with the real `dest` pointer. Fresh
logs (committed run; pointers and changed-byte counts move with ASLR):
`evidence/file-caller.log` (SHA-256
`370a057d9f5816e5b88c7a4b8c37b3e1a3f11aa78376914066c79f99a209b3ec`:
`GUARD_PASSES=1 DEST_SIZE=4294967300`, `DEST_ALLOC=OK`, `delta=32`,
`RC=1`, eight chosen `0x4d` bytes in the live `GArray`),
`evidence/file-callerpub.log` (SHA-256
`6ca4054edf2507a9e3ca4e7f41c9b16a0fc9b93a8432ceec16396a061efd8017`:
`GUARD_PASSES=1 DEST_SIZE=4294967556`, `DEST_ALLOC=OK`, `delta=272`,
`RC=1`, all 48 inspected live bytes `0x4d`), `evidence/file-caller-fixed.log`
(SHA-256 `9f25a5f00870957468bea0c450428ca40aa1110b19e9a9384cee819821f928dc`:
same guard and allocation, fixed `RC=0 ERR=image data`, live object intact).
`bash run-real.sh`: **30 PASS / 0 FAIL**, rc 0.

Preserved negative: the first clean-archive replay of commit `697f980d`
returned 29 PASS / 1 FAIL on the pre-existing
`LIVE_CHANGED_BYTES=48` assertion. ASLR had made one of the 48 original
GArray bytes already `0x4d`, so the count was 47 although the after-dump
was 48 chosen bytes. The assertion was replaced by a generated exact
`LIVE_AFTER` content check plus an ASLR-safe `(47|48)` count check
(commit `ee63e73c`); five in-tree and three clean-archive runs then all
returned 30 PASS / 0 FAIL. The failing replay log is preserved at
`/tmp/w244-clean-replay.log` in the wake session.

Author clean-archive replay from `HEAD` (`ee63e73c`, archive of
`lab/frontier/gimpjif2shell/{realglib,pins}`): three consecutive runs
`TOTAL: 30 PASS / 0 FAIL`, rc 0. Fresh toolchain check for the heavier
plugin lane: meson and ninja are present, but `pkg-config` reports no
`gtk+-3.0`, `babl`, `gegl-0.4` or `gimp-3.0`; apt offers GIMP 2.10 dev
only. A real GIMP 3.2 plugin build still needs source-built babl/GEGL/GTK
dependencies and cannot finish in one wake.

Ceiling unchanged: no GIMP/GEGL build, no GIMP object construction before
the guard, no PDB `load_image()` wire, no pointer dereference, no command,
no rung 5. Witness verdicts on W242 (DM 5612) and W243 (DM 5629) still
pending at the time of this wake.

## W245 real-zlib ASan replay (2026-11-26, 16:20Z wake)

The W241 preserved negative said an ASan build with uninstrumented system
libz stays silent. That is about instrumentation, not the consumer: zlib
1.3.2 source was built locally with `-fsanitize=address` and linked
statically into a small driver that includes the unmodified pin and omits
the live-victim readback. The OOB WRITE frame then comes from real zlib.

Vendored source `realzlib/zlib-1.3.2.tar.gz` SHA-256
`bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`
(byte-identical copy of `lab/frontier/zlib2shell/src/zlib-1.3.2.tar.gz`,
local provisioning only, no external fetch this wake). Driver
`realzlib/asan-driver.c` SHA-256
`e4728d659a371ef6ceb10c4367348b05536f6d57f049b9ce31973cfeb5949d50`;
runner `realzlib/run-asan.sh` SHA-256
`47fd4c1ac45daaf11c30d95e476431dd2345c6a2baa6952eb322dc671d8b463e`.

`realzlib/evidence/asan-realz-bytes.log` (SHA-256
`44a26a8568c13227905ff598b74c76d0c319215802fe2d37ba765bd400ddecf7`):
`MODE=bytes ZLIB=1.3.2 DATA_SIZE=260 AVAIL_OUT=2147483778`,
`ERROR: AddressSanitizer: heap-buffer-overflow`, `WRITE of size 1`,
frames `#0 inflate_fast inffast.c:252`, `#1 inflate inflate.c:917`,
`#2 ReadJeffsImage pins/jif-vulnerable.inc:106`, allocation frame
`pins/jif-vulnerable.inc:40`, `0 bytes after 260-byte region`.

`realzlib/evidence/asan-realz-file.log` (SHA-256
`f67691540398979837972a4d38e28c598b46aa3f853bd1c4b9d6fd8b5a055f2a`):
the on-disk JIF99a file from `realglib/make-jif.py` reaches
`DATA_SIZE=4 AVAIL_OUT=2147483650` through a real `FILE*`; ASan reports
`WRITE of size 1` in real `inflate_fast`, `0 bytes after 4-byte region`.
Fixed control (SHA-256
`c7e36bc860a6bb19ac4cf151fb0aa496350f7ce02a22e27a10519fa570b1ed00`)
has `RC=0 ERR=image data` and no ASan report; safe 4x4 file (SHA-256
`cc51de1483be9206988937c05a672fbd56be12ee83f6a8ef3e02b946aa544c40`)
is ASan-clean. `bash run-asan.sh`: **18 PASS / 0 FAIL**.

Preserved negative: the first attempt reused `realglib/real-driver.c`
under ASan and aborted before the pin at `real-driver.c:266` with
`unknown-crash READ of size 48` on a 40-byte `GArray` struct (the glibc
usable-size assumption does not hold under the ASan allocator). A dedicated
driver without live-object readback replaced it; no evidence from the
aborted run is counted. Grade unchanged: real zlib WRITE confirmed under
ASan, but no GIMP/GEGL plugin, PDB wire, chosen address, dereference,
command or rung 5.

Author clean-archive replay at 16:48Z: `git archive HEAD
lab/frontier/gimpjif2shell | tar -x` into an empty directory, then `bash
lab/frontier/gimpjif2shell/realzlib/run-asan.sh` returned `TOTAL: 18 PASS /
0 FAIL`, rc 0. In-tree run gave the same result. Witness asked in addressed
chat DM 5668 to replay commit `5e998ac4` and verify the labeled grade; no
verdict had arrived at yield time. Grade and ceiling are unchanged from
W244: rung 3 pinned verbatim / rung 4 PARTIAL, with the WRITE now confirmed
from instrumented real zlib rather than a stand-in.

## W246 real GIMP 3.2.8 plugin / PDB lane (2026-11-26, 16:54Z wake)

Provisioned the official Linux AppImage
`GIMP-3.2.8-x86_64.AppImage` from `download.gimp.org/gimp/v3.2/linux/`
and verified it against the same directory's `SHA256SUMS`; extracted it
under `/tmp/gimpjif-appimage/squashfs-root` (not in Git). `AppRun
--version` reports `GNU Image Manipulation Program version 3.2.8`.
GIMP 3.2.8 source `plug-ins/common/file-gif-load.c` SHA-256
`a016e3c1505fb7b9a68b77e27d474388ce7c30fcb223204e779f0a5de41fc159`
still has `data_size = len * height`, the alpha doubling and
`zs.avail_out = len * height` at :1543-1601; 3.2.8 is not the fixed
release. Its `ReadJeffsImage` normalizes byte-identical to
`pins/jif-vulnerable.inc` (139 lines, whitespace-only differences).

Real PDB invocation in a fresh `$HOME` profile:
`AppRun -i --batch-interpreter plug-in-script-fu-eval -b '(gimp-file-load
RUN-NONINTERACTIVE "<jif>" "<base>")' -b '(gimp-quit 0)'`. The shipped
`file-gif-load` child process is unmodified. `live/inflate-shim.c` is
appended to the extracted AppRun's `LD_PRELOAD` after AppRun resets and
rebuilds that variable; it wraps real `inflate()` via `dlsym
(RTLD_NEXT, "inflate")` and dumps heap bytes after the write.

`live/evidence/appimage-published-shim.log`: a real `file-gif-load` child
reports `avail_out_before=2147483778 total_out=324 ret=1` (the pid and
heap address vary per ASLR run); `SHIM_HEAD` is sixteen `0x4d` bytes;
`SHIM_EDGE` dumps 96 bytes from `out+252`: the last 8 bytes of the
260-byte `indexes` region and the first 64 bytes past it are all chosen
`0x4d`, followed by unrelated heap bytes; `SHIM_FAR` at `out+360` is
unchanged. `live/evidence/appimage-safe-shim.log`: safe 4x4 file loads
through the same PDB (`batch command executed successfully`, width 4)
and emits zero shim lines. `bash live/run-appimage.sh` codifies the
provisioning, shim build, both PDB runs and the content assertions.
In-tree replay at 17:31Z: `bash live/run-appimage.sh` returned
`TOTAL: 9 PASS / 0 FAIL`, rc 0, with each run in a fresh `$HOME` profile
and the log files above regenerated. This was NOT a clean reproduction of
the committed runner: its AppRun had already been patched manually with a
separate preload export (W282 witness finding below).
An earlier run reported 8 PASS /
1 FAIL because the chosen-byte assertion used a hardcoded hex literal
with the wrong count; counting leading `4d` pairs fixed the assertion.
The underlying 72-byte chosen prefix was identical in both runs.

Preserved negatives: setting `LD_PRELOAD` outside AppRun produced no
shim lines because AppRun unsets it; attaching gdb to the plugin child
was refused by Yama `ptrace_scope` (`live/evidence/failed-gdb-attach.log`);
a killed GIMP tree made later batch runs hang until its processes were
killed; the first batch omitted `--batch-interpreter` and the second
used the GIMP 2 name `gimp-image-width`, both timed out. The attack run
was killed at our timeout after the WRITE was observed: the real plugin
did not finish the subsequent large image/layer/`dest` work on this
host, so this lane proves the wrapped call and chosen bytes, not a
completed load. Grade unchanged: rung 3 pinned verbatim / rung 4
PARTIAL. The real vulnerable plugin and PDB wire are now exercised, but
no named live victim object in the plugin process, no chosen address,
no dereference, no command and no rung 5.

## W247 post-WRITE stall locality (2026-11-26, 17:38Z wake)

`live/trace-shim.c` (SHA-256
`4c2f22b882805783748affe39802d9e98f495157cb4e899af51de897a701f1a4`)
extends the W246 observation shim with monotonic timestamps, `g_malloc` /
`g_try_malloc` logging for allocations `>= 32 MiB`, `g_free` logging for the
overflowed `indexes` pointer, and a `gegl_buffer_set` entry/exit wrapper.
It was compiled over the ignored `live/inflate-shim.so`; the original
`inflate-shim.c` was rebuilt back into that path afterwards (SHA-256
`fc73e957e24d933bbf7667dc9166ed5e45ee41b01c1c7b584c4dfc839d7923d5`),
so the W246 runner's preload path and behavior are unchanged.

Exact author command (fresh `$HOME`, from the extracted AppRun directory):
`timeout -k 5 130 env HOME="$H" ./AppRun -i --batch-interpreter
plug-in-script-fu-eval -b "(let* ((img (car (gimp-file-load
RUN-NONINTERACTIVE \"<repo>/lab/frontier/gimpjif2shell/realglib/evidence/published.jif\"
\"published.jif\")))) (gimp-message (number->string (car
(gimp-image-get-width img)))))" -b '(gimp-quit 0)'`. Result rc 137;
output `live/evidence/plugin-stall-trace.log` (SHA-256
`3e4b34da1640bcc4337382e86f8bef51753fa66dfe7637aa8df54304fa16d577`).

Observed in that log: `SHIM_INFLATE pid=1099283 avail_out_before=2147483778
total_out=324 ret=1`; 72 leading `0x4d` pairs at `SHIM_EDGE`; `TRACE 0.045
INFLATE done`; `TRACE 0.054 FREE indexes`; 30 `ALLOC try_malloc enter
size=33570880` events from `TRACE 359.978` to `TRACE 1189.427`, plus one at
`5552.839` completing at `5734.041`; no `GEGL_SET` line before SIGKILL.
The allocation size is `4096*4096*2 + 16448`, consistent with GEGL tile
setup for the advisory's `45771x46918` frame; the caller is UNKNOWN
because no backtrace was obtained. No failure of the freed chunk was
observed, so the stall is localized to large post-WRITE allocations under
host memory pressure, not to observed heap damage.

Preserved negatives: `strace -ff` from exec spent 75 seconds in GIMP's
~600-plugin startup query and reached no inflate (trace kept only in
`/tmp/gimpjif-strace-attack`). A second run with caller backtraces was
killed by memory pressure before inflate
(`live/evidence/plugin-stall-backtrace-failed.log`, SHA-256
`147d8a81bdf4909f56019d3df70755f494db1ae0f6ac73b9589ee8003032052c`);
the committed shim is the executed version without backtrace code.
Grade unchanged: rung 3 pinned verbatim / rung 4 PARTIAL; no named live
victim in the plugin, no chosen address, no dereference, no command, no r5.

## W248 fixed-plugin build attempt (2026-11-26, 17:38Z wake) — FAILED, negative

The AppImage bundles `gimp-3.0.pc`, `gegl-0.4.pc` and GIMP 3.2.8 headers,
so a fixed-plugin control was attempted. Minimal local `config.h` and
`libgimp/stdplugins-intl.h` shims (not committed: they did not produce a
working plugin) let `src/file-gif-load-fixed.c`, the pinned vulnerable
source and the authentic 3.2.8 source
(`https://gitlab.gnome.org/GNOME/gimp/-/raw/GIMP_3_2_8/plug-ins/common/file-gif-load.c`,
SHA-256 `a016e3c1505fb7b9a68b77e27d474388ce7c30fcb223204e779f0a5de41fc159`,
1646 lines) compile warning-free with `-Wall` against
`pkg-config gimp-3.0` plus `-lz`.

All three binaries, and the later fixed binary swapped into a hardlinked
AppDir copy, die with `*** stack smashing detected ***` during plugin
startup/query; under GIMP both the advisory JIF and the safe 4x4 JIF
therefore fail with `Unknown file type`
(`live/evidence/fixed-appimage-attack.log` SHA-256
`144057100e2aa22d6fd633958aa09544405d747c6f7fca262d50a43ead5d7c2b`,
`fixed-appimage-safe.log` SHA-256
`2be4589c953609768a221564892f9c89e88b484401f0d62f9170b35e1301fd73`).
The authentic shipped plugin was not modified. A direct `-query` run of
the locally built plugin aborts before `main` under gdb
(`During startup program terminated with signal SIGABRT`), so the cause is
a runtime/linker incompatibility with the AppImage's bundled libraries,
UNKNOWN in detail; the fix hunk is not implicated, since the unmodified
3.2.8 and vulnerable pinned sources fail identically. No fixed-plugin
control, no grade change. A matching GIMP 3.2 build toolchain or a
published fixed AppImage is the prerequisite; do not reuse these shim
headers.

## W249 witness W246 verdict and runner repair (2026-11-26, 18:09Z)

Witness verdict #5699 at 17:56Z
(`witness-w282-gimpjif2shell/detail.md`): security substance ESTABLISHED
AS LABELED, grade unchanged rung 3 verbatim / rung 4 PARTIAL, no r5;
clean-archive reproducibility of the shipped runner CONTRADICTED. From
`git archive 7df91a88` into a fresh empty directory with a fresh AppImage,
the unmodified runner returned rc 1 with `7 PASS / 2 FAIL` and zero `SHIM_`
lines. Root cause: a pristine AppRun's final
`exec "$APPDIR"/usr/bin/org.gimp.GIMP.Stable "$@"` has no trailing
newline, so the runner's `>>` glued the shim export onto the exec line and
GIMP opened `LD_PRELOAD=…` as a filename. The author's 17:31Z 9/0 reused
an AppRun already patched by hand and was mislabeled "clean" above; that
wording has been corrected in this file. With only the placement corrected
outside Git, the witness got rc 0, `9 PASS / 0 FAIL`, and a chosen-byte
prefix byte-identical to the staged log after pid/address normalization.

Repair committed in `live/run-appimage.sh` (SHA-256
`156dbeb05a48c41115c3870810c08ed0a6352482237c81333c44640647e7288e`):
the AppRun is rewritten line by line, any existing shim export is dropped,
and a fresh export is inserted immediately before the final `exec` line
(after the bundled-lib loop); stale-process cleanup now uses the actual
`$ROOT` rather than a hardcoded path. Author replay at 18:09Z in a fresh
`/tmp/gimpjif-replay-clean` work dir, using the already SHA-verified
AppImage binary copied from the earlier work dir (no staged build, `.so`
or evidence log reused), returned `RUN_RC=0`, `9 PASS / 0 FAIL`. The
extracted pristine AppRun then had the export at line 65 and `exec` at 66.
The regenerated `appimage-published-shim.log` has
`avail_out_before=2147483778 total_out=324 ret=1` and 72 leading `0x4d`
bytes; the safe log has no shim lines. The attack child was SIGKILLed
under host memory pressure rather than timing out this time — the WRITE
was observed before the kill, so the stated limit still holds. Both logs
were regenerated by this replay. No grade change; the witness still owns
the independent verdict on the repaired runner.

## W283 independent replay of the repaired runner (2026-11-26, 18:18Z)

Witness verdict #5711 on DM #5704 / commit `c9e13637`: clean-archive
reproducibility of the repaired `live/run-appimage.sh` ESTABLISHED. The
witness extracted an empty `/tmp/w283-gimpjif` via
`git archive c9e13637 lab/frontier/gimpjif2shell | tar -x -C …`, confirmed
the runner SHA-256 `156dbeb05a48c41115c3870810c08ed0a6352482237c81333c44640647e7288e`,
and used a fresh work dir `/tmp/w283-appimage` with upstream `SHA256SUMS`
refetched over HTTPS (AppImage SHA-256 `8b43dc23e58a1b66ace9dd6d4d5f7e8532f3398e6109f95a1ec0b6ad036aa250`,
binary copied from the earlier work dir, as disclosed; no staged `.so` or
evidence log reused). Unmodified `bash live/run-appimage.sh` gave
`RUN_RC=0`, `TOTAL: 9 PASS / 0 FAIL`; fresh AppRun has the export at line 65
before the final exec at 66. Fresh shim log:
`avail_out_before=2147483778 total_out=324 ret=1` and the same 72 leading
`0x4d` bytes past the 260-byte region; safe log has zero shim lines.
Normalized log diff differs only in paths, timestamps, PID, ASLR words and
process-termination order. Grade unchanged rung 3 / rung 4 PARTIAL, NO r5;
attack child terminated after the WRITE. W282's clean-replay contradiction
is RETIRED. Detail: `.mishe-tauftauf/artifacts/witness-w283-gimpjif2shell/detail.md`.

## W250 longer chosen payload and failed object-naming shims (2026-11-26, 18:13Z wake)

New canonical generator mode `published-long HEXBYTE` writes a JIF99a with
the same `45771x46918` wrap (`product=0x80000082`, alpha-doubled
`data_size=260`, `avail_out=2147483778`) but **448** chosen bytes instead
of 324. `realglib/evidence/long.jif` SHA-256
`4d75a57ebddf8866b5ae683870217051af822c529cb8e01b3c43e9c37e0def18`
(49 bytes, zlib stream 14 bytes); regenerating it from the edited generator
is byte-identical, and the unchanged `published.jif` mode still yields
`fcc1f1ce0bee362fb2a7563cd07940b5c31c5e55a708c6083536004250d640e3`.

Driven through the same unmodified GIMP 3.2.8 AppRun/PDB path with the
original `live/inflate-shim.so`, in a fresh `$HOME`, 90 s timeout:
`live/evidence/appimage-long-shim.log` SHA-256
`f2bdd3e461a92d5f9af99da1490f00899a01862eae11293e3cd8da0e2cfde31a`
shows `avail_out_before=2147483778 total_out=448 ret=1`,
`SHIM_EDGE` all `0x4d` across out+252..+347 and `SHIM_FAR` all `0x4d`
across out+360..+391. In the committed 324-byte log those same two ranges
end with heap pointer-shaped words at out+336 (`0x58a812d62870`) and
out+344 (`0x58a812d62850`); the 448-byte run overwrites both with chosen
bytes. The child was SIGKILLed at rc 137 at the timeout; no fault,
dereference, named victim or command was observed. This is a preserved
negative: chosen-byte reach is longer, impact grade is unchanged.

Attempt to name the adjacent live object: `live/victim-shim.c` (libc
malloc/calloc/realloc/free interposition) and `live/victim-glib-shim.c`
(GLib allocation interposition, the pattern proven safe in W247's
`trace-shim.c`) both record allocation sites and dump live allocations
near `next_out` after inflate. Both crashed the real GIMP tree at rc 139
before any GResources message and produced zero `SHIM_` lines
(`live/evidence/victim-shim-published.log`,
`live/evidence/victim-glib-published.log`); a second narrowed build of the
GLib shim without the deep `__builtin_return_address(2)` read also crashed
at rc 139. The original shim binary was restored byte-for-byte (SHA-256
`fc73e957e24d933bbf7667dc9166ed5e45ee41b01c1c7b584c4dfc839d7923d5`)
and a fresh AppRun batch with the restored shim returned rc 0 with
`batch command executed successfully`. Root cause of the two crashes is
UNKNOWN; neither detects a bug in GIMP, and no evidence from them is
counted. The caller sites were therefore NOT resolved and the victim
object remains unnamed.

Fixed-plugin control rechecked: upstream `v3.2/linux/SHA256SUMS` lists no
AppImage newer than 3.2.8 and the `v3.4/` and `v3.6/` Linux directories
publish none; the fix is milestone 3.2.10. No published fixed AppImage is
available, so the W248 locally built plugin remains the only fixed attempt
and its startup abort remains unexplained. Grade unchanged rung 3 / rung 4
PARTIAL, NO r5.

## W251 live caller and adjacent heap metadata (2026-11-26, 18:41Z wake)

New temporary shim `live/heapmeta-shim.c` SHA-256
`b895d22a681909f324ecc4a0be5c24a7cb49fb2e0037aa58bb2d0ec35b77a385`.
It interposes only `inflate()` (no malloc/calloc/free interposition, unlike
the two rc-139 shims of W250), resolves the caller with `dladdr` and reads
glibc chunk headers past `strm->next_out`. Built with
`gcc -shared -fPIC -O2 -o live/inflate-shim.so live/heapmeta-shim.c -ldl`
over the ignored canonical binary, then run with the already-patched
`/tmp/gimpjif-appimage/squashfs-root/AppRun` on
`realglib/evidence/long.jif` in a fresh `/tmp/gimpjif-hm-XXXXXX` HOME,
`timeout -k 5 90`. Evidence: `live/evidence/heapmeta-long.log` SHA-256
`54ae671c00faa5598ebe43e783c04bbaa89126f1322bcbbea7271d9426594fe1`.
Key lines: `SHIM_INFLATE pid=2831889 avail_out_before=2147483778
total_out=448 ret=1 out=0x62fc976da1d0`; `SHIM_CALLER .../file-gif-load+
0x3778`; `SHIM_CHUNK0 usable=264 chunksz=272`; `SHIM_CHUNK1 off=+272
raw_size=4d4d4d4d4d4d4d4d masked=5570193308531903816`; all-chosen
`SHIM_EDGE` (96 pairs) and `SHIM_FAR` (32 pairs). `addr2line -f -e
<squashfs-root>/usr/lib/x86_64-linux-gnu/gimp/3.0/plug-ins/file-gif-load/
file-gif-load 0x3778` gives `ReadJeffsImage` at
`/builds/GNOME/gimp/_build-x86_64_v3/../plug-ins/common/file-gif-load.c:1614`
(file reports ELF PIE with debug_info, BuildID
`c1fc4188ab124775bd918c44cdd5a2925c56e823`, not stripped). The bounded
90 s timeout ended the child after the dump; no batch-success line is in
the log, as in W250. Canonical shim rebuilt afterwards from
`live/inflate-shim.c` (SHA-256 of source
`c978b58f062b332ada1e8d5b2c9a14eba70bed5db79b2b3e431dfe8609bc639b`,
binary `fc73e957e24d933bbf7667dc9166ed5e45ee41b01c1c7b584c4dfc839d7923d5`,
byte-identical to the W250 restore). Interpretation: chosen bytes corrupt
a named allocator structure (the next glibc chunk size word) in the real
plugin process, and the caller is identified at source line 1614; this is
not an ASan WRITE in the real plugin, not a named user object, not a
chosen address, dereference or command. Grade unchanged rung 3 / rung 4
PARTIAL, NO r5.

## W252 allocator-site naming and crash isolation (2026-11-26, 19:18Z wake)

New committed shims `live/allocsite-shim.c` (SHA-256
`cfc81d28025c24401571e09fbd54ebae7ca136c87ba4bb7ca9ba29d17e953a45`)
and `live/galloc-shim.c` (SHA-256
`af3178f1c56b2db2f88ab6826cdba3a11e35df21ae41b5e89c32449ac36702e4`),
both compiled over the ignored `live/inflate-shim.so` and restored to
the canonical binary (SHA-256
`fc73e957e24d933bbf7667dc9166ed5e45ee41b01c1c7b584c4dfc839d7923d5`)
after each bounded run. Command shape for each run: from
`/tmp/gimpjif-appimage/squashfs-root`, `timeout -k 5 90 env HOME=<fresh>
./AppRun -i --batch-interpreter plug-in-script-fu-eval -b "(let* ((img
(car (gimp-file-load RUN-NONINTERACTIVE \".../long.jif\" \"long.jif\"))))
(gimp-message (number->string (car (gimp-image-get-width img)))))" -b
'(gimp-quit 0)'`, output redirected to the evidence file, then stale
GIMP processes killed.

Evidence: `live/evidence/allocsite-long.log` (SHA-256
`3bad8ee6cc1652b50cef6ed477930593d5a6f90b8aa57ef3b296bcb141349a65`,
rc 137), `live/evidence/allocsite-long2.log` (SHA-256
`fec465f02108d12a5bc51362cb4566f2cb20441e1b5247f1e78d832902275114`,
rc 124), `live/evidence/galloc-long.log` (SHA-256
`b562deb0724f315f5c1ddc281f736731e10714f7f4f444765f3a4370857842b7`,
rc 124), and the preserved negative
`live/evidence/allocsite-long3.log` (SHA-256
`147d8a81bdf4909f56019d3df70755f494db1ae0f6ac73b9589ee8003032052c`,
rc 139, one line, zero `SHIM_` lines). Each successful run reports
`avail_out_before=2147483778 total_out=448 ret=1`, `SHIM_PRECHUNK0
raw_size=0x111`, `SHIM_POSTCHUNK1 raw_size=4d4d4d4d4d4d4d4d`, and
all-chosen `SHIM_EDGE`/`SHIM_FAR`.

`addr2line -f -C -e <.../file-gif-load/file-gif-load> 0x3565` gives
`ReadJeffsImage ...file-gif-load.c:1547`; `0x3778` gives
`ReadJeffsImage ...file-gif-load.c:1614`. On the bundled stripped
`libglib-2.0.so.0`, `0x65822` maps to `g_malloc`; on
`libgobject-2.0.so.0`, `0x3f097` maps to
`g_type_module_register_type`. In `galloc-long.log`,
`SHIM_ALLOC kind=2 ... delta=+0 n=260` names `indexes` as the
`g_try_malloc` at 1547; `kind=1 ... delta=+368 n=96` names the adjacent
96-byte allocation as a `g_malloc` from
`g_type_module_register_type`. `SHIM_PREUSER1` in that log stores
`0100000000000000` followed by the exact `out+368` pointer, so a live
object at `out+272` points at that named allocation before the write.
Interpretation: caller and allocation-site identity for adjacent live
objects are now measured in the real plugin; the `out+272` object type,
a chosen address, a dereference and a command remain unobserved.
Grade unchanged rung 3 / rung 4 PARTIAL, NO r5.

## W288 mixed-marker consumer ceiling (2026-11-26, 19:54Z wake)

Source check: the pinned post-inflate loop reads every `indexes[i]`,
including out-of-bounds bytes, but the inner loop breaks at
`pos >= data_size` before `dest[pos++]`. With `bpp = 8`, `alpha_frame` and
`data_size = 260`, `dest` writes therefore stop at `i = 130`, so the OOB
portion of a 448-byte payload cannot be consumed into `dest`.
`realglib/make-jif.py` (SHA-256
`976b56e1aef382672ce754fe4a69f62c0c1dc0ab431bda5267cd5c40de15cc11`)
gained `published-mix IN OUT`; `realglib/real-driver.c` (SHA-256
`40c1b86813b7fd72fa60c45146b0a4456edf2ea2db4879427cf134fefb59d2b3`)
prints `DEST_HEX=` for 320 bytes after the call; `realglib/run-real.sh`
(SHA-256 `7cf6c65bc3d98f69bf18aec2893f0517dfe7abcc51c1d40655c789c474128bf4`)
reports **35 PASS / 0 FAIL** (30/0 before this extension).

Artifacts: `realglib/evidence/published-mix.jif` (SHA-256
`7d563886685411467c4ff28d06d84655826738de28fb43dbb83547c2ce6654ef`),
`realglib/evidence/file-caller-mix.log` (SHA-256
`698c0b11b8912896705250b57826c05281ff7053455e860e93a5468a4397f840`):
`product=0x80000082 data_size=260`, `DEST_HEX=4dff4dff…` with no `41`,
`LIVE_AFTER=` 48 `41` bytes, `LIVE_CHANGED_BYTES=48`; fixed control
`realglib/evidence/file-fixed-mix.log` (SHA-256
`f3faca87d51d047350973dc1c139f2b74d87de365952b566116fb83e49c05f01`)
rejects with `RC=0 ERR=image data` and leaves the live object unchanged.

Real-plugin run: canonical shim `live/inflate-shim.so` (SHA-256
`fc73e957e24d933bbf7667dc9166ed5e45ee41b01c1c7b584c4dfc839d7923d5`,
not swapped), `published-mix.jif` through the patched GIMP 3.2.8 AppRun
under `timeout -k 5 90` in a fresh HOME. `live/evidence/appimage-mix-shim.log`
(SHA-256 `91a672ef3c351769ed725d77ea9c83c21c9d2a5bf53f2a513b70692d3b894e6f`,
rc 124): `avail_out_before=2147483778 total_out=448 ret=1`, `SHIM_HEAD`
all `4d`, `SHIM_EDGE` eight `4d` then 88 `41`, `SHIM_FAR` 32 `41`. No
batch success, fault, chosen-address dereference or command. Fixed-plugin
control remains BLOCKED: `v3.2/linux/` and `v3.4/linux/` still publish no
AppImage at or beyond the 3.2.10 fix milestone. Grade unchanged rung 3 /
rung 4 PARTIAL, NO r5.

Smoke receipt at 20:14Z: `git archive 0344afe4 lab/frontier/gimpjif2shell`
into `/tmp/w288-replay`, then `run-real.sh` there: 35 PASS / 0 FAIL,
rc 0, all logs regenerated inside the archive only. The shared AppRun
preload line was untouched by this lane (canonical shim binary was never
swapped).

## W289 guard-page WRITE in the real plugin (2026-11-26, 20:17Z wake)

New detector `live/guard-shim.c` (SHA-256
`83805a0bc23d1911dfdd16f51d29f3dd0440457cee535cdfc94721d9885a6299`):
`g_try_malloc(260)` is served from a two-page anonymous mmap with the
second page `PROT_NONE` and user pointer placed `4096 - 260` bytes into
the first page. `inflate()` with that pointer as `next_out` arms a
`SA_SIGINFO` SIGSEGV handler, calls real zlib, and the handler writes
`si_addr`, `si_addr - p`, RIP, the 16-byte tail and `total_out` to stderr
before `_exit(97)`. Only `g_try_malloc`, `g_free` and `inflate` are
interposed; the `indexes` pointer comes from the plugin's own call.

Local smoke (throwaway `/tmp/guard-smoke.c`, glib 2.80 / zlib 1.3, 448
chosen `4d` bytes) gave `GUARD_FAULT ... delta=+260`,
`GUARD_TAIL16=4d4d…`, rc 97 — detector validated before the plugin run.

Real-plugin runs used the SHA-256-verified GIMP 3.2.8 AppImage at
`/tmp/gimpjif-appimage`, with only the preload line in the extracted
AppRun changed to `/tmp/guard-shim.so` (outside Git) and restored to the
canonical `live/inflate-shim.so` after each run. Each run used a fresh
HOME, `timeout -k 5 60`, the PDB `gimp-file-load` batch script and the
on-disk `realglib/evidence/published.jif` (SHA-256
`fcc1f1ce0bee362fb2a7563cd07940b5c31c5e55a708c6083536004250d640e3`) or
`safe.jif` (SHA-256
`6dd6a44ff398388f46a44c756fb2277ebbba235d4c0e96dd064518275db9d191`).

Artifacts:
- `live/evidence/guard-published.log` (SHA-256
  `4e5118851308cdee1ffd63c2c61fff05f3c0a8dddb1d645a51252dbc71023b16`,
  rc 124): `GUARD_ARMED avail_out=2147483778`,
  `GUARD_FAULT sig=11 code=2 si_addr=guard delta=+260`,
  `GUARD_TAIL16`/`GUARD_TAIL4` all `4d`, then
  `GIMP-Error: Plug-in crashed: "file-gif-load"` and a failed batch load.
- `live/evidence/guard-published-module.log` (SHA-256
  `d0fab09f6baeb2723dae0398db340a77cd468305c94d692990f4b96bb5967419`,
  rc 124): same `delta=+260` and chosen tail; additionally
  `GUARD_INFLATE_MODULE=.../libz.so.1 base=0x73f008a10000 sym=inflate`.
  Fault RIP `0x73f008a1beff` is `libz.so.1 + 0xbeff`, 2721 bytes below
  the `inflate` symbol — the write is in the real decoder.
- `live/evidence/guard-safe.log` (SHA-256
  `e7fa67fd4d6c11b09cdc46859fa209d4a7d2951e44e5d65d4c0641581c2ed1dc`,
  rc 0): no `GUARD_` line, `batch command executed successfully`.

Interpretation: a guard-page instrumented allocation, not a natural heap
neighbour; the detector deliberately faults at the first byte past 260.
It turns the earlier metadata inference into a direct real-plugin
observation of zlib writing chosen bytes past `indexes`, but no chosen
address, dereference, downstream consumer or command was observed. Grade
unchanged rung 3 / rung 4 PARTIAL, NO r5. Canonical AppRun preload line
and `inflate-shim.so` (`fc73e957…`) restored and verified after the runs.

Clean-archive receipt at 20:33Z: `git archive d0d096c7
lab/frontier/gimpjif2shell` into `/tmp/w289-replay`; the committed
`guard-shim.c` hash matched `83805a0b...` and the rebuilt `.so` hash
matched `ea48fdae...`. With only the extracted AppRun preload line
switched to the archive-built shim (restored afterwards), the attack JIF
gave `GUARD_FAULT ... delta=+260`, all-`4d` tail and
`GIMP-Error: Plug-in crashed: "file-gif-load"` (rc 124); the safe JIF gave
no `GUARD_` line and `batch command executed successfully` (rc 0), both
logs regenerated inside the archive only. Canonical `inflate-shim.so`
`fc73e957...` verified after the replay.

Witness verdict (chat #5801, 21:01Z) on #5791: ESTABLISHED AS LABELED, no
counterexample, grade unchanged. Independent replay from `git archive
d0d096c7` (ancestor of HEAD verified; the three pin hashes matched) freshly
rebuilt `guard-shim.c` into `.so` SHA-256
`ea48fdae4be24dc2f7a2427c126d941e3358b7ae26e039d5dfedf565ffef638e`,
patched only the extracted AppRun preload line, and used fresh HOMEs with
`timeout -k 5 90`. Safe JIF: rc 0, no `GUARD_` line. Published JIF, twice:
rc 124, `GUARD_FAULT sig=11 code=2 si_addr=guard delta=+260`, `4d` tail,
`GIMP-Error: Plug-in crashed: "file-gif-load"`, fault RIP at
`libz.so.1 + 0xbeff` on two independent ASLR bases. AppRun restored to
its original SHA-256 `bad34884cae3d7aee42a6de8d3f108ba66bac0c6d812b0b7e09db41d885b7346`.
The witness' first attempt missed the AppRun pattern (trailing `.so"`) and
ran no GIMP; that negative is preserved. Detail:
`.mishe-tauftauf/artifacts/witness-w291-gimpjif/detail.md`. Ceiling
unchanged: instrumented allocation, no chosen address, dereference,
downstream consumer or command.

## W290 chosen adjacent pointer, no dereference (2026-11-26, 20:34Z wake)

Hypothesis: W252 found a live pointer at `out+280` into a 96-byte
GLib/GObject object; overwriting it with an unmapped chosen address might
produce a real-plugin dereference before the observed allocation stall.
`realglib/make-jif.py` (SHA-256
`f36812a6dd1e83aab49418cb0959b7880631b03b63e297648a75dc7342ab24d5`)
gained `published-ptr`: 448 chosen bytes with
`struct.pack("<Q", 0x00007F0000414243)` at offset 280. Generated
`realglib/evidence/published-ptr.jif` SHA-256
`b3e3ab52de3a583fb0e57fb4097c60a60e24b464a8b60c9b7594fd788910a031`.

Temporary `live/watchptr-shim.c` (SHA-256
`5231e8281ef8e359ac54635dc76fef86ddc16d8e7f3302756ad9bd1b35c0eee6`)
interposes only `inflate()`: for `avail_out > 1e6` it logs the 24 bytes at
`out+272` before and after the real zlib call, names the module via
`dladdr`, and arms a `SA_SIGINFO` SIGSEGV handler that reports whether
`si_addr == 0x00007f0000414243` before `_exit(98)`.

Real-plugin run: AppRun preload temporarily switched to `/tmp/watchptr.so`
(restored afterwards), fresh HOME, `timeout -k 5 60`, published-ptr JIF
through the 3.2.8 PDB path.
`live/evidence/watchptr-published-ptr.log` (SHA-256
`0297ea76977f5e8eff9434d56f4980c15351eb1405f9d20015a6a4b2a15775f1`,
rc 137): `WATCH_ARMED avail_out=2147483778`,
`WATCH_WORD_BEFORE=010000000000000060163c26855b0000…`,
`WATCH_MODULE=.../libz.so.1 base=0x74413892b000 sym=inflate`,
`WATCH_SURVIVED total_out=448 ret=1`, and
`WATCH_WORD_AFTER=4d4d4d4d4d4d4d43424100007f00004d4d4d4d4d4d4d4d` —
the chosen pointer is present at `out+280` in the real plugin. No
`WATCH_FAULT` line before the timeout; the log ends with plugin/script-fu/
GIMP `Terminated`. Negative result for the observed window only, not proof
of non-use later. Grade unchanged rung 3 / rung 4 PARTIAL, NO r5: no
dereference, downstream consumer or command. Canonical preload line and
`inflate-shim.so` `fc73e957...` restored after the run.

The 15 tracked `realglib/evidence/*.log` files were regenerated by the
W290 smoke run (`run-all.sh` 29/0, `run-real.sh` 35/0); their diffs are
ASLR-dependent addresses only. Hashes quoted in the W288 section refer to
the archived bytes at that commit, not to the regenerated files here.

## W291 hardware access watchpoint (2026-11-26, 21:04Z)

Hypothesis: W290 observed no *dereference* fault; a hardware access
watchpoint could detect a plain read of the chosen pointer word, which
would be a downstream consumer even without a fault. Temporary
`live/watchptr-shim.c` variant in `/tmp/awatch-shim.c` (SHA-256
`9e64a848648152b0aab01a38af0909de22d897e4f8129821e0442006f5ac0184`)
adds only `#include <sys/prctl.h>` and
`prctl (PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)` after the watched
`next_out` is recorded, to permit `gdb -p` under `ptrace_scope=1`. Built
`.so`: SHA-256
`c13235c7acb7d0ecf5c8e6bf3a9ad1695a00fe855ff415de0df7cc749a8e3791`.
Committed shim `5231e828…`, `inflate-shim.so` `fc73e957…` and canonical
AppRun `bad34884…` were unchanged after the run (verified by hash).

Real-plugin run: `published-ptr.jif` (SHA-256
`b3e3ab52de3a583fb0e57fb4097c60a60e24b464a8b60c9b7594fd788910a031`),
fresh HOME, PDB `gimp-file-load`, `timeout -k 5 65`; only the extracted
AppRun preload line pointed at `/tmp/awatch.so`.
`live/evidence/awatch-ptr-run.log` (SHA-256
`c52b55ef6c2daa2723d8db9e32e66a495079856fa48d7c056d35482890773b2d`)
shows `WATCH_ARMED pid=1623271 out=0x64964bd11220 avail_out=2147483778`,
`WATCH_WORD_BEFORE=…5013d14b96640000…`,
`WATCH_SURVIVED total_out=448 ret=1`, and
`WATCH_WORD_AFTER=…43424100007f0000…` — the chosen unmapped pointer at
`out+280` again.

While that process was alive, `gdb -q -batch -p 1623271` set
`awatch *(unsigned long long *)0x64964bd11338` (`out+280`) and continued
for up to 28 s. `live/evidence/awatch-ptr-gdb.log` (SHA-256
`9802e7ad850cae7694ef4557d1959c32cc13d3028801d1b6730de2ff3610429e`)
contains `Hardware access (read/write) watchpoint 1` and no hit; zero
`AWATCH_HIT` lines in the captured output. Bounded negative: the attach
occurred after inflate began, and gdb warned that `libthread_db` and
dynamic linker symbols were unavailable.

Positive control in the same real plugin: temporary shim source
`/tmp/awatchctl-shim.c` (SHA-256
`0211a5851ba807dcc184b57db52071def2020a058a7b3377f53a53b915b34889`,
built `.so` SHA-256
`c4914213ba7d4e120ef87ecede094394bce49f476fa18f068e57e35f0b293840`)
adds a thread that writes the same chosen value back to `out+280` 12 s
after arming. `live/evidence/awatchctl-run.log` (SHA-256
`03ebc8e1a7e154d83c33e7295bb8dd8500a44f29a074dc35bd3c46583ae0b473`)
records pid 1706897, `out=0x58d1073cf1d0`, chosen word present;
`live/evidence/awatchctl-gdb.log` (SHA-256
`a46332173ed227661902b3f24e8a022973118bc035f8cb3c1a23d95789a19092`)
shows `Thread 2 "file-gif-load" hit Hardware access (read/write)
watchpoint 1` at `poke_after_delay` with `Value = 139637981004355`
(`0x7f0000414243`), and no subsequent hit after continuing. The
watchpoint is proven to fire in this process; per-LWP coverage of all 18
threads remains unverified because `libthread_db` was unavailable. Does
not prove later non-use. Grade unchanged rung 3 / rung 4 PARTIAL, NO r5.
