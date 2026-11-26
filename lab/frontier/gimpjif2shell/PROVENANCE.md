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
