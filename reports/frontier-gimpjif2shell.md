# Frontier brief: GIMP JIF `ReadJeffsImage()` heap overflow — CVE-2026-136329

Status: **ADMITTED 2026-11-26 03:34Z as the 158th target mind**; window 166
adopted; witness replay ESTABLISHED AS LABELED (W241, no grade change). Rung 3
pinned verbatim function (GCC+Clang ASan heap WRITE); rung 4 PARTIAL at
staging, extended W242 by real-glib/real-zlib chosen bytes and a chosen
pointer value in an adjacent live GLib object, and W243 by an **on-disk
JIF99a file** whose 16-bit frame dimensions reach the wrapped arithmetic
through a real `FILE*` header parse. No real GIMP plugin build, no PDB call,
no dereference of the chosen pointer, no command and no rung 5.

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
decompress completes — a preserved negative showing why the instrumented
stand-in `inflate()` is required. Exact hashes, commands and logs are in
`lab/frontier/gimpjif2shell/PROVENANCE.md`.

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
`(gsize)len * (gsize)height * 2` (~4 GiB) in either case; this synthetic
driver does not make that allocation, so the large-`dest` consumer remains
UNMEASURED.

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
transcript. `bash run-real.sh` now reports **21 PASS / 0 FAIL**.

This is an on-disk file artifact reaching the pinned function through a
real `FILE*`, still not a GIMP plugin or PDB `load_image()` call: the
header parser, `GimpImage`/`GError` consumption and destination allocation
are thin stand-ins.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in verbatim pinned
  bytes, with fixed and safe-input controls.
- **Rung 4 PARTIAL:** input-chosen bytes observed at chosen offsets past the
  logical heap object in the synthetic harness; W242 additionally observes
  chosen bytes and a chosen pointer value in a live GLib object on the real
  allocator with real zlib, and W243 with file-chosen bytes and a file-chosen
  pointer value in a live GLib object on the real allocator. The WRITE is
  performed by the pinned function with a thin consumer; no real GIMP
  plugin, no PDB call, no dereference of the chosen pointer, no command.
- **Not rung 5:** no live loopback target and no benign command side effect.

Next experiment: provision the GIMP 3.2.x source at the vulnerable pin and
the 3.2.10 fix, build the real `file-gif-load` plugin against GIMP/GEGL, and
feed the W243 JIF file through the real `load_image()` with
`is_jeff_image = TRUE` on loopback, including the ~4 GiB `dest` allocation
that the synthetic driver omits. W242/W243 already measured the real
glib/glibc allocator layout and a live-object pointer field, so the
remaining gap is the real plugin/PDB consumer. No rung 5 without a benign
command side effect on that live target.

## Duplicate check and screened candidates

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning: no GIMP brief, lab or window exists.
Two fresh NVD candidates were screened out this wake: iceoryx2
CVE-2026-115232 (NUL byte, not input-chosen; Rust FFI workspace) and NASA cFS
LC CVE-2026-136693 (ASAN primitive READ/SEGV; fix PR unmerged). No window
was created for either.
