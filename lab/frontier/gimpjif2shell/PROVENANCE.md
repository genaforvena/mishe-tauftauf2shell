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
