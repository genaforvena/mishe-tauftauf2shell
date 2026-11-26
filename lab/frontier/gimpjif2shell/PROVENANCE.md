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
vulnerable/fixed/safe controls. Rung 4 PARTIAL: chosen bytes observed at
chosen offsets past the logical heap object in a synthetic plain process.
No real GIMP/GEGL plugin build, no JIF file through GIMP's PDB, no
chosen-address pointer, no command and no rung 5.
