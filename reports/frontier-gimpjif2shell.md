# Frontier brief: GIMP JIF `ReadJeffsImage()` heap overflow — CVE-2026-136329

Status: **STAGED 2026-11-26 W241**; window 166 created and registered
03:01Z; operator admission and witness replay owed. Rung 3 pinned verbatim
function (GCC+Clang ASan heap WRITE); rung 4 PARTIAL
(chosen bytes past the 260-byte heap buffer in a synthetic plain process).
No real GIMP/GEGL build, no JIF file through GIMP's PDB, no chosen-address
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
`WRITE of size 1`, 0 bytes after a 260-byte region, write frame
`ReadJeffsImage pins/jif-vulnerable.inc:106`, allocation frame
`pins/jif-vulnerable.inc:40`. The fixed build rejects the input
(`MODE=attack RC=0 ERR=image data`); safe input (`4x4`, no alpha) is
ASan-clean in both bodies. The plain real-libz build reads sixteen chosen
`0x4d` bytes at `indexes + 260` (`CANARY_AT=260 FIRST=4d4d…`). An
ASan build using the uninstrumented system libz stays silent while the
decompress completes — a preserved negative showing why the instrumented
stand-in `inflate()` is required. Exact hashes, commands and logs are in
`lab/frontier/gimpjif2shell/PROVENANCE.md`.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in verbatim pinned
  bytes, with fixed and safe-input controls.
- **Rung 4 PARTIAL:** input-chosen bytes observed at chosen offsets past the
  logical heap object in a synthetic plain process. The WRITE is performed
  by an ASan-visible stand-in consumer; no real GIMP plugin, no JIF wire
  path through the PDB, no chosen-address pointer, no command.
- **Not rung 5:** no live loopback target and no benign command side effect.

Cheapest next experiment: build only `file-gif-load.c` against a minimal
GIMP/GEGL stub, feed the published JIF PoC through `load_image()` with
`is_jeff_image = TRUE`, and check whether the real GEGL/glib allocator
layout puts attacker-chosen bytes in an adjacent object with a controllable
offset. Compare 3.2.x vulnerable and the 3.2.10 fix. Keep the no-pointer,
no-command ceiling until a real consumer is measured.

## Duplicate check and screened candidates

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning: no GIMP brief, lab or window exists.
Two fresh NVD candidates were screened out this wake: iceoryx2
CVE-2026-115232 (NUL byte, not input-chosen; Rust FFI workspace) and NASA cFS
LC CVE-2026-136693 (ASAN primitive READ/SEGV; fix PR unmerged). No window
was created for either.
