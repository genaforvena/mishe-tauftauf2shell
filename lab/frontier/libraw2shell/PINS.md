# PINS — libraw2shell (W197)

| Artifact | Origin | sha256 |
|---|---|---|
| `pinned/LibRaw-0.22.3.tar.gz` | `https://github.com/LibRaw/LibRaw/archive/refs/tags/0.22.3.tar.gz` | `7edf96c5b70cff88980a02ab0fc8af125cb6a4a377985573c654439d9d02355c` |
| `pinned/poc_xtrans_oob_write.zip` | GitHub user attachment linked in issue #894 | `619e741e27bd0394270ec4eadc149d24b10aa03415de63cc479b2a16512abe61` |
| `pinned/poc_xtrans_oob_write.input` | extracted from the zip | `c7940268cfb817adc4d5d42e9327a93fd042d7cd4cda8bc4b4ed6f1c4435dae2` |
| `pinned/fix-894.patch` | verbatim two-line fix proposed in issue #894, hunk counts corrected | `32fc61e5a52c0b393fd09175bf9b1283c29065767613d15a16e421dd1a2afc9c` |
| `craft_poc.py` | lab-only negative-result artifact (chosen-pixel attempts) | `cb53b7c1b0ae10652214215e1b969d4f57e8bef67bb4425e1da8a375c363ff44` |

Advisory: `https://www.vulncheck.com/advisories/libraw-0.22.3-heap-out-of-bounds-write-via-xtrans-interpolate`
(CVE-2026-135176, 2026-11-23). Report: `https://github.com/LibRaw/LibRaw/issues/894`.

Vulnerable lines verified against the pinned bytes, not rendered web line numbers:
`src/demosaic/xtrans_demosaic.cpp:176-179` (allocation/memmove), `:427` (store),
`src/demosaic/misc_demosaic.cpp:68-79` (stale `iwidth`/`iheight`).

No upstream merged fix was found; the fixed control is the reporter's proposed
patch. Fixed status is UNKNOWN.
