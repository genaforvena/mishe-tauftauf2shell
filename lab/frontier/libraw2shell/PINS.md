# PINS — libraw2shell (W197)

| Artifact | Origin | sha256 |
|---|---|---|
| `pinned/LibRaw-0.22.3.tar.gz` | `https://github.com/LibRaw/LibRaw/archive/refs/tags/0.22.3.tar.gz` | `7edf96c5b70cff88980a02ab0fc8af125cb6a4a377985573c654439d9d02355c` |
| `pinned/poc_xtrans_oob_write.zip` | GitHub user attachment linked in issue #894 | `619e741e27bd0394270ec4eadc149d24b10aa03415de63cc479b2a16512abe61` |
| `pinned/poc_xtrans_oob_write.input` | extracted from the zip | `c7940268cfb817adc4d5d42e9327a93fd042d7cd4cda8bc4b4ed6f1c4435dae2` |
| `pinned/fix-894.patch` | verbatim two-line fix proposed in issue #894, hunk counts corrected | `32fc61e5a52c0b393fd09175bf9b1283c29065767613d15a16e421dd1a2afc9c` |
| `craft_poc.py` | lab-only negative-result artifact (chosen-pixel attempts) | `cb53b7c1b0ae10652214215e1b969d4f57e8bef67bb4425e1da8a375c363ff44` |
| `craft_nonzero_poc.py` | lab-only nonzero-pixel variant generator (W2) | `004ff4350d66000a0c941956bfc910ea16d561c0f9a7300477f448e1917cf862` |
| `evidence/nonzero-oob.input` | derived from pinned PoC by `craft_nonzero_poc.py` | `b59f64e9837b06a8f0ca07a3776e961e7d0493794e0d6cb38fbcb80022069341` |
| `craft_whitelevel_poc.py` | lab-only WhiteLevel steering generator (W3) | `ab5ace42392c8558d4c939d1524a9ffb29a112acb021b8141ce9a0dd8b30d1cf` |
| `evidence/whitelevel2048.input` | W3 variant, WhiteLevel 2,048 | `d398d0e78077a07cb0fb4572fce16805de1d3d31bf5d0718355b2b80c52c35f5` |
| `evidence/whitelevel4095.input` | W3 variant, WhiteLevel 4,095 | `8d9b520418207522efb8450c2aa80dbbdb3eb6fbe6da97ffe484e2f86d7cb905` |
| `evidence/whitelevel8191.input` | W3 variant, WhiteLevel 8,191 | `50c91fbbdbd49baba44ab2eab51fe19d726245c1d8aca6fe056cd09e7c3ce42b` |
| `evidence/whitelevel16383.input` | W3 variant, WhiteLevel 16,383 | `2547a078ca25f315e957d30614a9c4370e0657262036487d0fcdda2390c78bc8` |
| `craft_dimension_poc.py` | lab-only frame-size steering generator (W5) | `2703d113236f4baf8b6a164b8198448d4b4b89d33d7e9c81f2831d91c27f3e55` |
| `evidence/dim1024.input` | W5 variant, 1024x1024 frame from `evidence/nonzero-oob.input` | `a0e318197405aa5df29a3f5c1a0916487e0eb8c67c55ec00c03dd0308ff2da3a` |

Advisory: `https://www.vulncheck.com/advisories/libraw-0.22.3-heap-out-of-bounds-write-via-xtrans-interpolate`
(CVE-2026-135176, 2026-11-23). Report: `https://github.com/LibRaw/LibRaw/issues/894`.

Vulnerable lines verified against the pinned bytes, not rendered web line numbers:
`src/demosaic/xtrans_demosaic.cpp:176-179` (allocation/memmove), `:427` (store),
`src/demosaic/misc_demosaic.cpp:68-79` (stale `iwidth`/`iheight`).

No upstream merged fix was found; the fixed control is the reporter's proposed
patch. Fixed status is UNKNOWN.
