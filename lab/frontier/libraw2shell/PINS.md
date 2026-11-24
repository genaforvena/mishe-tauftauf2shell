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
| `evidence/wl-probe-11036.input` | W6 variant, WhiteLevel 11,036, exact `0x4141` at index 68,644 | `b856c1c62d48a63f9c3d42a4d32be11033c0dc405fcbcc063f6b9ddaa6d61215` |
| `evidence/wl-probe-11035.input` | W6 calibration neighbour, `0x4142` | `8d865153c01b4128e270fa1e5bcc9988865dae48829c94bca5eb955d1d1cce09` |
| `evidence/wl-dead.input` | W6 negative target, WL 3,234 -> `0xdeb3`, not `0xdead` | `6ed079d8c97e89bdd3eff5367064ef32fffa4b4d66e5746cbc53a24f6c5192da` |
| `evidence/dim1024-wl11036.input` | W7 negative: W6 WL does not transfer to D=1024 | `6df37eb18792169d21fbd60179a1368a992fe1e1537c22d89ed7a7e40e76ae70` |
| `evidence/dim1024-wl6864.input` | W7 target-1 probe at far index, `0x4146` | `805e7b4007e4ae49dfde1badd8c8a67d4ed93d9b2d4e20b55ed94158e02ef502` |
| `evidence/dim1024-wl6866.input` | W7 target-1 probe, `0x4142` | `65dca5a48b6f48d6a316632bd8ddc9cb6cb17be2da138d12b9ee927f728d2049` |
| `evidence/dim1024-wl6867.input` | W7 target-1 probe, `0x413e` | `aab51772ae94f86efd3faf89457b3944a0d1d2142da1f196713b97f9e8caf4f3` |
| `evidence/dim1024-wl24600.input` | W7 target-2 bracket, `0x1235` | `c0c5df90f5f03a4b8625b784e4e653e240a548f2e47e76a06398b6ed2ab50fbc` |
| `evidence/dim1024-wl24601.input` | W7 exact pre-chosen `0x1234` at index 268,324 | `b894e63c5e70cf685bb1a309e9c14ee265bcec8068a6bbe4aac55023138c0f77` |
| `evidence/dim1024-wl24602.input` | W7 target-2 bracket, `0x1233` | `d35f0d336eab74161fe9cef1fc936a882b516df8a69b747af412edb9b3d35f93` |
| `evidence/dim1024-wl24603.input` | W7 second exact `0x1234` hit | `1fedbfcf3f4807ac37e2cce3467a2fb34b29d04e56b48ee5f366f264482ffa55` |
| `evidence/dim1024-wl24606.input` | W7 sweep, `0x1233` | `566c84a57ce21f5e73128a02104c2e0bc1549806f0a4c0ec85a9c9d2581f0b68` |
| `evidence/dim1024-wl24607.input` | W7 sweep, `0x1233` | `0d2d9e00f52fbd90f2973bfb85a9c343267ab3c1a4b609b8ef2e4f8907b40191` |
| `evidence/dim1024-wl24608.input` | W7 sweep, `0x1233` | `f01be451f0051806b18aa820b759c231e11579fd9aca2e731e1d2a5ed7a99782` |
| `evidence/dim1024-wl24609.input` | W7 sweep, `0x1233` | `37cebe51c26b055895d07d0cffa1d0ef7c0875fa8bca43f30a5f825bedaea5d9` |

Advisory: `https://www.vulncheck.com/advisories/libraw-0.22.3-heap-out-of-bounds-write-via-xtrans-interpolate`
(CVE-2026-135176, 2026-11-23). Report: `https://github.com/LibRaw/LibRaw/issues/894`.

Vulnerable lines verified against the pinned bytes, not rendered web line numbers:
`src/demosaic/xtrans_demosaic.cpp:176-179` (allocation/memmove), `:427` (store),
`src/demosaic/misc_demosaic.cpp:68-79` (stale `iwidth`/`iheight`).

No upstream merged fix was found; the fixed control is the reporter's proposed
patch. Fixed status is UNKNOWN.
