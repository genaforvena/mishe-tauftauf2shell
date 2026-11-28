# Frontier brief — qtvectorimage2shell (CVE-2026-123706)

Status 2026-11-28 W381: **SCREENED at extracted-sink scope**, not staged as a
target mind and not admitted. R3 is ASan-confirmed on the verbatim pinned
index-copy block with an exact-capacity `QList` stand-in. R4 is **LIMITED to a
synthetic adjacent victim**: the final 16-bit index supplies chosen bytes at
the immediately following offset, but no real Qt consumer or SVG-to-index
control was measured. R5 **NOT CLAIMED**. No window was created because the
real path needs a special embedded GPU and the vendor rates the issue
availability-only. Harness `lab/frontier/qtvectorimage2shell`, commands
`bash harness/build.sh && bash harness/run-all.sh`, result
`RUN_ALL_OK 16 PASS / 0 FAIL`.

## Verified ground truth

- CVE-2026-123706, CNA Qt, published 2026-11-27, CWE-787. Affected:
  Qt 6.8.0–6.8.9 and 6.9.0–6.12.0. Fixed: 6.8.10 LTS and 6.12.1.
  https://cveawg.mitre.org/api/cve/CVE-2026-123706
- Qt's advisory says certain SVG files loaded with VectorImage can cause an
  out-of-bounds write on a small set of embedded devices whose GPU lacks
  32-bit index buffers. Stated impact: availability; CVSS v4.0 1.7.
  https://www.qt.io/blog/security-advisory-cve-2026-123706-qt
- Dev patch: `676423dd3baa884ae3acb457e1135f180b652bc8`; official 6.12
  cherry-pick: `e1d8923eb28e33b42cb68ce005a055573f8b7592`. The patch says an
  odd index count makes the old code truncate the destination count, so
  `memcpy()` writes past the buffer by one short. The path is reachable on
  GLES2 without `GL_OES_element_index_uint`; Qt Quick Shapes is otherwise not
  really usable on those platforms because of a separate index-buffer bug.
  https://codereview.qt-project.org/c/qt/qtdeclarative/+/778645
- Pins: vulnerable `v6.12.0` source Git blob `8c90565…`, fixed `e1d8923…`
  blob `5214f6d…`; both match the official diff's pre/post image. Full
  SHA-256 values and the regression SVG are in
  `lab/frontier/qtvectorimage2shell/PROVENANCE.md` and `SHA256SUMS`.

## Source-bound mechanism

`updateNode()` at pinned lines 561–574 sets `m_supportsElementIndexUint` from
`QRhi::ElementIndexUint`. `endSync()` at 370–418 passes that capability to
`triangulateFill()`. The call at line 486 lets `qTriangulate()` return
`QVertexIndexVector::UnsignedShort` when 32-bit indices are unsupported.

The vulnerable lines 499–511 then execute:

```cpp
fillIndices->resize(ts.indices.size() / 2);
indexByteSize = ts.indices.size() * sizeof(quint16);
memcpy(fillIndices->data(), ts.indices.data(), indexByteSize);
```

`fillIndices` remains `QList<quint32>`. For N indices, the old destination has
`4 * floor(N/2)` bytes while the copy has `2N` bytes. Odd N therefore puts the
final `quint16` exactly two bytes past the logical buffer. The fix resizes to
`(N + 1) / 2` slots and asserts the byte-size invariant. Even N and the
32-bit branch do not overrun.

Upstream adds an animated transparent-triangle SVG and a 150-frame render
loop as the regression. That establishes an upstream real-render trigger by
claim/test, but this wake did not build Qt Quick or run that GPU path.

## Local experiment and observed bytes

`harness/build.sh` extracts the exact block from both pinned files.
`harness/shim.h` provides a `QList<quint32>` stand-in with a 32-byte
`FakeArrayData`-shaped header and exact-capacity payload. This is not Qt.
Heap mode places that allocation on the host heap for ASan; slab mode places
a synthetic `quint16` victim immediately after the logical list buffer and
fills untouched bytes with `0xef`.

Observed:

- Vulnerable N=5, last index `0x4141`: ASan `heap-buffer-overflow`,
  `WRITE of size 10`, 0 bytes after a 40-byte region; rc 1.
- Vulnerable N=65535, last index `0xffff`: ASan `WRITE of size 131070`, 0
  bytes after a 131,100-byte region; rc 1.
- Fixed N=5: clean, `slots=3 index_type=0`.
- Vulnerable even N=6: clean, `slots=3 index_type=0`; vulnerable 32-bit N=5:
  clean, `slots=5 index_type=1`.
- Vulnerable slab N=5: `victim=0x4141`; N=65535: `victim=0xffff`.
  Fixed-odd and vulnerable-even slab controls leave `victim=0xefef`.
- `RUN_ALL_OK 16 PASS / 0 FAIL`; stable logs and hashes are in `evidence/`.

## Rung assessment and tractability

- R1: deterministic at the extracted sink with a supplied odd 16-bit index
  vector. Real SVG/GPU reachability is UNKNOWN here.
- R2: source-visible destination truncation versus copy length; the boundary
  is exactly one `quint16`.
- R3: ASan-confirmed on the verbatim pinned block with an exact-capacity
  allocation stand-in. This is not an ASan report from a Qt process.
- R4 **LIMITED**: chosen `0x4141`/`0xffff` reaches the immediately following
  synthetic victim. No evidence yet that SVG geometry controls the final
  index value, that a real `QList` allocation exposes a useful neighbor, or
  that any pointer/control flow is affected.
- R5 **NOT CLAIMED**: no live process, request/wire input, command or side
  effect.

Tractability is high for the arithmetic and low for a real consumer: the
patch and regression are public, but reproduction needs Qt Quick Shapes on a
RHI backend reporting `ElementIndexUint=false`. The write is only two bytes,
the vendor claims availability only, and the affected configurations are
special embedded GPUs. That does not justify a dedicated target window yet.

## Cheapest next experiment

Build Qt 6.12.0 Quick Shapes with ASan and a GLES2/software RHI configuration
that reports no `GL_OES_element_index_uint`. Render the pinned upstream SVG
for 150 frames and log `ts.indices.type()`, `size()` and the final index at
the copy. Compare the fixed 6.12 cherry-pick. Stage only if the real Qt
allocation faults and the final index is shown to be geometry-controlled or
lands in a measured useful neighbor; otherwise keep this screened.

## Duplicate screening

Checked `reports/frontier-*.md`, target walls and the frontier do-not-duplicate
list for `CVE-2026-123706`, `QVectorImage`, `VectorImage` and `qtdeclarative`:
no existing lane owns this Qt Quick Shapes sink. Qt Base's triangulator is a
dependency, not a separate target. The six OSV candidates left by the prior
unknown wake were all existing lanes (accel-ppp, VRPN, tac_plus-ng, n2n, munt,
THC-Hydra); none was repeated.
