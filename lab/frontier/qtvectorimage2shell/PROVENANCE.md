# qtvectorimage2shell — provenance and evidence ledger (W381, 2026-11-28)

## Claim and pins

- CVE-2026-123706, CNA Qt, published 2026-11-27T11:15:53Z, CWE-787.
  Qt 6.8.0–6.8.9 and 6.9.0–6.12.0 are affected; 6.8.10 LTS and 6.12.1
  are fixed. Qt rates this availability-only, CVSS v4.0 1.7, on a small set
  of embedded GPUs without 32-bit index-buffer support.
  https://cveawg.mitre.org/api/cve/CVE-2026-123706
  https://www.qt.io/blog/security-advisory-cve-2026-123706-qt
- Upstream dev fix `676423dd3baa884ae3acb457e1135f180b652bc8`; official
  6.12 cherry-pick `e1d8923eb28e33b42cb68ce005a055573f8b7592`.
  https://codereview.qt-project.org/c/qt/qtdeclarative/+/778645
- Pinned vulnerable source: Qt `v6.12.0`,
  `src/quickshapes/qquickshapegenericrenderer.cpp`, SHA-256
  `ebfdc04f76d6740b83ab86c4addfb18b75d9455e021c1eff5b13c03c9ca0285a`.
  Git blob `8c90565796e5cb6b94ab9f1496d9822beb943e7a`, matching the official
  diff's preimage.
- Pinned fixed source: commit `e1d8923eb28e33b42cb68ce005a055573f8b7592`,
  same path, SHA-256
  `5a0f8706009d1fb32c1880bacf6da097212d903671094ce86c7bcaad14fece39`.
  Git blob `5214f6d47d956e4d5b9cfc9322bd0ec902c791a5`, matching the official
  diff's postimage.
- Official 6.12 patch SHA-256
  `861bf7fb260897b13f2fdd36924be2eddd63f10a14c90b735b0627d1252192dc`.
  Upstream regression SVG SHA-256
  `cf25f45efce5f4ecf982c99f6c0e956e15a790651159b21be0ebfe1e17c369c5`.
  `qtriangulator_p.h` at Qt `v6.12.0` SHA-256
  `f6bea7eff8e12d25bc6a22e0422efeeca9e3d18f76be97627b15735bd1c615ac`.
  All five pins are checked by `SHA256SUMS`.

## Source-bound mechanism

`QQuickShapeGenericRenderer::updateNode()` at pinned lines 561–574 queries
`QRhi::ElementIndexUint`; `endSync()` at 370–418 passes the result as
`supportsElementIndexUint` to `triangulateFill()`. At 486, `qTriangulate()`
therefore may return `QVertexIndexVector::UnsignedShort` when the backend
lacks 32-bit index support.

The vulnerable block at pinned lines 499–511 keeps `fillIndices` as a
`QList<quint32>`. For N 16-bit indices it calls
`fillIndices->resize(N / 2)`, providing `4 * floor(N/2) = 2N - 2` bytes
when N is odd, then copies `indexByteSize = N * sizeof(quint16) = 2N` bytes.
The final attacker-influenced index is a two-byte store immediately past the
logical buffer. Even N and the 32-bit branch are bounded. The fixed block
rounds up to `(N + 1) / 2` quint32 slots and adds a size assertion.

The upstream regression is an animated transparent triangle; its test grabs
150 frames. That real Qt/GPU path was **not run here**.

## Harness scope

`harness/build.sh` extracts the exact block from each pinned source file,
from `size_t indexByteSize;` through the `memcpy`, excluding the function's
closing brace. Extracted block SHA-256:

- vulnerable `dad690cf366482c5ec304aa5aeb36efe4239dad3095db7c60af85ac16be24d21`
- fixed `0f5cbecaa293974d23378803c1bff5ef8748733f9026a874eae799ff01890246`

`harness/shim.h` supplies only `QVertexIndexVector`, `QTriangleSet`,
`QSGGeometry::Type`, `Q_ASSERT`, and a `QList<quint32>` stand-in. Heap mode
allocates a 32-byte `FakeArrayData` header plus exactly N elements, modeling
the source's exact-capacity buffer boundary; it is not Qt. Slab mode uses the
same layout inside a 200,000-byte local array and initializes unused bytes to
`0xef`, so the two bytes immediately after the logical list buffer form a
readable synthetic victim. No SVG parser, triangulator, Qt, GPU, network,
listener or external system is involved.

Commands:

```
bash harness/build.sh
bash harness/run-all.sh
```

Observed on GCC 13.3.0, `-O0 -g`, host ASan:

- Vulnerable odd N=5, last index `0x4141`: ASan `heap-buffer-overflow`,
  `WRITE of size 10`, 0 bytes after a 40-byte region; rc 1.
- Vulnerable maximum odd N=65535, last index `0xffff`: ASan
  `WRITE of size 131070`, 0 bytes after a 131,100-byte region; rc 1.
- Fixed odd N=5: clean, `slots=3 index_type=0`.
- Vulnerable even N=6: clean, `slots=3 index_type=0`.
- Vulnerable 32-bit N=5: clean, `slots=5 index_type=1`.
- Vulnerable slab N=5: `slots=2 index_type=0 victim=0x4141`.
- Vulnerable slab N=65535: `slots=32767 index_type=0 victim=0xffff`.
- Fixed odd and vulnerable even slab controls: victim remains `0xefef`.
- `RUN_ALL_OK 16 PASS / 0 FAIL`. Stable logs and their hashes are under
  `evidence/`; raw PID/address-specific logs are gitignored.

Clean `git archive` replay at commit `80dac20d` (archive SHA-256
`b5c04b9ce9af2be5eaefc917b0865625504b49b39ad5c5b6f184390e113c2d1a`)
in a fresh `/tmp` directory reproduced `BUILD_OK` and `RUN_ALL_OK 16 PASS /
0 FAIL` with no file outside the archive.

## Evidence boundary

R3 is confirmed only for the verbatim extracted block against the exact-size
allocation stand-in. The synthetic slab demonstrates that the copied final
index can be chosen bytes at the immediately following offset, but no real
Qt allocation, SVG-controlled index, adjacent object, pointer or control flow
was measured. R4 is therefore LIMITED to that stand-in mechanic; the real
consumer path is UNKNOWN. R5 is not claimed. The candidate is screened, not
staged, and has no target window.
