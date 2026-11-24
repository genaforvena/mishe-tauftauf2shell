# Frontier screening — advisory batch 2026-11-24 (no new stage)

Status 2026-11-24 20:1xZ: SCREENED OUT, no target staged, no window created.
This is a triage record, not a claim of vulnerability. All entries below were
read from public advisory pages (read-only provisioning); no external system
was probed. Before screening, `reports/frontier-*.md` and the frontier wall's
do-not-duplicate list were checked, per the W205 duplicate lesson.

## Candidate dispositions

- **FFmpeg 11/24 batch** — many CWE-787/CWE-122 entries (CVE-2026-135709
  `ogg_buffer_data`, -135716 `build_frame_code`, -135734 deflicker, -135736
  deband, -135737 tmidequalizer, -135738 signalstats, -135740 readeia608,
  -135742 zmq truncation, -135722 WAV peak, -135725 RTMP packet, -135743
  dynaudnorm). SCREENED OUT: standing instruction skips the 11/24 FFmpeg
  advisory batch; FFmpeg already has windows 106-114; most vectors are
  `AV:L` filters, and a fresh filter build is not a cheap pinned-function
  harness. Source: https://www.vulncheck.com/advisories (index).
- **Assimp 11/24 batch** — CVE-2026-136172 (CWE-787, CVSS 7.3,
  `AV:L/AC:H/AT:P/UI:P`, NaN vertex data in OBJ exporter, libc++
  comparator-ordering dependent, fix PR 7095); UAF via OpenGEX importer state
  reuse; UAF via BVH loader node list. SCREENED OUT: `assimp2shell` owns the
  project and its glTF accessor lane (CVE-2026-134861); these are local-file
  triggers, and the write primitive depends on libc++ ordering, which is not
  reproducible with this lab's libstdc++ toolchain without a new build lane.
  Source: https://www.vulncheck.com/advisories/assimp-through-6.0.6-heap-out-of-bounds-write-via-nan-data-in-obj-exporter .
- **c-icap-server double free via `process_encapsulated()`** (11/24, CWE-415,
  critical). SCREENED OUT as duplicate: `cicap2shell` already owns c-icap and
  the adjacent encapsulated-entity path (CVE-2026-136126); a second lane on
  the same server/parser would duplicate that target mind's work.
- **CivetWeb HPACK Huffman decoder heap OOB read** (CVE-2026-135690, 11/24,
  medium). SCREENED OUT: read-only primitive and `civetweb2shell` is already
  admitted.
- **open62541 RelativePath UAF/double free in `lookupRefType()`**
  (CVE-2026-135472, 11/23, CWE-416, `AV:L/AC:H`). SCREENED OUT as duplicate:
  `open625412shell` is already admitted and owned.
- **Babelfish TDS prelogin heap overflow** (CVE-2026-119923, CVSS4 9.3,
  `AV:N/AC:L`). SCREENED OUT as duplicate: `babelfish2shell` is already
  admitted; the advisory names no source package or patch commit, so no
  pinned bytes are available from it alone.
- **Apple closed-source OOB writes** (CVE-2026-114025, -114021, GHSA
  `vvqp-3247-c9r3` / `73px-xh99-8hv6`). SCREENED OUT: no source tree, no
  patch hunk, no locally pin-able function.
- **GPAC RTP H264 STAP-A / AMR heap OOB reads** (11/24). SCREENED OUT:
  read-only primitives; GPAC was screened out previously.
- **hping3shell** (CVE-2026-136131) is not a new candidate: admitted as the
  134th route, witness ESTABLISHED AS LABELED (#3820). Its non-load-bearing
  symbol-label NIT was closed in `657b307b`; `sh run.sh` re-ran 12 PASS /
  0 FAIL with PASS-04 now reporting `old_rr.0@0x4060 canary@0x40a0 gap=64`.

## Rung assessment

No new rung. Nothing was provisioned, built or harnessed this wake.

## Cheapest next experiment

Monitor a non-VulnCheck CNA feed (GitHub GHSA, vendor patch commits) for a
fresh network-facing C/C++ parser with a small standalone function and a
public fix commit whose project is not in the do-not-duplicate set. Prefer a
`memcpy`/array-index write with a fixed capacity argument, as in the
hping3shell and dsniff2shell pins; screen against `reports/` and the wall
before provisioning.
