# Provenance — live555vorbis2shell (CVE-2026-137587)

Claim sources read 2026-11-26 (read-only provisioning, no external probing):
- CVE record https://www.cve.org/CVERecord?id=CVE-2026-137587
- Canonical CVE JSON https://cveawg.mitre.org/api/cve/CVE-2026-137587
- CNA advisory https://www.vulncheck.com/advisories/live555-before-2026.08.25-heap-out-of-bounds-read-via-parsevorbisortheoraconfigstr
- GHSA import https://github.com/advisories/GHSA-h6r7-83p9-fpf5 (unreviewed)
- Upstream changelog https://download.live555.com/changelog.txt (2026.08.25 entry)
- Fix patch https://github.com/live555-mirror/live555-mirror/commit/ef760df8569703b93f8df990a07086d7e760d171.patch
- Equivalent fix patch https://github.com/lengfeld/live555-unofficial-git-archive/commit/03015a0ae5ab3a1c53106eb938213d0d05e16f1e.patch

Pinned raw bytes:
- `pins/VorbisAudioRTPSource.cpp.vuln` from
  https://raw.githubusercontent.com/live555-mirror/live555-mirror/82ca996f9960c8ab69bf98570b116da107ca89f0/liveMedia/VorbisAudioRTPSource.cpp
  (6665 bytes; SHA-256 bf1e426a3761642089a8dafff635cd24b0b4fc609e779202832d1cb4f5c11ddf; git blob edce800dbd54842c6149c4277782d3f20d7c25d6)
- `pins/VorbisAudioRTPSource.cpp.fixed` from
  https://raw.githubusercontent.com/live555-mirror/live555-mirror/ef760df8569703b93f8df990a07086d7e760d171/liveMedia/VorbisAudioRTPSource.cpp
  (6776 bytes; SHA-256 6b80d6bd4be5eaf8923ddefb8501063cab74fa8918b67691dfd02ae3fa3c344d; git blob fd3bbe4e842884fad3b2011e4f8a06974d50b8f3)
- `pins/fix-ef760df.patch` (SHA-256
  7bbe420e829b0d4968030d0ab7a016c65d181cb431983a8bff59f18c5edf54ac).
All three are checked by `sha256sum -c PIN_HASHES.txt` from the `pins/`
directory; the manifest is a plain three-line digest list.

`gen_sink.py` emits `h/sink_vuln.cpp` (raw pinned lines 119-197) and
`h/sink_fixed.cpp` (raw pinned lines 119-200) unchanged, preceded by a
frontier-authored prelude and `#line 119 "liveMedia/VorbisAudioRTPSource.cpp"`.
`run-all.sh` re-verifies that each emitted file contains the exact pinned
slice before building. `h/driver.cpp` implements an exact-size libc base64
decoder (live555's `base64Decode` uses `new[]` and trims only padded input;
all vectors are unpadded) and calls the parser from a local argv string.
Everything except the copied sink bytes is frontier-authored scaffolding.

Correction preserved: the patch hunk header `@@ -183,13 +183,16 @@` and the
read-only scout's `:183/185/187` are patch-relative. Raw blob lines (counted
from line 1 of the pinned file) are `:186/:188/:190` for the three vulnerable
memmoves and `:186/:190/:194` for the fixed guards. The ASan assertions use
the raw numbers; the report records the discrepancy.

Negatives: plain build rc 0 on vector A, no rung-1/2 claim; no SDP, RTSP,
socket, full live555 build, loopback service or external target in any step.
All runs are local files and local processes. No harness step contacts a
network address.
