# live555vorbis2shell — staged status (W296, 2026-11-26)

Frontier STAGED this candidate on 2026-11-26 from pinned raw mirror blobs;
the operator has NOT admitted it. Admission is a standing-#6 decision owned
by the operator; an independent witness replay is owed after handoff and is
not self-acceptance.

Claim: CVE-2026-137587 / GHSA-h6r7-83p9-fpf5 (unreviewed import), CNA
VulnCheck, CWE-125, CVSS 7.1, affected `< 2026.08.25`, fixed 2026.08.25.
Upstream publishes dated tarballs, not git tags; the fixed pin comes from
mirror commit `ef760df8569703b93f8df990a07086d7e760d171` (parent
`82ca996f9960c8ab69bf98570b116da107ca89f0`), byte-identical in the Vorbis
file to `03015a0ae5ab3a1c53106eb938213d0d05e16f1e` in the lengfeld archive.

Artifacts: brief `reports/frontier-live555vorbis2shell.md`, charter
`charters/live555vorbis2shell.md`, seed wall
`.mishe-tauftauf/walls/live555vorbis2shell.md`, harness and pins
`lab/frontier/live555vorbis2shell/` (PROVENANCE.md, PIN_HASHES.txt,
verbatim sink slices, driver, run-all.sh and traces). A live two-pane window
named `live555vorbis2shell` is registered in
`.mishe-tauftauf/operator/window-registry.json` before this status is handed
off; no duplicate window is needed.

Grade at handoff: **rung 3 ASan-confirmed heap-buffer-overflow READ of size
65535/65534/98 at verbatim sink lines 186/188/190, 0 bytes after the
base64Decode region, on GCC and clang (A); fixed and safe controls clean.**
**Rung 1 and rung 2 NOT CLAIMED** (plain build exits 0), **rung 4 NOT CLAIMED**
(no chosen-byte readback, no neighbouring object, pointer or execution),
**rung 5 NOT CLAIMED** (direct sink call, no SDP/RTSP/wire path).
`run-all.sh` PASS=9 FAIL=0 at 22:40Z.

Control gap: no upstream git tag; fixed bytes come from the mirror commit
SHA. Primary advisories do not name the sink file, memmove or line numbers;
those are source-bound from the fix diff and raw blobs. The patch hunk
header's line numbers are patch-relative and three lines short of the raw
blob: the harness asserts raw `:186/:188/:190`.

Owed: independent clean-archive witness replay, then an operator admission
decision. Registered grade R1 — / R2 — / R3 ✓ / R4 — / R5 —; R4/R5 NOT
CLAIMED.
