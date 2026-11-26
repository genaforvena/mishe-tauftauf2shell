# live555vorbis2shell — admitted status (W296/W297, 2026-11-26)

Admitted by the operator at 22:5xZ under standing #6 as the 191st declared
target mind: claim source CVE-2026-137587 / GHSA-h6r7-83p9-fpf5, affected
`< 2026.08.25`, fixed 2026.08.25 (mirror pins `bf1e426a…` vulnerable,
`6b80d6bd…` fixed), claimed unchecked `memmove` reads in
`parseVorbisOrTheoraConfigStr()`, and a named rung-4 experiment (chosen-byte
readback in the extracted harness, then a loopback RTSP SDP vulnerable/fixed
pair). No duplicate CVE, GHSA or sink lane. Window 199 was adopted as-is on
the inner tmux socket (panes %404/%405, dead=0, one registry entry). The
independent witness replay (W297) is recorded below; author reports are not
self-acceptance.

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

Owed: none for admission or replay. W297 independent witness replay (tape
#5893/#5894) CLOSED ESTABLISHED AS LABELED at the registered rung-3 scope,
no counterexample and no grade change; folded into `research-manifest.json`.
Named depth experiment under standing #7: extend the local driver to print
the three destination buffers and show attacker-chosen bytes read past the
source allocation (rung 4 in the extracted harness only); then build the
pinned pre-fix RTP client and replay a loopback RTSP SDP `a=fmtp config=`
against a vulnerable/fixed pair for rung 2 and any real-client readback.
Keep plain rc=0, fixed commit `ef760df8569703b93f8df990a07086d7e760d171`
(hardened file `6b80d6bd4be5eaf8923ddefb8501063cab74fa8918b67691dfd02ae3fa3c344d`)
and the safe-vector control. Registered grade R1 — / R2 — / R3 ✓ / R4 — /
R5 —; R4/R5 NOT CLAIMED.

## Operator clean-archive admission replay (22:48Z)

From `git archive HEAD lab/frontier/live555vorbis2shell` with `runs/` and the
five prebuilt harness binaries removed: pins 3/3 OK against
`PIN_HASHES.txt`, runner sha256
`9cd39b0a13dd6e1f0fde58e65de9bfce9ba18db0e22155afcc21b92ce8a67db8`,
`sh run-all.sh` rc 0, `PASS=9 FAIL=0`. Fresh GCC ASan: `READ of size
65535/65534/98` at verbatim `liveMedia/VorbisAudioRTPSource.cpp:186/:188/:190`
in `memmove`, 0 bytes after the exact-size `base64Decode` `new[]` region;
clang ASan reproduces at `:186`. Fixed pin and safe vector rc 0 without
ASan, plain vulnerable A rc 0 with `id=65535 comment=0 setup=0 ident=0`
(rung 1/2 negative preserved). The patch hunk's `:183/:185/:187` are
patch-relative; raw pinned lines are authoritative.
