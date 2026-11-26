# pjproject2shell — status (frontier staging, 2026-11-26)

State: **STAGED by frontier W239**, not admitted; witness replay UNKNOWN.
Brief `reports/frontier-pjproject2shell.md`, harness
`lab/frontier/pjproject2shell/`, seed wall `.mishe-tauftauf/walls/pjproject2shell.md`,
charter `.mishe-tauftauf/charters/pjproject2shell.md`. The person owns wake
units and full-flag sync; the operator owns admission.

Claim: `CVE-2026-77396` / GHSA-6p2p-5wf8-h5hr (GitHub CNA, published
2026-07-13, Moderate, CWE-122/CWE-787): pjproject <= 2.17 AVI player uses the
file-supplied video chunk length as the read size into a frame buffer sized
from declared video dimensions; the only guard is a release-build no-op
assertion. Fix commit `7ecc6584969a923c4190b6912afbf5952b5a4b9f`, parent
`c1ea7648fb53f945493972a23133b9e0d3e4a1fe`; the advisory lists no patched
version, so upstream version boundaries are UNKNOWN.

Pins: full `pjmedia/src/pjmedia/avi_player.c` from both commits plus
byte-exact excerpts of the video branch (hashes in `PROVENANCE.md`). The
vulnerable body asserts `frame->size >= ch.len` (no-op in release) and calls
`file_read3(fd, frame->buf, ch.len, ...)`; the fixed body clamps to
`frame->size`, skips unread chunk bytes and sets the frame size to the
clamped length. GCC and Clang ASan report `heap-buffer-overflow`,
`WRITE of size 64`, 0 bytes after a 48-byte region, write frame
`pins/avi-vulnerable.inc:15` in `avi_get_frame()`. Plain readback:
`CANARY_AFTER=4d495348452d504a50524f4a45435421` (chosen
`MISHE-PJPROJECT!` at frame bytes 48..63). Fixed build stays at 48 bytes;
safe input is clean in both bodies. `run-all.sh`: 29 PASS / 0 FAIL.

Grade: **rung 3 pinned verbatim / rung 4 PARTIAL** (chosen bytes past a
synthetic logical frame). No real library build, crafted AVI, pointer,
wire, command or r5. The stand-in file caps the copy at 64 present bytes;
the real claim permits a much larger file-supplied length.

## Next

1. Done in-tree and from a clean archive: replay passed; witness verdict
   requested. Next owner: witness, then operator admission.
2. Build real pjproject at the vulnerable parent with
   `PJMEDIA_HAS_VIDEO=1` and ASan; synthesize a minimal AVI with small
   declared dimensions and a `00dc` chunk of 64+ chosen bytes; drive
   `pjmedia_avi_player_create_streams()` and a frame pull to measure the
   real write and any adjacent live object.
3. Replay the same AVI against the fix commit to confirm the clamp. Only
   after a real-consumer WRITE with vulnerable/fixed/safe controls should a
   pointer-bearing target be considered; keep the no-command ceiling.

## Receipts

- Provisioning 2026-11-26 02:06Z: read-only fetch of two raw upstream
  `avi_player.c` blobs; advisory read from GitHub HTML and API. No AVI was
  sent to any external system.
- Author run 2026-11-26 02:09Z: `bash run-all.sh` in-tree returned
  `TOTAL: 29 PASS / 0 FAIL`, rc 0; raw logs in `out/`.
- Clean archive 2026-11-26 02:09Z: `git archive 814e9392
  lab/frontier/pjproject2shell` into `/tmp/w239-pjproject-clean`;
  unmodified `run-witness.sh` (sha256
  `28added488bf8fd11a1e896b933c28c2f686394d5ceca34fc232c3f994e2335f`)
  returned `WITNESS REPLAY PASS`, `TOTAL: 29 PASS / 0 FAIL`, rc 0, four pins
  exact; in-tree replay identical.
- Window created 2026-11-26T02:10:10Z on the inner tmux socket: index 164,
  session `mishe-tauftauf2shell-current`, panes `%330`/`%331`, `dead=0`,
  captures 911/256 bytes, both processes live (`tail -F` status above,
  `plant_view --role pjproject2shell --output --log --follow` below).
  Registered in `.mishe-tauftauf/operator/window-registry.json` (165 windows
  / 165 unique names). Staged by frontier, not admitted.
