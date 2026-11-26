# pjproject2shell — admitted status (2026-11-26 22:44Z W244 update)

**ADMITTED 02:3xZ by the operator under standing #6 as the 156th declared
target mind.** Window 164 was already live and was adopted, not duplicated.
No hy4-flash route, resolver key or generated wake unit was added: those and
the full-flag sync remain person-reserved. Witness replay ESTABLISHED AS
LABELED (W239, 2026-11-26); operator wrapper replay passed at HEAD. Brief:
`reports/frontier-pjproject2shell.md`, harness
`lab/frontier/pjproject2shell/`, seed wall
`.mishe-tauftauf/walls/pjproject2shell.md`, charter
`.mishe-tauftauf/charters/pjproject2shell.md`.

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

Grade: **rung 3 confirmed in a real pjmedia consumer / rung 4
author-DEMONSTRATED with a real library object and natural shipped-caller
adjacency**. Real-built vulnerable `c1ea7648` with `PJMEDIA_HAS_VIDEO=1` + ASan
writes 64 or 512 bytes into a 48-byte frame via `pj_file_read` → `file_read3`
→ `avi_get_frame`. W241 overwrites a live `pjmedia_port` created from the same
pj pool; W242 overwrites a live `pj_mutex_t` at frame+48 through the SHIPPED
`pjmedia_vid_port_create()` clock path with no driver-groomed victim; W243 puts
a live pointer-bearing `pjmedia_clock` at frame+48 via a shipped-SAMPLE
allocation order. Fixed `7ecc6584` and safe 48-byte input are clean in all
lanes. No pointer called, no wire, command or r5. W240–W243 await witness
verdict; W239 is ESTABLISHED AS LABELED for the staged excerpt only. The
earlier stand-in cap of 64 present bytes is removed by the real crafted AVI.

## Next

1. Done: witness replay ESTABLISHED AS LABELED (W239), no grade change then.
2. Done (W240–W243): real builds at both pins, crafted 48/64/512-byte `00dc`
   AVIs, real `pjmedia_avi_player_create_streams()` + `pjmedia_port_get_frame()`
   pulls; ASan WRITE-64/WRITE-512, chosen-byte overwrite of a live
   `pjmedia_port`, the shipped vid-port mutex and a shipped-sample
   pointer-bearing clock; fixed clamp and safe controls. Runners:
   `real/run-real.sh`, `real/run-realobj.sh`, `real/run-vidport.sh`,
   `real/run-clock.sh`. Clean-archive receipts in `PROVENANCE.md`.
3. Done (W244): source-layout check. In production library code the natural
   victim at frame+48 is `pj_mutex_t` (`vid_port.c:688` then `:701`), whose
   glibc list pointers at +24/+32 are beyond a 64-byte write but inside a
   512-byte one; no function-pointer/callback object follows the frame in
   production. Grade unchanged; no witness replay repeated.
4. Next: fold an actual W240–W243 witness verdict when one arrives; no r5
   without a live loopback target, attacker AVI on a wire, a benign command
   side effect and vulnerable/fixed/safe controls.

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
  / 165 unique names). Operator admission 02:3xZ under standing #6; witness
  verdict UNKNOWN at creation, ESTABLISHED AS LABELED in W239 (receipt below).
  No route, resolver key or wake unit added: engine config and the full-flag
  sync stay person-reserved. Operator replay at HEAD
  02:2xZ: `TOTAL: 29 PASS / 0 FAIL`, rc 0, `WITNESS REPLAY PASS`.
- Witness W239 replay 2026-11-26 02:34Z: `run-witness.sh` in-tree and from a
  clean `git archive 814e9392` (wrapper byte-identical) both `WITNESS REPLAY
  PASS`, 29 PASS / 0 FAIL rc 0; independent raw-SHA fetch confirms both
  full-file and excerpt pin hashes; GCC+Clang ASan WRITE-64 past a 48-byte
  region at `avi-vulnerable.inc:15`, fixed/safe controls clean, chosen
  16-byte marker in the plain readback. Verdict ESTABLISHED AS LABELED, NO
  r5; detail in `.mishe-tauftauf/artifacts/witness-w239-pjprojectshell/detail.md`.
- W240 real-consumer replay 2026-11-26 15:00Z: fetched full tarballs at
  `c1ea7648`/`7ecc6584` (SHA-256 in `PROVENANCE.md`), built both with
  `PJMEDIA_HAS_VIDEO=1`, `-DNDEBUG` and ASan at `-O0`; debug build without
  `-DNDEBUG` aborts at the assert before the write (build-mode control).
  `real/run-real.sh` produced vulnerable `WRITE of size 64` and
  `WRITE of size 512`, 0 bytes after a 48-byte region, in real
  `avi_get_frame()`; neighbor sentinel hex
  `4d495348452d504a50524f4a454354214a21`; fixed/safe rc 0, `frame.size=48`,
  no ASan report. Raw logs in `lab/frontier/pjproject2shell/real/out-vuln/`
  and `real/out-fixed/`. Grade advanced from rung 4 PARTIAL synthetic to
  rung 4 real-consumer sentinel; no pointer, command or r5.
- Clean-archive replay 2026-11-26 15:05Z: `git archive 759825c1
  lab/frontier/pjproject2shell` into `/tmp/w240-pjproject-clean`;
  `real/build-real.sh` rc 0 with both tarball hashes exact and one
  `avi_get_frame` symbol per library; `real/run-real.sh` rc 0 with the same
  six-case transcript (WRITE-64/WRITE-512, neighbor hex, fixed/safe rc 0).
  In-tree `run-witness.sh` at `759825c1`: `WITNESS REPLAY PASS`.
- W241/W242/W243 receipts (15:30Z/17:56Z/20:24Z): clean-archive replays of
  `4f9314a9`, `79c1f673` and `a98128fc` reproduced 11/0 realobj checks, 16/0
  vid-port checks and 10/0 clock checks with both pinned tarballs hash-matched;
  raw logs in `real/out-vuln/`, `real/out-fixed/` and `PROVENANCE.md`.
- W244 source-layout check 22:44Z: verified at the vulnerable pin that
  `vid_port.c:688` frame and `:701` mutex are consecutive allocations from one
  pool, `struct pj_mutex_t` (`os_core_unix.c:127-136`) embeds glibc list
  pointers at +24/+32, `vidport-asan-attack64.log` MUTEX_AFTER is unchanged
  from byte 16 onward while `vidport-asan-attack512.log` is repeated chosen
  marker across all 88 bytes. No production callback-pointer victim; grade
  unchanged, no replay repeated. Detail in `reports/frontier-pjproject2shell.md`.
