# Frontier brief: pjproject AVI video chunk length overflow — CVE-2026-77396

Status: **ADMITTED 2026-11-26 by the operator** (156th target). W239 witness
replay ESTABLISHED AS LABELED for the staged excerpt evidence. W240 adds a
real `pjmedia` build at both pins: ASan-confirmed OOB WRITE of 64 and 512
bytes in real `avi_get_frame()` and chosen-marker overwrite of a live
adjacent sentinel, with fixed and safe controls. Grade: **rung 3 confirmed in
the real consumer / rung 4 with a driver-provided sentinel**. No library
object overwrite, no pointer, no wire, no command and no rung 5.

## Claim and scope

- CVE-2026-77396 / GHSA-6p2p-5wf8-h5hr, CNA GitHub, published 2026-07-13,
  updated 2026-08-20, Moderate, CWE-122 + CWE-787. Sources:
  `https://github.com/pjsip/pjproject/security/advisories/GHSA-6p2p-5wf8-h5hr`,
  `https://api.github.com/repos/pjsip/pjproject/security-advisories/GHSA-6p2p-5wf8-h5hr`.
- Project: `pjsip/pjproject`, `pjmedia/src/pjmedia/avi_player.c`,
  `avi_get_frame()`. Affected: pjproject <= 2.17. Patched versions in the
  advisory: **None** ("a fix is in progress ... master branch"). Upstream fix
  commit `7ecc6584969a923c4190b6912afbf5952b5a4b9f` (2026-07-13T02:27:02Z,
  "Merge commit from fork ... Clamp the read to the frame buffer capacity"),
  vulnerable parent `c1ea7648fb53f945493972a23133b9e0d3e4a1fe`. Version
  boundaries are UNKNOWN beyond the advisory's `<= 2.17` and commit-level
  pins; no tag carrying the fix was checked.
- Claimed primitive: the AVI video chunk length (`ch.len`, file-supplied) is
  used as the byte count for a read into `frame->buf`, whose capacity comes
  from the file-supplied declared video dimensions. The only guard is
  `pj_assert()`, which is a no-op in release builds. A crafted AVI therefore
  writes file-chosen bytes past the frame buffer, with attacker-controlled
  length and contents; the advisory calls local playback a crash and
  attacker-supplied AVI to a parser a stronger memory-corruption exposure.
  A real AVI file and real public-API frame pull are exercised below; no
  network wire, pointer, command or rung 5.

## Pins and source-bound mechanism

- Byte-exact full-file pins: `src/avi_player-vuln.c` (SHA-256
  `1ccafcd255ad996e572753495191ff5347b2062c9152617458425f30c9446081`,
  1338 lines) and `src/avi_player-fixed.c`
  (`dae6aeee810d88173657cefb3486f89bdee77dbe87b2520a5ae784f854fc5042`,
  1366 lines), fetched from the two raw GitHub SHAs above.
- Verbatim excerpts: `pins/avi-vulnerable.inc` = vulnerable lines 1208-1228
  (`45fe04f09520dfef6f2cc52f70d6293a4fdd96e7f76d6eb41a79e2586e710ba1`);
  `pins/avi-fixed.inc` = fixed lines 1208-1256
  (`2cc1805d5dee8959837926dcb492ffb3b53de4b2a2b4e063f0afc4f3f11139de`).
- Vulnerable body (excerpt lines 14-16, full file 1221-1223):
  `pj_assert(frame->size >= ch.len);`
  `status = file_read3(fport->fd, frame->buf, ch.len, 0, &size_read);`
  `if (status != PJ_SUCCESS) goto on_error2;`
  and then `frame->size = ch.len;` (full file 1226). Upstream `file_read3()`
  passes its `size` as the requested length to `pj_file_read()`, so the
  file-supplied chunk length drives the copy; the assertion cannot protect a
  release build.
- Fix hunk (full file 1221-1255) adds `pj_uint32_t read_len = ch.len;`,
  clamps `read_len` to `frame->size` with a log message on truncation, reads
  only `read_len`, seeks past the unread chunk bytes to keep file alignment,
  and sets `frame->size = read_len`. The pinned fixed excerpt is ASan-clean
  on the same attack input and keeps the logical frame at 48 bytes.

## Local evidence

`bash lab/frontier/pjproject2shell/run-all.sh`: **29 PASS / 0 FAIL**, rc 0.
GCC and Clang ASan on the verbatim vulnerable excerpt at `-O0`:
`AddressSanitizer: heap-buffer-overflow`, `WRITE of size 64`,
`0 bytes after 48-byte region`, write frame
`avi_get_frame ... pins/avi-vulnerable.inc:15`. The fixed excerpt is
ASan-clean and reports `AVI_FRAME_SIZE=48`; safe input (chunk length 48
against the same 48-byte frame) is ASan-clean in both bodies. A plain build
whose physical buffer is 96 bytes but whose logical `frame->size` is 48
prints `CANARY_AFTER=4d495348452d504a50524f4a45435421`: bytes 48..63 are
the chosen `MISHE-PJPROJECT!` ASCII marker, while the vulnerable body also
adopts `AVI_FRAME_SIZE=64`. The plain fixed build clamps to 48 and writes no
marker; the safe input writes no marker.

For the staged excerpt, stand-ins are `pjmedia_frame`, `avi_reader_port`,
`pjmedia_avi_subchunk`, file positioning, `file_read3()` as a bounded
`memcpy` of the present payload, and a caller; the stand-in file caps the
copy at 64 present bytes. The W240 real-consumer lane removes that cap.

## Real-consumer lane (W240, 2026-11-26 15:00Z)

`bash real/build-real.sh && bash real/run-real.sh` builds both pinned trees
with `PJMEDIA_HAS_VIDEO=1` and ASan at `-O0`, release-style `-DNDEBUG`
semantics, and replays a minimal 4x4 24-bpp DIB AVI through
`pjmedia_avi_player_create_streams()` and `pjmedia_port_get_frame()`.
`real/make_avi.py` creates 48-, 64- and 512-byte `00dc` chunks with
`MISHE-PJPROJECT!` at payload offset 48; hashes and logs are in
`PROVENANCE.md`.

- Vulnerable `c1ea7648`, 64-byte chunk: ASan `heap-buffer-overflow`,
  `WRITE of size 64`, 0 bytes after a 48-byte region, stack
  `fread` → `pj_file_read` → `file_read3 (avi_player.c:158)` →
  `avi_get_frame (avi_player.c:1222)` → `pjmedia_port_get_frame`.
- Vulnerable, 512-byte chunk: same site, `WRITE of size 512` — the full
  file-supplied length, no 64-byte stand-in cap.
- Vulnerable, 64-byte chunk with a live 18-byte adjacent sentinel:
  `NEIGHBOR_AFTER=4d495348452d504a50524f4a454354214a21` — 16 chosen marker
  bytes at frame+48..+63, last two sentinel bytes intact. `frame.size` becomes
  64. No library object or pointer was targeted.
- Vulnerable safe input (48-byte chunk) and both fixed `7ecc6584` cases:
  rc 0, `frame.size=48`, no ASan report; the fixed build logs the clamp.

Exact commands, hashes, AVI bytes and raw logs:
`lab/frontier/pjproject2shell/PROVENANCE.md`, `real/out-vuln/`,
`real/out-fixed/`.

## Witness replay (W239, 2026-11-26)

ESTABLISHED AS LABELED. `bash lab/frontier/pjproject2shell/run-witness.sh` from
the worktree and from a clean `git archive 814e9392 lab/frontier/pjproject2shell`
(wrapper byte-identical, sha256 `28added4…e2335f`) each returned `WITNESS
REPLAY PASS`, four pins exact, `TOTAL: 29 PASS / 0 FAIL`, rc 0. Independently
fetched both raw upstream `avi_player.c` blobs by SHA: full-file and
`sed -n '1208,1228p'` / `'1208,1256p'` excerpt hashes match all four pins;
the only upstream diff is the video-branch clamp at lines 1221-1255. GCC and
Clang ASan -O0 logs show `WRITE of size 64`, 0 bytes after a 48-byte region,
write frame `avi_get_frame pins/avi-vulnerable.inc:15`; fixed and safe inputs
are ASan-clean at `AVI_FRAME_SIZE=48`, plain attack exposes the 16 chosen
bytes `MISHE-PJPROJECT!` past the 48-byte logical frame. That verdict was
limited to the staged excerpt evidence; the W240 real-consumer lane above
supersedes it. Full detail:
`.mishe-tauftauf/artifacts/witness-w239-pjproject2shell/detail.md`.

## Grade and tractability

- **Rung 3 confirmed in a real consumer:** GCC and Clang ASan on the verbatim
  pinned branch, plus a real `pjmedia` build at the vulnerable parent, show
  heap OOB WRITEs of 64 and 512 bytes in `avi_get_frame()` on a real crafted
  AVI, with fixed and safe-input controls.
- **Rung 4 with a driver-provided live object:** chosen
  `MISHE-PJPROJECT!` bytes land at frame+48..+63 and overwrite an adjacent
  18-byte sentinel read back after the real `pjmedia_port_get_frame()` call.
  The adjacent object is allocated by the driver, not a library object; no
  pointer was corrupted and no command executed. Do not overstate as pointer
  control.
- **Not rung 5:** no live loopback service, no attacker-supplied bytes
  through a network wire, no pointer hijack, no command side effect.

Cheapest next experiment: place a real `pjmedia` object (e.g. a pool block
or port struct) immediately after the frame buffer and see whether chosen
bytes corrupt a field that changes a later library decision. That would
upgrade rung 4 from a sentinel to a library-object overwrite. Rung 5 would
additionally need a loopback target reachable by attacker-supplied AVI bytes
and a benign command side effect with vulnerable, fixed and safe controls.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning. `sofiasip2shell`, `baresip2shell` and
`opensips2shell` cover other SIP stacks; no pjproject brief, lab or window
exists and pjproject is absent from the admitted-target list.
