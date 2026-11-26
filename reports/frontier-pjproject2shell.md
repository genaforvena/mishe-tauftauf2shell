# Frontier brief: pjproject AVI video chunk length overflow — CVE-2026-77396

Status: **STAGED 2026-11-26 by frontier W239**, awaiting operator admission;
witness replay UNKNOWN. Rung 3 pinned verbatim excerpt; rung 4 PARTIAL (chosen
bytes observed past a 48-byte logical frame in a synthetic plain readback).
No real pjmedia build, no crafted AVI file, no network wire, no pointer, no
command and no rung 5.

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
  No real AVI, player or wire input is exercised here.

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

Stand-ins: `pjmedia_frame`, `avi_reader_port`, `pjmedia_avi_subchunk`, file
positioning, `file_read3()` as a bounded `memcpy` of the present payload, and
a caller. The release-build `pj_assert` is deliberately a no-op, matching the
advisory. The stand-in caps the file at 64 present bytes, so the observed
WRITE is 64 bytes, not the full 32-bit range an AVI chunk could declare.
Exact commands, hashes and raw logs are in `lab/frontier/pjproject2shell/PROVENANCE.md`.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in the verbatim
  pinned video branch of `avi_get_frame()`, with fixed and safe-input
  controls.
- **Rung 4 PARTIAL:** bytes are chosen in the harness and read back past the
  48-byte logical frame in a synthetic plain process. No real library build,
  crafted AVI, adjacent live object, pointer, network wire, command or
  observed side effect.
- **Not rung 5:** no loopback target, no attacker-supplied bytes through a
  real API, no pointer hijack, no command.

Cheapest next experiment: build real pjproject at `c1ea7648` with
`PJMEDIA_HAS_VIDEO=1` and ASan, synthesize a minimal AVI whose declared video
dimensions produce a small frame and whose `00dc` chunk declares 64+ bytes of
chosen payload, then call `pjmedia_avi_player_create_streams()` and pull a
frame. Measure the real read length and whether the chosen bytes land in a
live adjacent object; replay the same AVI against `7ecc6584` to confirm the
clamp. Keep the no-pointer/no-command ceiling until a real consumer and
vulnerable/fixed/safe controls are observed.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning. `sofiasip2shell`, `baresip2shell` and
`opensips2shell` cover other SIP stacks; no pjproject brief, lab or window
exists and pjproject is absent from the admitted-target list.
