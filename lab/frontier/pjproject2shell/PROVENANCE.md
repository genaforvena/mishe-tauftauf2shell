# PROVENANCE — pjproject2shell (frontier W239, 2026-11-26)

## Provisioning (read-only fetch, no external probing)

Advisory read from
`https://github.com/pjsip/pjproject/security/advisories/GHSA-6p2p-5wf8-h5hr`
and `https://api.github.com/repos/pjsip/pjproject/security-advisories/GHSA-6p2p-5wf8-h5hr`.
Commit list read from
`https://api.github.com/repos/pjsip/pjproject/commits?path=pjmedia/src/pjmedia/avi_player.c&per_page=15`.

    mkdir -p lab/frontier/pjproject2shell/src
    curl -fsSL -o src/avi_player-vuln.c \
      https://raw.githubusercontent.com/pjsip/pjproject/c1ea7648fb53f945493972a23133b9e0d3e4a1fe/pjmedia/src/pjmedia/avi_player.c
    curl -fsSL -o src/avi_player-fixed.c \
      https://raw.githubusercontent.com/pjsip/pjproject/7ecc6584969a923c4190b6912afbf5952b5a4b9f/pjmedia/src/pjmedia/avi_player.c
    sed -n '1208,1228p' src/avi_player-vuln.c > pins/avi-vulnerable.inc
    sed -n '1208,1256p' src/avi_player-fixed.c > pins/avi-fixed.inc

Fix `7ecc6584969a923c4190b6912afbf5952b5a4b9f` (2026-07-13T02:27:02Z),
parent `c1ea7648fb53f945493972a23133b9e0d3e4a1fe`; advisory published
2026-07-13, patched versions None ("fix in progress master"). The full diff
between the two fetched blobs changes only the video branch at upstream lines
1221-1255: clamp `ch.len` to `frame->size`, seek past the unread bytes and
set `frame->size` from the clamped length.

## Pins (SHA-256)

| artifact | sha256 |
| --- | --- |
| `src/avi_player-vuln.c` | `1ccafcd255ad996e572753495191ff5347b2062c9152617458425f30c9446081` |
| `src/avi_player-fixed.c` | `dae6aeee810d88173657cefb3486f89bdee77dbe87b2520a5ae784f854fc5042` |
| `pins/avi-vulnerable.inc` | `45fe04f09520dfef6f2cc52f70d6293a4fdd96e7f76d6eb41a79e2586e710ba1` |
| `pins/avi-fixed.inc` | `2cc1805d5dee8959837926dcb492ffb3b53de4b2a2b4e063f0afc4f3f11139de` |

## Harness facts

- `harness/driver.c` supplies stand-ins for `pjmedia_frame`,
  `avi_reader_port`, `pjmedia_avi_subchunk`, constants, `pj_file_setpos`,
  `file_read3()` and a caller. Both excerpts are `#include`d verbatim; no
  pinned byte is edited.
- `pj_assert` is defined as a no-op (release build), matching the advisory's
  statement that the only guard is ineffective in production builds.
- `file_read3()` stand-in copies the present payload bytes with `memcpy`
  using the pinned `size` argument; the attack provides 64 present bytes.
  The real read may use the full file-supplied length; the cap is a harness
  limit, not a claim about pjproject.
- Logical frame capacity is 48 bytes (stand-in for dimensions-derived
  `frame->size`). Plain mode allocates 96 physical bytes and reads back
  bytes 48..63 after the call; ASan mode allocates exactly 48 bytes.
- Chosen marker is `MISHE-PJPROJECT!` at payload offset 48; copied bytes
  48..63 read back as
  `CANARY_AFTER=4d495348452d504a50524f4a45435421`.
- ASan builds use `-O0` for consistent reporting; no `-O1` claim is made
  for this candidate.

## Verification

    cd lab/frontier/pjproject2shell
    bash run-all.sh

Author run 2026-11-26 02:1xZ: **29 PASS / 0 FAIL**, rc 0. Raw logs in
`out/gcc-attack.log`, `out/clang-attack.log`, `out/fixed-attack.log`,
`out/vuln-safe.log`, `out/fixed-safe.log`, `out/plain-attack.log`,
`out/plain-safe.log`, `out/plain-fixed-attack.log`.
`bash run-witness.sh` rehashes the four pins, deletes `out/`, rebuilds every
binary and re-asserts the same evidence.

## Real pjmedia consumer lane (W240, 2026-11-26 15:00Z)

Provisioning is a read-only upstream fetch of two full source tarballs:

    real/build-real.sh
    curl -fsSL https://codeload.github.com/pjsip/pjproject/tar.gz/<sha>

| tarball | sha256 |
| --- | --- |
| `src/full/vuln.tar.gz` (`c1ea7648`) | `5ebc89e088b6a9272d22e6fef955b77b41aff7c322ab4728109da27fd0fa0f03` |
| `src/full/fixed.tar.gz` (`7ecc6584`) | `5f2984d84697f2b2fbad881d8fa69ca34f165219a646d2ce2b78f3aa2a8a88ca` |

Both trees configure with `PJMEDIA_HAS_VIDEO=1`, release-style `pj_assert`
semantics and `CFLAGS/CXXFLAGS='-fsanitize=address -g -O0
-fno-omit-frame-pointer -DPJMEDIA_HAS_VIDEO=1 -DNDEBUG'`; configure disables
sound, ffmpeg, SDL, SSL and v4l2. A debug build without `-DNDEBUG` aborts at
`avi_player.c:1221` before any write; that is a build-mode control, not the
production condition. With release flags the same source logs `Assert failed:
frame->size >= ch.len` and continues into `file_read3()`.

`real/make_avi.py` writes a minimal one-stream DIB AVI: 4x4, 24 bpp,
`00dc` chunk length 48/64/512, `MISHE-PJPROJECT!` at payload offset 48.

| AVI | sha256 |
| --- | --- |
| `real/attack64.avi` | `383683fca50d1fafaa8c5f50d2672bab6da8b3cbfa5cd088cbd4730890cce619` |
| `real/attack512.avi` | `834cf4cb260224e6d8b0d84ad68900bcc6d8a45442247c799764ea6b2bdecac0` |
| `real/safe48.avi` | `a21a70cfd5f43097dc875376881189c1d2a266a453ab7ad3a58f42b829bf67f7` |

`real/real-driver.c` calls the real public API
`pjmedia_avi_player_create_streams(..., PJMEDIA_AVI_FILE_NO_SYNC, ...)`,
gets the real video port, derives 48 bytes with
`pjmedia_get_video_format_info()->apply_fmt()`, allocates the frame buffer,
and pulls one frame with `pjmedia_port_get_frame()`. `exact` mode puts an
ASan redzone directly after the frame; `neighbor` mode places a live
18-byte sentinel (`LIVE-ADJACENT-OBJ!`) there and reads it back.

    bash lab/frontier/pjproject2shell/real/build-real.sh
    bash lab/frontier/pjproject2shell/real/run-real.sh

Observed (raw logs in `real/out-vuln/` and `real/out-fixed/`):

- vulnerable `attack64 exact`: ASan `heap-buffer-overflow`, `WRITE of size
  64`, 0 bytes after a 48-byte region; stack `fread` → `pj_file_read
  (file_io_ansi.c:132)` → `file_read3 (avi_player.c:158)` → `avi_get_frame
  (avi_player.c:1222)` → `pjmedia_port_get_frame (port.c:99)`.
- vulnerable `attack512 exact`: same site, `WRITE of size 512` — the full
  file-supplied chunk length, removing the 64-byte stand-in cap.
- vulnerable `attack64 neighbor`: `PULL_DONE frame.size=64`,
  `NEIGHBOR_AFTER=4d495348452d504a50524f4a454354214a21` — chosen
  `MISHE-PJPROJECT!` occupies bytes +48..+63 of the live sentinel and its
  last two bytes (`4a21`, "J!") remain.
- vulnerable `safe48 exact` and both fixed cases: rc 0, `PULL_DONE
  frame.size=48`, no ASan report. Fixed build logs `AVI video chunk (64)
  exceeds frame buffer (48), truncating` from the source clamp.

No pointer was corrupted, no command ran, and no external target was
contacted. Grade after this lane: rung 3 confirmed in the real pjmedia
consumer; rung 4 with a driver-provided live adjacent sentinel (no library
object or pointer control); no rung 5.

Clean-archive replay 2026-11-26 15:05Z: `git archive 759825c1
lab/frontier/pjproject2shell` into `/tmp/w240-pjproject-clean`, then
`bash real/build-real.sh` (rc 0, both tarball hashes above, one
`avi_get_frame` symbol in each built library) and `bash real/run-real.sh`
(rc 0 driver of all six cases). Clean logs match the in-tree transcript:
`WRITE of size 64` and `WRITE of size 512`, 0 bytes after a 48-byte region,
`NEIGHBOR_AFTER=4d495348452d504a50524f4a454354214a21`, fixed
`PULL_DONE frame.size=48` with `AVI video chunk (64) exceeds frame buffer
(48), truncating`. Staged `run-witness.sh` also still returns
`WITNESS REPLAY PASS` at commit `759825c1`.

## Real library-object lane (W241, 2026-11-26 15:26Z)

`real/real-driver.c` gains a third mode, `realobj`. It derives 48 bytes from
the real format manager, allocates the frame with the real allocator
`pj_pool_alloc(pool, framebytes)`, creates two live audio ports with
`pjmedia_null_port_create()` (each in its own library pool), then calls the
real library constructor
`pjmedia_bidirectional_port_create(pool, nget, nput, &victim)`, whose first
allocation is `PJ_POOL_ZALLOC_T(pool, struct bidir_port)` — so the live
120-byte `pjmedia_port` sits immediately after the frame in the same pool
block. It prints `delta = victim - buf`, the victim's key fields and 64 raw
bytes before and after `pjmedia_port_get_frame()`, and does not call or
destroy the corrupted port.

    bash lab/frontier/pjproject2shell/real/run-realobj.sh

Result 15:26Z: `delta=48` in all five runs, **TOTAL: 11 PASS / 0 FAIL**,
rc 0. Raw logs: `real/out-vuln/realobj-vuln-{attack64,attack512,safe48}.log`
and `real/out-fixed/realobj-fixed-{attack64,safe48}.log`.

- Vulnerable `attack64`: `VICTIM_BYTES_AFTER:4d495348452d504a50524f4a45435421…`,
  `VICTIM_AFTER name=0x4a502d454853494d` (the other fields unchanged because
  only 16 chosen bytes reach the object), `PULL_DONE status=0 frame.size=64`.
- Vulnerable `attack512`: `VICTIM_BYTES_AFTER` is 64 bytes of repeated
  `4d495348452d504a50524f4a45435421`; `name=0x4a502d454853494d`,
  `sig=0x4853494d`, `get=0x215443454a4f5250`,
  `put=0x4a502d454853494d`, `pdata=0x4a502d454853494d`, `frame.size=512`.
  No pointer is dereferenced or called. The vulnerable build also prints
  `Assert failed: frame->size >= ch.len` from the release-mode `pj_assert`
  macro but continues into `file_read3()`.
- Vulnerable safe48 and both fixed cases: `VICTIM_BEFORE`/`VICTIM_AFTER` and
  their 64-byte dumps are byte-identical; fixed attack64 logs
  `AVI video chunk (64) exceeds frame buffer (48), truncating`.

No ASan report is expected in `realobj` mode: both objects are inside one
pj pool block, so no redzone is crossed. The evidence is the chosen-byte
overwrite of live library fields, not an ASan diagnostic.

| artifact | sha256 |
| --- | --- |
| `real/real-driver.c` | `8304b76dfbefe8c2ecbb7eb35a7c3a81ca32d6ea3b66de8ed87b50d21342deef` |
| `real/run-realobj.sh` | `d6435096a6d5853c720e522681cb244667fad5ffc55e41e08a125ae25963b6cc` |

Regression at 15:27Z: `bash real/run-real.sh` still reproduces all six W240
cases (ASan WRITE-64/WRITE-512, neighbor marker, fixed clamp, safe control).

Clean-archive replay 2026-11-26 15:31Z: `git archive 4f9314a9
lab/frontier/pjproject2shell` extracted into `/tmp/w241-pjproject-clean`.
`bash real/build-real.sh` rc 0 (both tarballs re-fetched and hash-matched
above, one `avi_get_frame` symbol in each built library), then
`bash real/run-real.sh` reproduced all six W240 cases and
`bash real/run-realobj.sh` returned `TOTAL: 11 PASS / 0 FAIL`, rc 0.
Runner hashes matched the in-tree values above
(`8304b76d…` for `real-driver.c`, `d6435096…` for `run-realobj.sh`).

Natural-caller negative: `pjmedia_vid_conf_add_port()` in the pinned
vulnerable tree allocates `cport->get_buf` as the last item from
`cport->pool` (`pjmedia/src/pjmedia/vid_conf.c:555-568`); subsequent
`listener_slots`, `transmitter_slots`, `render_states` and `render_pool`
arrays come from the main pool (`:572-606`). No library object is naturally
adjacent after the AVI frame buffer in that shipped caller.
