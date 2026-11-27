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

Current-run note (W303 nit 1, 2026-11-27): the `NEIGHBOR_AFTER` line above
is historical evidence from the W240 driver at `759825c1`. Commit `4f9314a9`
replaced that print with the realobj mode, so present `real-driver.c:135`
emits only `NEIGHBOR_BEFORE` and `run-real.sh` does not assert the marker.
Current chosen-byte proof is in the realobj and vidport lanes.

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

## Natural shipped-caller victim (W242, 2026-11-26 17:49Z)

`real/vidport-driver.c` uses only shipped APIs:
`pjmedia_vid_dev_subsys_init()`, `pjmedia_avi_dev_create_factory()`,
`pjmedia_avi_dev_alloc()`, `pjmedia_vid_port_create()`,
`pjmedia_vid_port_connect()` and `pjmedia_vid_port_start()`. It does not
supply the victim buffer or object. In the pinned vulnerable source,
`pjmedia/src/pjmedia/vid_port.c:543` creates a fresh pool, `:688` allocates
`vp->frm_buf->buf` from it and `:701` allocates `vp->frm_mutex` from the
same pool; the active clock passes that buffer to the device at `:1176`,
`avi_dev.c:636` passes it to `avi_get_frame()`. A read-only shadow of the
private `struct pjmedia_vid_port` (source lines 74-115) prints the two
addresses and 88 mutex bytes before and after the pull.

    bash lab/frontier/pjproject2shell/real/run-vidport.sh

Result 17:49Z and repeat 17:50Z: **TOTAL: 16 PASS / 0 FAIL**, rc 0 each.
All six runs print `frm_buf=0x515000001d70 size=48`,
`frm_mutex=0x515000001da0`, `delta=48` (ASLR-independent readback).

- Vulnerable 64-byte `00dc`: `FRAME_SIZE_AFTER=64`;
  `MUTEX_AFTER:02000000452d504a50524f4a454354210002...` — 12 chosen marker
  bytes at mutex+4..+15; the mutex word at +0..+3 also changed from
  `00000000`. Cause of the first-word change is UNKNOWN; glibc mutex state
  is plausible, but no pointer was called or dereferenced.
- Vulnerable 512-byte `00dc`: ASan `heap-buffer-overflow`, `WRITE of size
  512`, 0 bytes after the 512-byte pool block; stack `fread` →
  `pj_file_read (file_io_ansi.c:132)` → `file_read3 (avi_player.c:158)` →
  `avi_get_frame (avi_player.c:1222)` → `pjmedia_port_get_frame (port.c:99)`
  → `avi_dev_strm_get_frame (avi_dev.c:636)` → `enc_clock_cb
  (vid_port.c:1176)` → `clock_thread`. `MUTEX_AFTER` begins with repeated
  `4d495348452d504a50524f4a45435421`.
- Vulnerable safe48 and both fixed cases: `FRAME_SIZE_AFTER=48`, live mutex
  bytes byte-identical before/after, no ASan report.

The driver skips `pjmedia_vid_port_stop()` after readback: an earlier run
with teardown hung on the clock-thread join (timeout 20, rc 124) after the
64-byte overflow, consistent with a live mutex being corrupted. It prints
and flushes the readback, sleeps 250 ms so an ASan report can complete,
then calls `_exit(0)`. The 512-byte ASan abort is expected (rc 1).

| artifact | sha256 |
| --- | --- |
| `real/vidport-driver.c` | `2539790c74a594f94b713e17e9a26d7f6c5b6871ca74334932d901eff57959e6` |
| `real/run-vidport.sh` | `f9d77e62b213a004da6e4654c181dbbfdfc2c9b2f9256885e2e2bfed149973e4` |

Raw logs: `real/out-vuln/vidport-asan-*.log` and
`real/out-fixed/vidport-asan-*.log`. Fix commit changes only the reader
clamp; the caller allocation sites are byte-identical at both pins.

Wire path is a bounded negative: the only AVI constructor takes a filename
(`avi_player.c:225` `pj_file_exists`, `:261` `pj_file_open`) and
`pjsua_avi_player_create()` likewise takes a path; no shipped socket or
RTP route feeds `00dc` bytes to `avi_get_frame()`. Grade stays rung 4:
chosen bytes in a live mutex, no pointer control, command or network.

First clean-archive attempt 17:51Z: `git archive 79c1f673
lab/frontier/pjproject2shell` into `/tmp/w242-pjproject-clean`; unmodified
`bash real/build-real.sh` returned rc 2 — `make -j6` failed creating
`output/pjsip-x86_64-pc-linux-gnu/*.o` in the vulnerable tree even though
the target directory exists afterward. That transient provisioning failure
meant `real/vidport-asan-fixed` was never built, so the runner reported
`11 PASS / 5 FAIL` with five "No such file or directory" cases. This is a
failed replay, not a passing receipt.

Clean-archive retry 17:55Z, same extracted tree and unmodified scripts:
`bash real/build-real.sh` rc 0 (both tarballs re-fetched at the pinned
commits with the hashes above, `avi_get_frame_symbols=1` in both libraries,
`PROVISION_DONE`), then `bash real/run-vidport.sh` rc 0 with
**TOTAL: 16 PASS / 0 FAIL**. Runner/driver hashes matched the in-tree
values above; all six clean logs show `delta=48`, the vulnerable 64-byte
chosen bytes in the live mutex, vulnerable 512-byte ASan `WRITE of size
512` through `enc_clock_cb`, and fixed/safe byte-identical mutex state.
No witness verdict for W240/W241/W242 as of chat event 5689 (17:35Z).

## Natural pointer-bearing victim in a shipped sample (W243, 2026-11-26 20:24Z)

`real/clock-driver.c` (sha256
`a6cd99f903bf7e17cfec480148746755fc3933d33e5b703bde72de5dc3fd9b2a`) and
`real/run-clock.sh` (sha256
`403b3944dbdbadd39c2b16dbf1bc466f99f65871b53f90e84c5959c20e0d768f`)
reproduce the allocation order of the shipped sample
`pjsip-apps/src/samples/vid_streamutil.c`: at `:733`/`:754` the AVI read
buffer comes from the app pool, then `:760` calls
`pjmedia_clock_create2(pool, ...)`; `clock_thread.c:174` allocates the live
`struct pjmedia_clock` from that same pool. The driver uses only shipped
pjmedia APIs; its `struct probe_clock` mirrors the private layout at
`clock_thread.c:110-132` for readback only, and never starts, stops,
destroys or calls through the clock (`_exit(0)` after readback).

In-tree `bash real/run-clock.sh` at 20:24Z: compile rc 0 for both pins,
five runs rc 0, **TOTAL: 10 PASS / 0 FAIL**. Every run logs
`CLOCK_ALLOC delta=48 size=96`. Vulnerable `attack64`:
`CLOCK_BYTES_AFTER:4d495348452d504a50524f4a45435421...` and
`CLOCK_AFTER pool=0x4a502d454853494d` (16 chosen bytes). Vulnerable
`attack512`: `pool=cb=0x4a502d454853494d`,
`user=0x215443454a4f5250`, `lock=0x4a502d454853494d`. Safe 48-byte input
and both fixed cases have byte-identical `CLOCK_BEFORE`/`CLOCK_AFTER`
fields and 128-byte readbacks; fixed logs the truncation clamp and
`PULL_DONE ... frame.size=48`. Fixture hashes are unchanged from W240
(`383683fc…`, `834cf4cb…`, `a21a70cf…`).

Scope limit: the natural layout is in a shipped *sample* application, not a
library-internal AVI consumer; the library callers checked in W241/W242
give a driver-groomed port or a live mutex. The clock was never started or
dereferenced; there is no wire path, pointer call, command or rung 5.
No witness verdict for W240–W243 as of chat event 5787 (20:18Z).

Clean-archive receipt 20:32Z: `git archive a98128fc
lab/frontier/pjproject2shell` into `/tmp/w243-pjproject-clean.Cj0ttc`, then
unmodified `bash real/build-real.sh` (rc 0, both tarballs re-fetched with
the pinned hashes above, `avi_get_frame_symbols=1` in both libraries,
`PROVISION_DONE`) and `bash real/run-clock.sh` (rc 0, **TOTAL: 10 PASS /
0 FAIL**). All five clean logs show `CLOCK_ALLOC delta=48 size=96`, the
same chosen-byte `CLOCK_BYTES_AFTER` prefix and pointer words as in-tree,
and byte-identical fixed/safe clocks. Driver and runner sha256 values
matched the in-tree values above.

## Witness replay and runner repair (W303/W304, 2026-11-27)

Witness #5967 (detail
`.mishe-tauftauf/artifacts/witness-w303-pjproject/detail.md`): all four real
lanes ESTABLISHED AS LABELED, grade unchanged, NO r5. Clean archive of HEAD
`7ea62b08`; runner hashes `build-real.sh` `1fae3a56…`, `run-real.sh`
`85de754f…`, `run-realobj.sh` `d6435096…`, `run-vidport.sh` `f9d77e62…`
matched the ask. `run-real` six cases with WRITE-64/WRITE-512 and the
48-byte fixed clamp; `run-realobj` 11 PASS / 0 FAIL; `run-vidport` 16 PASS /
0 FAIL on three runs. No pointer called or dereferenced, no wire, command.

Author repair of witness nit 2 at 01:43Z: `real/vidport-driver.c` sha256
`35599b999f3a349efb9a5ce426abf26d0efd78891266203b8a4cadd8cd4bdeb7` and
`real/run-vidport.sh` sha256
`68995b6c17acd6552240a3453a69681b5265d446039a7716a50cd892f82a2a09`.
The driver retains the 150 ms pull window and polls up to 2 s only for a
transient zero `frm_buf->size`; the runner exits 1 when FAIL>0. A first
poll-only version was wrong (`vid_port.c:689` sets `size=48` at creation),
giving five runs of 13 PASS / 3 FAIL, `RESULT: FAIL`, rc 1; preserved as a
negative. Five sequential corrected runs each returned
`TOTAL: 16 PASS / 0 FAIL`, `RESULT: PASS`, rc 0. Final in-tree logs: vuln
attack64 `FRAME_SIZE_AFTER=64` with chosen marker in `MUTEX_AFTER`;
attack512 ASan `WRITE of size 512` via `enc_clock_cb vid_port.c:1176` with
repeated chosen marker in the live mutex; fixed attack64
`FRAME_SIZE_AFTER=48` with unchanged mutex.
