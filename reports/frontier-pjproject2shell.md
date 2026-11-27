# Frontier brief: pjproject AVI video chunk length overflow — CVE-2026-77396

Status: **ADMITTED 2026-11-26 by the operator** (156th target). W239 witness
replay ESTABLISHED AS LABELED for the staged excerpt evidence. W240 built
both pinned trees with real `pjmedia`: ASan-confirmed OOB WRITE of 64 and 512
bytes in real `avi_get_frame()` and chosen-marker overwrite of a live
adjacent sentinel. W241 moves the frame into the real pj pool and overwrites
a live, library-created `pjmedia_port` object 48 bytes later, including its
function-pointer fields. W242 drives the same overflow through the SHIPPED
`pjmedia_vid_port_create()` clock path: its own frame buffer is followed at
exactly +48 by a live `pj_mutex_t` allocated by the library from the same
pool, with no driver-groomed victim. W243 adds a natural shipped-sample
allocation order that puts a live, pointer-bearing `pjmedia_clock` at the
same offset, with chosen bytes in its pool/callback/user_data/lock words.
Grade: **rung 3 confirmed in the real consumer / rung 4 author-DEMONSTRATED
with a real library object and natural shipped-caller adjacency**. W239
(staged excerpt), W243 (shipped-sample clock) and W240-W242 (all four real
lanes) are each ESTABLISHED AS LABELED by witness replay; the W303 verdict
(#5967, 2026-11-27 01:33Z) closed the last three with no grade change. No
pointer was called, no wire, no command, no r5.



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
`real/out-fixed/`. Clean-archive replay of commit `759825c1`
(`build-real.sh` + `run-real.sh`) reproduced all six cases at 15:05Z;
`run-witness.sh` still returns `WITNESS REPLAY PASS`.

## Real library-object victim (W241, 2026-11-26 15:26Z)

`bash lab/frontier/pjproject2shell/real/run-realobj.sh` adds a `realobj`
mode to the same driver and replays all five cases: **11 PASS / 0 FAIL**.
The 48-byte frame comes from the real allocator `pj_pool_alloc(pool, 48)`;
`pjmedia_null_port_create()` then builds two live audio ports (each in its
own library pool) and the library constructor
`pjmedia_bidirectional_port_create(pool, get, put, &victim)` allocates the
120-byte `struct bidir_port` from the **same** driver pool. Measured
`victim - buf = 48` in all five runs. The frame pull is still the real
`pjmedia_avi_player_create_streams()` → `pjmedia_port_get_frame()` path.
Because both objects live inside one pj pool block, ASan correctly reports
nothing; the proof is readback of the live object's fields before and after.

- Vulnerable `attack64`: `VICTIM_BYTES_AFTER` starts
  `4d495348452d504a50524f4a45435421`; the live `info.name.ptr` becomes
  `0x4a502d454853494d` (chosen ASCII bytes), while fields past byte 16 are
  untouched. `PULL_DONE status=0 frame.size=64`.
- Vulnerable `attack512`: all 64 inspected object bytes become repeated
  `MISHE-PJPROJECT!`; `name.ptr=0x4a502d454853494d`,
  `sig=0x4853494d`, `get_frame=0x215443454a4f5250`,
  `put_frame=0x4a502d454853494d`, `port_data.pdata=0x4a502d454853494d`.
  These are chosen bytes, not a dereferenced or called pointer.
- Vulnerable 48-byte safe input and both fixed cases: victim fields and
  bytes are byte-identical before and after, with
  `PULL_DONE frame.size=48`; the fixed build logs its truncation clamp.

Caveat: W241's adjacency is produced by the driver's real allocation order
(`pj_pool_alloc` then a library constructor using that pool), not by a
shipped caller's natural object layout. The victim is a real library object
created by a real library constructor, but no shipped pjmedia path places a
`pjmedia_port` immediately after an AVI frame buffer. W242 below finds a
different natural victim, a live `pj_mutex_t`, in the shipped video port.

Script hashes, raw logs and the clean-archive receipt are in `PROVENANCE.md`.
Clean `git archive 4f9314a9 lab/frontier/pjproject2shell` replay at 15:31Z
rebuilt both tarballs and reproduced all 11 realobj checks and all six W240
cases with matching runner hashes.


## Natural shipped-caller victim (W242, 2026-11-26 17:49Z)

`bash lab/frontier/pjproject2shell/real/run-vidport.sh` builds a separate
`real/vidport-driver.c` against both pinned trees (16 PASS / 0 FAIL, twice).
It registers the shipped AVI virtual device with
`pjmedia_avi_dev_create_factory()` / `pjmedia_avi_dev_alloc()`, creates a
`pjmedia_vid_port` with the shipped `pjmedia_vid_port_create()`, connects a
null sink and starts the port's active clock. No victim buffer or object is
supplied by the driver. `vid_port.c:543` creates a fresh pool, `:688`
allocates the frame buffer and `:701` allocates a live `pj_mutex_t` from
that same pool; the clock calls
`pjmedia_vid_dev_stream_get_frame(vp->strm, vp->frm_buf)` at `:1176` and the
AVI device passes that buffer to `avi_get_frame()` at `avi_dev.c:636`.

- Measured in all six runs: `frm_buf=0x515000001d70 size=48`,
  `frm_mutex=0x515000001da0`, `delta=48`. A read-only shadow of the private
  `struct pjmedia_vid_port` (source lines 74-115) is used only to print these
  addresses and the 88 mutex bytes before and after the pull.
- Vulnerable 64-byte chunk: `FRAME_SIZE_AFTER=64` and the live mutex bytes
  at +4..+15 become the chosen marker (`MUTEX_AFTER:02000000
  452d504a50524f4a45435421...`); the mutex state word at +0..+3 also
  changes from the pre-pull value. The cause of that first-word change is
  UNKNOWN (glibc mutex state is plausible); no pointer was called.
- Vulnerable 512-byte chunk: ASan `WRITE of size 512`, 0 bytes after the
  512-byte pool block, stack `fread` → `pj_file_read (file_io_ansi.c:132)`
  → `file_read3 (avi_player.c:158)` → `avi_get_frame (avi_player.c:1222)`
  → `pjmedia_port_get_frame (port.c:99)` → `avi_dev_strm_get_frame
  (avi_dev.c:636)` → `enc_clock_cb (vid_port.c:1176)` → clock thread.
  `MUTEX_AFTER` starts with repeated `MISHE-PJPROJECT!`.
- Vulnerable safe48 and both fixed cases: frame size stays 48 and the live
  mutex bytes are byte-identical before and after; fixed runs are ASan-clean.

The driver skips library teardown (`_exit(0)`) after the readback: with a
corrupted mutex, `pjmedia_vid_port_stop()` blocked on clock-thread join in
an earlier 64-byte run. Logs: `real/out-vuln/vidport-asan-*.log` and
`real/out-fixed/vidport-asan-*.log`. The fix changes only the reader clamp;
`vid_port.c` and `avi_dev.c` allocation order is byte-identical at both
pins. No wire or command path exists, so the grade stays rung 4.
Clean `git archive 79c1f673 lab/frontier/pjproject2shell` replay at 17:55Z
rebuilt both pinned trees and reproduced all 16 checks; the first attempt
at 17:51Z had a transient `make -j6` provisioning failure, preserved in
`PROVENANCE.md`.

## Natural pointer-bearing victim in a shipped caller (W243, 2026-11-26 20:24Z)

`real/clock-driver.c` + `real/run-clock.sh` (commit `a98128fc`) reproduce the
allocation order of the shipped sample
`pjsip-apps/src/samples/vid_streamutil.c`: `play_file.read_buf` is allocated
from the app pool (`:733`/`:754`), then `pjmedia_clock_create2()` is called
on that same pool (`:760`), and `clock_thread.c:174` allocates the live
pointer-bearing `struct pjmedia_clock` from it. The driver uses only real
pjmedia APIs; a local mirror of `clock_thread.c:110-132` reads the object
without calling or destroying it (`_exit(0)` after readback).

`bash lab/frontier/pjproject2shell/real/run-clock.sh` against both pinned
release-style ASan builds returned **10 PASS / 0 FAIL**: `CLOCK_ALLOC
delta=48 size=96` in all five runs; vulnerable 64-byte `00dc` overwrites
`clock->pool` with chosen `0x4a502d454853494d` and the first 16 object bytes
with `4d495348452d504a50524f4a45435421`; vulnerable 512-byte writes the
chosen marker across the whole readback (`CLOCK_BEFORE cb=0x1dcd6500` →
`CLOCK_AFTER pool=cb=0x4a502d454853494d`,
`user=0x215443454a4f5250`, `lock=0x4a502d454853494d`; see label correction
below). Safe 48-byte
input and both fixed cases leave the 128 readback bytes byte-identical,
fixed logs the truncation clamp and `frame.size=48`. No pointer was called
or dereferenced: the clock was never started, stopped or destroyed.

Field-label correction (verified at the vulnerable pin; W298 witness NIT):
the driver's `struct probe_clock` mirrors `clock_thread.c:110-132` but omits
`pj_uint64_t max_jump` at `:119`, so its printed `cb` (offset 48) is the real
`max_jump` (baseline `0x1dcd6500`), printed `user` (56) is the real `cb` and
printed `lock` (80) is the real `running`/`quitting` word. The real pointer
fields are `cb` +56, `user_data` +64, `thread` +72 and `lock` +88. The printed
labels are shifted one word; the chosen-byte claim rests on the 128-byte
`CLOCK_BYTES_AFTER` dump, which is the repeating marker at every real offset.
No grade impact.

Caveat: the natural allocation order is in a shipped *sample* application,
not in a library-internal AVI consumer; the two library-internal callers
checked above have a mutex or no adjacent object. No wire input reaches
`avi_get_frame()`, so this remains rung 4, not rung 5. Clean-archive replay
receipt and hashes are in `PROVENANCE.md`.


## Production-library victim layout check (W244, 2026-11-26 22:44Z)

A read-only source trace at the vulnerable pin answers the remaining scope
question: is a pointer-bearing object naturally allocated after the AVI frame
buffer in a PRODUCTION library caller? **Partly yes; no grade change.**

- `pjmedia_vid_port_create()` creates a dedicated pool (`vid_port.c:543`),
  then allocates the AVI-device stream (`:611`), the clock (`:653`), the
  converter (`:214`/`:231`) and the passive port (`:665`) BEFORE the frame.
  It then allocates `vp->frm_buf->buf = pj_pool_zalloc(pool, vafp.framebytes)`
  at `:688` and `pj_mutex_create_simple(pool, ...)` at `:701`; the live
  `pj_mutex_t` is the next and last allocation from that pool, at frame+48.
  The clock thread passes `vp->frm_buf` unchanged through `videodev.c:679`
  and `avi_dev.c:636` into `avi_get_frame()`. This is library-internal
  production code, with no sample and no driver-supplied victim.
- `struct pj_mutex_t` (`pjlib/src/pj/os_core_unix.c:127-136`) embeds glibc
  `pthread_mutex_t` at +0; on x86_64 its `__pthread_list_t` at +24/+32 is two
  raw pointers (`bits/struct_mutex.h:22-37`). The `pj_thread_t *owner` at +80
  needs `PJ_DEBUG=1`, which is compiled out by the `-DNDEBUG` release build
  (`pjlib/include/pj/config.h:361-367`).
- **Correction to a plausible over-read:** a 64-byte `00dc` chunk is only
  16 bytes past a 48-byte frame, so it reaches mutex bytes 0..15 only.
  `real/out-vuln/vidport-asan-attack64.log` `MUTEX_AFTER` is byte-identical to
  `MUTEX_BEFORE` from byte 16 onward; the pointer fields at +24/+32 are NOT
  touched by that case. A 512-byte chunk does cover them:
  `real/out-vuln/vidport-asan-attack512.log` `MUTEX_AFTER` is repeated
  `MISHE-PJPROJECT!` across all 88 readback bytes, alongside ASan
  `WRITE of size 512`. No pointer was dereferenced or called in either case.
- Ceiling confirmed: no function-pointer/callback-bearing object is allocated
  after the frame in production library code. `vid_conf.c:557` get_buf is
  last in its own pool and later arrays use the conference pool;
  `avi_dev.c:469` encoded buffer is followed only by a raw title string
  (`:475`/`:487`). The pointer-bearing `pjmedia_clock` remains the W243
  shipped-SAMPLE victim. Grade unchanged: rung 3 / rung 4
  author-DEMONSTRATED, no wire, no pointer call, no command, no r5.


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

## Witness replay (W298, W243, 2026-11-26 23:05Z)

ESTABLISHED AS LABELED for W243 exact scope; grade unchanged, NOT r5.
Independent clean `git archive a98128fc lab/frontier/pjproject2shell` into
`/tmp/pjproject-witness-w298`: driver sha256 `a6cd99f9…dc3fd9b2a`, runner
sha256 `403b3944…0e0d768f` and three AVI fixture hashes matched. Unmodified
`build-real.sh` rc 0 with both pinned tarballs hash-matched and
`avi_get_frame_symbols=1` in each library; unmodified `run-clock.sh` rc 0,
`10 PASS / 0 FAIL`. Five `CLOCK_ALLOC delta=48 size=96`; vulnerable 64 writes
the chosen pool word and 16 object bytes, 512 writes 128 marker bytes; safe48
and both fixed runs byte-identical with the clamp logged. Source lines
`vid_streamutil.c:733/:754/:760`, `clock_thread.c:174` and
`avi_player.c:1221/:1222` verified fresh. No counterexample and no benign
input tripping the oracle. Its one NIT is the field-label shift corrected in
the W243 section above. The clock was never started, stopped or called; no
wire and no command. W240/W241/W242 verdicts remain owed. Detail:
`.mishe-tauftauf/artifacts/witness-w298-pjproject/detail.md`.

## Witness replay (W303, 2026-11-27 01:33Z)

ESTABLISHED AS LABELED for all four real lanes (W240 `run-real`, W241
`run-realobj`, W242 `run-vidport`, W243 `run-clock`); grade unchanged, NO r5.
Witness #5967, detail
`.mishe-tauftauf/artifacts/witness-w303-pjproject/detail.md`. Clean
`git archive 7ea62b08 lab/frontier/pjproject2shell`: all four runner sha256s
matched and unmodified `build-real.sh` returned rc 0 with
`avi_get_frame_symbols=1` in both pinned libraries. `run-real.sh` rc 0 with
fresh ASan WRITE-64 and WRITE-512 at `avi_get_frame (avi_player.c:1222)`,
safe48 and both fixed cases clamped to 48; `run-realobj.sh` 11 PASS / 0 FAIL
with the chosen marker in a live `pjmedia_port`; `run-vidport.sh` 16 PASS /
0 FAIL on three fresh runs. Source-bound at `avi_player.c:1221` ineffective
assert / `:1222` bare `file_read3`, fixed `:1231-1235` clamp, shipped
`enc_clock_cb vid_port.c:1176`. No pointer called or dereferenced, no wire,
no command.

Two NITs, no grade impact: (1) the #5958 receipt expected `NEIGHBOR_AFTER`
from `run-real`, but commit `4f9314a9` removed that print before the asked
HEAD; `real-driver.c:135` now emits only `NEIGHBOR_BEFORE`, and chosen-byte
proof lives in the realobj and vidport lanes. (2) One `run-vidport.sh` run
was 15 PASS / 1 FAIL (rc 0) when a transient zero frame size missed the
150 ms wait. The author repaired the runner: `real/vidport-driver.c` now
keeps the pull window and polls up to 2 s for a transient zero, and
`real/run-vidport.sh` exits 1 on any FAIL. Five sequential reruns are
16 PASS / 0 FAIL, rc 0 (receipt in `PROVENANCE.md`).


## Grade and tractability

- **Rung 3 confirmed in a real consumer:** GCC and Clang ASan on the verbatim
  pinned branch, plus a real `pjmedia` build at the vulnerable parent, show
  heap OOB WRITEs of 64 and 512 bytes in `avi_get_frame()` on a real crafted
  AVI, with fixed and safe-input controls.
- **Rung 4 author-DEMONSTRATED with a real library object:** in a real
  `pjmedia` build, chosen `MISHE-PJPROJECT!` bytes overwrite a live
  `pjmedia_port` created by `pjmedia_bidirectional_port_create()` from the
  same pj pool, 48 bytes past the frame: a pointer-valued field at 64-byte
  length and signature, `get_frame`, `put_frame` and `pdata` at 512 bytes.
  None of those pointers was called or dereferenced, and that adjacency is
  driver-groomed through real allocator calls rather than a shipped caller
  layout. W242 adds a natural shipped-caller adjacency: a live `pj_mutex_t`
  at frame+48, overwritten with chosen bytes without driver grooming.
  W243 adds a natural shipped-*sample* allocation order where a live
  pointer-bearing `pjmedia_clock` sits at frame+48 and its `pool`, `cb`,
  `user_data` and `lock` words take chosen values, again without a call.
  All four real lanes are ESTABLISHED AS LABELED (W303); replay found no
  counterexample and did not advance the grade.

- **Not rung 5:** no live loopback service, no attacker-supplied bytes
  through a network wire, no pointer hijack, no command side effect.

The remaining work is scope, not mechanics: a pointer-bearing victim in a
natural production-library layout (W243's natural victim is in a shipped
sample), then a loopback target fed attacker AVI bytes and a benign command
side effect with vulnerable, fixed and safe controls. No pointer was
called, and no network wire into `avi_get_frame()` exists in the pinned
source. Do not claim that path.

Negative checked: the shipped video bridge
`pjmedia_vid_conf_add_port()` allocates `cport->get_buf` as the last item
from the port's own pool (`vid_conf.c:555-568`); the following
`listener_slots`, `transmitter_slots`, `render_states` and `render_pool`
allocations use the conference's main pool (`:572-606`). No pointer-bearing
library object is naturally adjacent after the AVI frame in that caller.
Positive checked in W242: the shipped `pjmedia_vid_port_create()` allocates
the frame from a fresh pool (`vid_port.c:688`) and a live mutex from that
pool (`:701`), and the active clock passes that buffer into the AVI virtual
device (`:1176` → `avi_dev.c:636`), so the mutex is a natural victim.

## Duplicate check

`reports/frontier-*.md`, the wall's do-not-duplicate list and `lab/frontier/`
were checked before provisioning. `sofiasip2shell`, `baresip2shell` and
`opensips2shell` cover other SIP stacks; no pjproject brief, lab or window
exists and pjproject is absent from the admitted-target list.
