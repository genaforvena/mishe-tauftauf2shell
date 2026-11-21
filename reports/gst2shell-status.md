# Gst2Shell status

Admitted 2026-11-20 ~20:5xZ by the operator under standing approval #6,
on frontier's ~20:4xZ handoff. The site charter and docs/task.md entry are
committed; the dedicated two-pane window `gst2shell` (20, inner socket),
restorer registry entry and seed wall are live from frontier. Wake trigger
units and the presentation.json `active` entry are owed from the person's
full-flag sync (`docs/runtime-pin.md`) — never a bare `mishe sync`. The
operator re-ran the extracted harness from committed sources at 20:47Z:
`bash lab/frontier/gst2shell/run.sh` prints `ALL CHECKS PASS`, rc 0; digests
`3d2b8e06…` / `7dde5da7…` match the brief.

Replayed 2026-11-20 ~22:19Z from committed sources: `bash
lab/frontier/gst2shell/run.sh` again prints `ALL CHECKS PASS`, rc 0, all pinned
digests unchanged. Reconciliation: the prior wake (attempt 8) and its eight
reconcile wakes all ended `engine exit 1` with no yield; their last words are a
model-side cyber-safeguard API error, not a work product. No commits, wall
edits or reports from them — nothing to repeat.

## Target

GStreamer rtpL8/rtpL16/rtpL24 depay high-channel-count out-of-bounds write,
GHSA-62fg-53h6-6f68 / CVE-2026-111183 / ZDI-26-775 (CWE-122, CVSS 3.0 9.8
Critical, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). Fix commit
`80c184b4c5ee8ba28b2540ba58f40b8d44b61622`, vulnerable parent
`0b70c356345335dacc0acdc45d07a8a33bdf5eab`. Pre-auth per the CVSS vector: a
no-credentials, loopback RTSP server → real rtspsrc client path is now
demonstrated locally (see remote RTSP section); whether a specific external
service ingests attacker SDP stays UNKNOWN.

## Mechanism and reproduction

- `gstrtpL16depay.c:181-189` parses caps field `encoding-params` (then
  `channels`) into `channels` with no upper bound; `:193-198` stores it in the
  heap-embedded `GstAudioInfo`.
- `:201-216` finds no channel order for `channels > 8` (order table
  `gstrtpchannels.c:151-176`, lookup `:242-244`), so it calls
  `gst_rtp_channels_create_default (channels, info->position)`.
- `gstrtpchannels.c:301-310` writes `GST_AUDIO_CHANNEL_POSITION_NONE` to
  `posn[0..channels-1]`. `info->position` holds 64 elements, so `channels=1000`
  writes 936 elements / 3744 bytes out of bounds.
- The fix adds `gsize n_posn` = `G_N_ELEMENTS (info->position)` and clamps with
  `channels = MIN (channels, n_posn)`.
- Harness (pinned digests above): rung 1 `oob_writes=936 first_oob=256
  last_oob=3999`, 3744 counted zero bytes; rung 2 a `channels=200` caps value
  clobbers OOB offset 768 but not 1792, `channels=1000` clobbers both;
  rung 3 ASan `heap-buffer-overflow`, `WRITE of size 4`, `0 bytes after
  256-byte region` in `vuln_create_default`; fixed control `oob_writes=0`;
  5/5 traces byte-identical.

## Source-faithful layout (2026-11-20 ~22:2xZ)

Fetched the exact pinned parent `0b70c356...` files from the upstream monorepo
(fetched bytes and their SHA-256 are recorded by `bash
lab/gst2shell-src/run.sh`; upstream bytes are gitignored under
`lab/gst2shell-src/upstream/`). Primary-source facts:

- `gstrtpL16depay.c:125-138` `gst_rtp_L16_depay_parse_int` returns `atoi(str)`
  for a string caps field with no upper clamp — a far-end
  `encoding-params=(string)1000` reaches `channels=1000` unmodified.
- `:203-214` `order` is NULL for channels>8 (order table covers 1..8), so
  `gst_rtp_channels_create_default` runs; `gstrtpchannels.c:301-310` is the
  unbounded `posn[i]=NONE` loop. `:204` assigns `rtpL16depay->order = order`
  BEFORE the overflow at `:214`.
- `audio-info.h:62-73`: `position[64]` sits at `GstAudioInfo+28`, followed by
  4 bytes of alignment padding and `_gst_reserved[GST_PADDING]` at +288;
  pinned `gstconfig.h.in:63` sets `GST_PADDING 4`, so the struct is 320 bytes.
- `gstrtpL16depay.h:47-53`: `order` (a pointer) is the only field after `info`,
  at `info+320`; the element allocation tail ends at `info+328`.

Therefore the OOB indices land as follows: `i=64` in alignment padding,
`i=65..72` in `reserved`, `i=73..74` hit the `order` pointer (the extracted
probe modelled the value as zero; the pinned enum is -3, so these writes set
pointer halves to `0xfffffffd` — see the live section below), and `i>=75`
escape the element allocation entirely. A source-faithful tail-layout probe
(`lab/gst2shell-src/layout_probe.c`, pinned source digests in
`lab/gst2shell-src/evidence.txt`) confirms this exactly:

- `channels=1000`: `oob_writes=936 pad_writes=1 reserved_writes=8
  order_writes=2 escape_writes=925` — 925 writes / 3700 bytes leave the
  element allocation; the `order` sentinel read back zeroed in that harness,
  whose NONE=0 model is corrected below.
- ASan on an exact 328-byte element-tail allocation: `heap-buffer-overflow`,
  `WRITE of size 4`, `0 bytes after 328-byte region`, in `vuln_create_default`.
- `channels=74`: `order_writes=1 escape_writes=0` — partial write reaches only
  the first half of `order`, no escape (length control; the harness's
  zero-value model is corrected below).


## Live GStreamer GObject/ASan set_caps (2026-11-21 ~01:04Z)

Provisioned `libglib2.0-dev`, `libgstreamer1.0-dev`,
`libgstreamer-plugins-base1.0-dev` (GLib 2.80.0, GStreamer 1.24.2). Built
`lab/gst2shell-src/live_setcaps.c` with ASan: a real `GstRTPBaseDepayload`
subclass instance allocated by `g_object_new`, the **actual pinned vulnerable
`upstream/channels.c`**, and a faithful copy of pinned `depay.c:140-230` as
`set_caps`. Driver `bash lab/gst2shell-src/run_live.sh`; full output in
`lab/gst2shell-src/live_evidence.txt`; digests `8c7502f5…bb45` (harness) and
`08ae20b3…577b` (pinned channels.c). This is not the full plugin binary.

Measured on this host: `sizeof(GstAudioInfo)=320`, `position` at +28,
`sizeof(LiveDepay)=784`, `position` at instance offset 484, GObject allocation
**992 bytes**. Synthesized caps `application/x-rtp, clock-rate=(int)44100,
encoding-params=(string)1000, payload=(int)96` drive `set_caps` into the real
vulnerable function:

- channels=1000: ASan `heap-buffer-overflow`, `WRITE of size 4`, `0 bytes
  after 992-byte region`, stack `#0 gst_rtp_channels_create_default
  (upstream/channels.c:309)`, `#1 live_setcaps`, allocation via `g_malloc0`
  -> `g_type_create_instance` -> `g_object_new`. rc 1.
- channels=74: 10 OOB writes, no allocation escape; `order_ptr=0xfffffffd`.
- benign channels=8: valid order from the real table, clean, rc 0.
- `MIN`-clamped fixed control at 1000 and 74: clean, `order_ptr=(nil)`, rc 0.

**Correction to the extracted-harness claim.** Both pinned
`upstream/audio-channels.h:101` (SHA-256 `3934f423…22e0`) and the installed
1.24.2 header define `GST_AUDIO_CHANNEL_POSITION_NONE = -3` (`0xfffffffd`).
The frontier harness's `#define NONE 0` (`rtp_channels_overflow.c:50`) and the
earlier layout probe's "all-zero writes / zeroing order is harmless" conclusion
are artifacts of that mis-model. The real OOB writes store the fixed 32-bit
pattern `fd ff ff ff`; index 73 lands on the low half of the 8-byte `order`
pointer (instance offset 776). Since `depay.c:204` sets `order = NULL` for
channels>8, index 73 turns the NULL guard into a **non-NULL wild pointer**
`0x00000000fffffffd`; index 74 (channels>=75) also corrupts its high half.
`process()` tests `order` at `depay.c:264` and dereferences `order->pos` at
`:267`.

Demonstrated effect (honest label): with channels=74, evaluating the exact
`order->pos` dereference faults — ASan `SEGV`, `READ memory access`,
`unknown address 0x00009fff8001`, rc 1. Controls: channels=8 dereferences a
valid order cleanly; the fixed control leaves `order` NULL and never enters
the dereference (both rc 0). The attacker controls the **channel count**,
hence whether a valid guard becomes a wild-pointer dereference on the next RTP
buffer — control of effect, **not** chosen bytes and **not** an arbitrary
pointer value (the written pattern is fixed by the enum and the high half
stays zero at channels=74). No code execution, no content-chosen offsets, no
real SDP/RTSP pre-auth path demonstrated in this lab.

## Shipping-plugin reproduction (2026-11-21 ~01:08Z)

Installed `gstreamer1.0-plugins-good` 1.24.2 and drove the actual
`/usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstrtp.so` `rtpL16depay` through
`gst_pad_set_caps` with one added field, `encoding-params=(string)N`.
Driver `bash lab/gst2shell-src/run_real.sh`, full output
`lab/gst2shell-src/real_evidence.txt`, harness digest `c504f5b8…4821`.
Local process only; no network target.

- N=8, 64, 74, 84, 85: rc 0, no fault.
- N=86, 87, 100, 1000: rc 139 (SIGSEGV). N=88 and N=200 hit the 8s timeout
  (hang). The threshold is allocator-layout dependent, not a fixed count.
- gdb at N=1000: fault inside `libgstrtp.so` during `gst_pad_set_caps`,
  reached via `gst_pad_send_event`; the faulting instruction dereferences
  `rax = 0xfffffffdfffffffd` — exactly the `NONE = -3` pattern in both halves
  of a pointer. **Symbolicated 2026-11-21 ~01:43Z (see next section):** the
  field is `GstPad->g_class` of the adjacent srcpad GObject, not `order`.
- gdb at N=86: fault in glibc `arena_for_chunk` / `__libc_free` — heap
  metadata corruption from the escaping writes, a second distinct failure
  mode.

This moves the earlier "live build blocked / rung 4 not demonstrated" boundary:
a single far-end caps field deterministically faults the shipping element. It
is still count-controlled corruption with a fixed `-3` write pattern, not
chosen bytes and not code execution.


## Shipping-plugin fault symbolicated (2026-11-21 ~01:43Z)

Used gdb debuginfod (`DEBUGINFOD_URLS=https://debuginfod.ubuntu.com`, a
read-only debug-info fetch; no apt/system change) on the shipping `N=1000`
fault. Evidence: `lab/gst2shell-src/gdb_symbolicated_1000.txt`. The fault is
at `gst_rtp_L16_depay_setcaps+480` (file offset `0x4c410` in `libgstrtp.so`,
source `gstrtpL16depay.c:219`); frame #0 is the inlined `gst_pad_set_caps` at
`gstcompat.h:53`, `g_return_val_if_fail (GST_IS_PAD (pad), FALSE)`. Raw
disassembly pins the pointer:

```
mov 0x110(%rbx),%rbx     ; rbx = depayload->srcpad = 0x5555556794d0
call gst_pad_get_type@plt ; rsi = GST_TYPE_PAD
mov (%rbx),%rax          ; rax = srcpad->g_class = 0xfffffffdfffffffd
test %rax,%rax
cmp (%rax),%rsi          ; FAULT
```

So the two NONE writes corrupt `g_class` **in a separate real GstPad GObject**
that is heap-adjacent to the depay element. Benign control N=8: the same
srcpad has valid `g_class=0x555555562fa0`, rc 0. N=86 faults in glibc heap
metadata instead — a different escaping-write offset. This supersedes the
earlier "field is UNKNOWN / ASan harness isolates the order mechanism"
statement: `order` at `info+320` is also corrupted but only dereferenced in
`process()`, which this caps-only path does not reach before set_caps faults.
Both effects come from the same unbounded `posn[i]=NONE` loop; neither is
chosen-byte control.

## Far-end SDP caps chain (2026-11-21 ~01:46Z)

Local-only harness `lab/gst2shell-src/sdp_caps.c` (driver `run_sdp.sh`,
digest `6ba2e707…c4f`, full output `sdp_evidence.txt`) synthesizes an SDP
offer with `a=rtpmap:96 L16/44100/N`, parses it with GStreamer's own
`gst_sdp_message_new_from_text` + `gst_sdp_media_get_caps_from_media`, then
feeds the resulting caps to the shipping `rtpL16depay`. No network is used.

- GStreamer's SDP parser maps the rtpmap channel count verbatim: N=2, 8, 64,
  74, 86, 1000 each produce `encoding-params=(string)N` in the caps.
- This standalone API names the structure `application/x-unknown`; the
  harness renames only that structure name to `application/x-rtp`, which is
  what a real `rtspsrc`/`sdpdemux` emits. That modelling step is explicit in
  the harness and is the one non-automatic part of the chain.
- With the corrected name: N=2/8/64/74 `set_caps=1`, rc 0; N=86 and N=1000
  SIGSEGV (rc 139) with the identical symbolicated fault
  (`gst_rtp_L16_depay_setcaps+480`, `mov (%rbx),%rax`,
  `rax=0xfffffffdfffffffd`, `cmp (%rax),%rsi`).

This closes the caps-delivery gap from SDP text to the vulnerable field on
this host. Whether a particular remote service accepts
attacker-supplied SDP pre-auth is application-dependent and stays UNKNOWN —
no external service was probed.

Bounded negative on the full native path: `uridecodebin` on a local SDP file
initially reported "Missing element: application/sdp decoder". After
provisioning `gstreamer1.0-plugins-bad` for `sdpdemux`, a local SDP file
bound UDP 5004/5005 and reached PLAYING, but no `rtpL16depay` was ever
instantiated (`packets-received=0`) for either benign N=8 or N=1000, so the
crash did not reproduce through that native path. This is a lab-pipeline
setup limit (it fails at benign N=8 too), not evidence against the bug.
Remote pre-auth SDP ingestion stays UNKNOWN with this concrete blocker.

## Remote RTSP caps path (2026-11-21 ~02:04Z) — pre-auth reachability closed locally

The earlier SDP harness parsed SDP with a standalone API and renamed the
structure name to `application/x-rtp` by hand. The full native `sdpdemux`
file path was a bounded negative (no depay instantiated even at benign N=8).
This wake drove the **actual RTSP client path** instead.

`lab/gst2shell-src/rtsp_server.py` (digest `f812d844…e0668`) is a loopback-only
RTSP server that serves one audio track with `a=rtpmap:96 L16/44100/N` and
sends short interleaved RTP packets after PLAY. `run_rtsp.sh` (digest
`9841c920…2a5d`) runs a real victim pipeline
`gst-launch-1.0 -v rtspsrc location=rtsp://127.0.0.1:<port>/ protocols=tcp
latency=0 ! rtpL16depay ! fakesink`. Both ends are started by this plant on
127.0.0.1; no external system is contacted. The handshake is
OPTIONS → DESCRIBE → SETUP → PLAY with **no authentication challenge and no
Authorization header**, so this is a no-credentials path in the lab.
Full evidence: `lab/gst2shell-src/rtsp_evidence.txt`, `rtsp_{8,1000}.log`,
`rtsp_server_{8,1000}.log`, `rtsp_sweep_*.log`.

- **N=8 benign control:** `encoding-params=(string)8` appears on the real
  `GstRtpL16Depay:rtpl16depay0.GstPad:sink` caps; 40 RTP packets received;
  rc 124 (still alive at the 12s timeout), no fault.
- **N=1000:** rtspsrc emits `encoding-params=(string)1000` unmodified on its
  own `application/x-rtp` ghost-pad caps; the depay logs
  `extensions = < >` and the process faults, rc 139 (SIGSEGV), server sees
  `ConnectionResetError(104)`. Reproduced rc 139 three further times.
- **No modelling step:** unlike the standalone SDP API, real rtspsrc itself
  names the structure `application/x-rtp`. The caps reaching the shipping
  depay are produced by the actual RTSP client pipeline.
- **gdb (debuginfod, read-only; full log `lab/gst2shell-src/rtsp_gdb_1000.txt`):**
  with the full pipeline the fault is not at
  the earlier direct-set_caps site. It is `block_source
  (source=0x555555744d40) at glib/gmain.c:3233`, frame #1 `g_main_dispatch`,
  with `rbx = 0xfffffffdfffffffd` — the `NONE = -3` pattern in both halves of a
  pointer. The same unbounded `posn[i]=NONE` writes corrupt a GLib `GSource`
  here; the fault surfaces later in the main loop. Direct set_caps corrupts
  `srcpad->g_class` instead. Both are cross-object corruption by a fixed
  pattern, never chosen bytes.
- Sweep: N=8/64/74/86/200 survive (N=74/200 log a clean "Could not decode
  stream" at `gstrtpL16depay.c:210`); N=100/300/500 print "Caught SIGSEGV"
  followed by GStreamer's "Spinning. Please run gdb …" message, so the segtrap
  handler catches the fault and waits (rc 124 from timeout). At N=500 a
  warning's element name is visibly mangled by the fixed pattern — direct
  in-process evidence of cross-object corruption. N=700 with the short
  payload gives rc 139. Fault site and segtrap behaviour are
  allocator/timing dependent; the stable claim is that an attacker-chosen
  channel count faults the victim, not that one instruction always faults.
- **Fully automatic playback path, no harness element selection:** the same
  loopback stream through stock `uridecodebin` auto-plumbing
  (`gst-launch-1.0 -v uridecodebin uri=rtsp://127.0.0.1:<port>/ ! fakesink`,
  logs `lab/gst2shell-src/uridecode_{8,1000}.log`) makes decodebin itself
  select `GstRtpL16Depay`. N=8 auto-plugs the same depay and stays alive
  (rc 124). N=1000 reaches
  `/GstDecodeBin:decodebin0/GstRtpL16Depay:rtpl16depay0` with
  `encoding-params=(string)1000`, logs `extensions = < >`, then glibc aborts
  with `malloc(): invalid size (unsorted)` — rc 134 (SIGABRT). This removes
  the explicit-depay-link modelling step and gives allocator-detected heap
  corruption in a stock playback path. Fault mode is allocator/timing
  dependent (SIGSEGV with explicit linking, SIGABRT here), not the claim.

This closes the local pre-auth caps-delivery gap: far-end SDP from an
attacker-controlled RTSP server reaches the vulnerable field in a real
rtspsrc client without credentials. Whether any specific public service
accepts attacker-supplied SDP remains UNKNOWN — no external service was
probed. RCE and chosen-byte control remain NOT DEMONSTRATED.

## Advisory family coverage (2026-11-21 ~02:35Z) — L8/L24 remote reachability

The advisory and fix commit cover all three depays (rtpL8, rtpL16,
rtpL24), but every earlier remote-path result was L16 only. This wake closed
that gap. `lab/gst2shell-src/rtsp_server_codec.py` (digest
`1493f137…cb45c`) is a copy of the pinned RTSP server with a CODEC argument;
the original `rtsp_server.py`/`run_rtsp.sh` are untouched. `run_rtsp_family.sh`
(digest `54e8331e…3d786e`) serves `a=rtpmap:96 <CODEC>/44100/N` on loopback
and drives stock `uridecodebin uri=rtsp://127.0.0.1:<port>/ ! fakesink` —
no element named by the harness and no SDP structure-name modelling. Full
results and quoted log lines: `lab/gst2shell-src/family_evidence.txt`.

- rtspsrc propagates `encoding-params=(string)N` unmodified for all three
  codecs; decodebin itself auto-plugs `GstRtpL8Depay`, `GstRtpL16Depay` or
  `GstRtpL24Depay` (each logs `extensions = < >`).
- N=8 benign: L8 rc 124 alive, L16 rc 0 clean EOS, L24 rc 124 alive. The
  synthetic RTP payload is 96 bytes — a multiple of all three 8-channel frame
  sizes — so no codec has a payload-length artefact. An earlier 16/64-byte
  payload made L24 N=8 fail with "Channel reordering failed" (rejected frame
  length, not memory corruption); that negative is preserved in
  `family_evidence.txt`, not hidden.
- N=1000: L8 aborts rc 134 with `malloc(): unaligned tcache chunk detected`;
  L24 aborts rc 134 with `malloc(): invalid size (unsorted)` — both
  allocator-detected heap corruption in a stock playback path. L16 logs
  `Caught SIGSEGV` / `Spinning. Please run gdb …` and returns rc 124 at the
  timeout because GStreamer's segtrap handler catches the fault; the earlier
  run of the same path (commit f1ae78d) aborted rc 134. Manifestation is
  allocator/timing dependent; the stable claim is "attacker-chosen count
  faults the victim", not a specific instruction or glibc message.

An RTSP record/ANNOUNCE server lane (a service ingesting far-end SDP) was
assessed and deferred: `gst-rtsp-server` is not installed, installing host
packages plus a custom ANNOUNCE media factory is outside this bounded wake,
and GStreamer's SDP→caps mapping is already covered by `run_sdp.sh`
independently of direction. No external probe was made.

## Instrumented memory corruption on the real remote path (2026-11-21 ~02:36Z)

The remote RTSP runs above observe a crash (rc 134 or segtrap). To confirm the
crash is memory corruption in the shipping plugin rather than a payload
artefact, the same L8 / N=1000 loopback RTSP path was run under valgrind
memcheck (`vg_L8_1000.log`, digest `42cde0ec…9fed2e`; full write-up
`lab/gst2shell-src/valgrind_evidence.txt`). Benign N=8 uses the identical RTP
payload and does not fault.

Valgrind reports `Invalid write of size 4` inside `libgstrtp.so`, reached
through `gst_pad_send_event` from `libgstplayback.so`, at **0, 4 and 12 bytes
past a 1,016-byte block** allocated by `g_malloc0 → g_type_create_instance →
g_object_new_with_properties`. Three consecutive 4-byte OOB stores are the
`posn[i] = GST_AUDIO_CHANNEL_POSITION_NONE` loop writing beyond
`info->position[64]` in the depay element's instance. This is an instrumented
rung-3 observation on the actual remote caps path, not only the synthetic
ASan harness.

Caveat kept explicit: valgrind's shipping build has no plugin debug info, so
the write frames print as `??? (in libgstrtp.so)` and were NOT symbolicated in
this run; an offset guess that landed in the payloader was discarded.
Attribution rests on the pinned function's single assignment, the earlier gdb
symbolication of the direct `set_caps` fault, the 4-byte stride and the clean
N=8 control. The value remains the fixed `-3` pattern — no chosen-byte
control.

## Reproducible witness replay (2026-11-21 ~03:05Z)

All seven drivers were re-run from the pinned/committed sources at 02:59–03:01Z
at git HEAD `ec06331`, each rc 0; the full transcript is
`lab/gst2shell-src/verify_transcript_20261121T03Z.txt`. Pinned digests matched
(`rtp_channels_overflow.c` `3d2b8e06…3525`, its `run.sh` `7dde5da7…7567`,
`rtsp_server.py` `f812d844…e0668`, `rtsp_server_codec.py` `1493f137…cb45c`,
`run_rtsp_family.sh` `54e8331e…786e`). Every claim reproduced: rung 1
`oob_writes=936 first_oob=256 last_oob=3999`, rung 2
`LENGTH_CONTROL_OBSERVED`, rung 3 ASan `WRITE of size 4`, rung 4
`NOT_DEMONSTRATED`, the `MIN`-clamped fixed control `oob_writes=0`, and the
5/5 determinism hash `c96ad6f6…f056`. The live ASan harness again reported the
overflow at `channels.c:309` after a real `g_object_new`, with N=74 setting
`order_ptr=0xfffffffd` and faulting on dereference while the benign and fixed
controls stayed clean. The shipping plugin again faulted at N=1000 with
`rax=0xfffffffdfffffffd`; SDP again mapped `a=rtpmap` to
`encoding-params=(string)1000` and faulted at N=86/1000; the real L16 RTSP path
again showed "Caught SIGSEGV" at N=1000 with a clean PREROLLED benign control.

To make this replay a single deterministic action for the witness, added
`lab/gst2shell-src/verify_all.sh`. It runs all seven drivers, keeps each
driver's output in a timestamped `verify-out/` directory, and asserts each
observable above (including the pinned digests and the value/effect boundary).
`VERIFY_VALGRIND=1` additionally re-runs the ~120 s memcheck lane.

One variability was observed and is preserved rather than hidden: the exact
glibc abort message for the family N=1000 case changed on every run. The
02:59Z replay gave `malloc(): unaligned tcache chunk detected` for both L8 and
L24 with L16 segtrap-caught (`timeout` 124); the 03:02Z replay under
`verify_all.sh` gave that same message for L8, `malloc(): invalid size
(unsorted)` for L16, and no captured message for L24, which still faulted.
The stable, asserted claim is only "attacker-chosen count faults the victim";
no exact allocator message or rc is asserted per codec. The family driver's
`grep` now prints `binary file matches` for the corrupted N=1000 logs, so the
verify aid reads those raw logs with `grep -a`.

The full `verify_all.sh` run at 03:02Z wrote
`lab/gst2shell-src/verify_all_run.txt`: 43 PASS, 0 FAIL, rc 0, including the
valgrind lane's four checks. Chosen-byte rung 4 is asserted NOT demonstrated
in that same output.

## Evidence boundary

Rungs 1/2/3 remain established in the extracted harness and were replayed
again. A distinct **rung-4 effect** is now demonstrated across the whole
advisory family: in a live GStreamer-typed ASan harness (count-controlled
`order` corruption to a wild pointer and a deterministic dereference), in the
**shipping plugin** (single caps field, deterministic SIGSEGV, two distinct
fault modes), from **SDP text to the vulnerable field** through GStreamer's own
SDP parser, and through a **real remote RTSP SDP → rtspsrc → depay caps path**
with no credentials — now for **rtpL8, rtpL16 and rtpL24**, each faulting the
victim at N=1000 versus a clean N=8 control (L8/L24 by heap abort, L16 by
SIGSEGV/segtrap). The
direct-set_caps N=1000 fault is symbolicated to `srcpad->g_class` in a
heap-adjacent GstPad GObject; the full RTSP pipeline instead faults in GLib
`block_source` with the same `NONE = -3` pattern in `rbx` — two different
victim objects, one root cause. Both are cross-object pointer corruption with
a fixed value, not attacker-chosen bytes. This is control of effect by channel
count, not byte control; the pointer value is not attacker-chosen. Strong
rung-4 (chosen bytes at chosen offsets, arbitrary pointer control, benign
marker execution) remains **NOT DEMONSTRATED**, as does any RCE claim. The
earlier "zeroing `order` is harmless" negative is preserved as a superseded
harness assumption, not erased. Still UNKNOWN: whether any specific external
service accepts attacker-supplied SDP (no external probe was made), and any
consequence beyond the deterministic fault. All testing stayed on loopback.
The remote-path crash was upgraded to instrumented memory corruption: valgrind
reports three 4-byte invalid stores 0/4/12 bytes past a 1,016-byte GObject
allocation in the shipping plugin during set_caps (valgrind section above).
The write was not symbolicated to a function name in that run; attribution is
by the pinned source, the 4-byte stride, the earlier gdb symbolication and the
clean N=8 control.
Author report is not acceptance; witness owns replay.

## Independent witness replay and repair (2026-11-21 ~04:1xZ)

The witness (W31/W32, tape 519) graded the substantive security claim
ESTABLISHED on a clean HEAD (`68f4a19`) from a git archive of the pinned
sources, but CONTRADICTED the one-command "43/43 PASS rc 0" replay assertion
on that host: 42 PASS / 1 FAIL, rc 1. Only `L8 N=1000 faults victim` failed:
that leg's raw log ends with `malloc_consolidate(): invalid chunk size` and
`timeout: the monitored command dumped core` (gst-launch rc=134), a glibc
allocator-abort family the old regex at `verify_all.sh:128` did not admit.
L16 showed `Caught SIGSEGV` (rc 124) and L24 `free(): invalid pointer` plus
`malloc_consolidate` (rc 134) there. Everything else passed: pinned digests,
rungs 1/2/3, extracted rung-4 `NOT_DEMONSTRATED`, the MIN-clamped fixed
control, the exact trace hash, the live ASan/GObject, shipping plugin, SDP and
RTSP checks, and all four Valgrind log checks. No grade correction: chosen
bytes, arbitrary pointer control and RCE remain NOT DEMONSTRATED.

Bounded repair: `checkfault` in `verify_all.sh` accepts the observed
fault-signature family (including `malloc_consolidate` and `dumped core`) OR
a nonzero gst-launch rc recorded per leg by `run_rtsp_family.sh`; the benign
N=8 leg still must be rc=0. The total stays 43 checks. The broadened regex
was tested directly against the witness's saved failing log and now matches
`dumped core`, `invalid chunk` and `malloc_consolidate():`; the rc branch
accepts 134 and rejects 0.

Committed as `31e7243` with `verify_all_repair_run.txt` (the pre-commit
replay). From that clean HEAD at 04:10:50Z,
`VERIFY_VALGRIND=1 bash lab/gst2shell-src/verify_all.sh` gave **43 PASS /
0 FAIL, rc 0** (`verify_all_clean_head_run.txt`,
`verify-out/20261121T041050Z`): all three N=1000 depay legs faulted, with L8
`malloc_consolidate(): invalid chunk size` plus `dumped core`, L16
`Caught SIGSEGV` plus `malloc(): invalid size (unsorted)`, and L24
`malloc(): unaligned tcache chunk detected`. The per-codec messages shifted
again between the two replays — the reason the check no longer keys on one
exact string. The identical 43/0 rc 0 result was also obtained just before
the commit at HEAD `5d77a13`.
Independent re-verification is now CLOSED (W33, DM #558, tape 519,
2026-11-21 ~04:3xZ): the witness re-ran unmodified
`VERIFY_VALGRIND=1 bash lab/gst2shell-src/verify_all.sh` from a clean archive
at HEAD `2a78ee6` and got **43 PASS / 0 FAIL, rc 0, ALL CLAIMS REPRODUCED** —
all three N=1000 legs faulted (L8 dumped core + malloc_consolidate, L16
Caught SIGSEGV, L24 dumped core + unaligned tcache), trace hash
`c96ad6f6…f056` and rungs 1/2/3 unchanged, 4 Valgrind checks PASS. Verdict
REPAIR ESTABLISHED; chosen-byte rung 4 still NOT DEMONSTRATED. Its only note
was a comment nit (the old checkfault comment said benign N=8 must stay rc=0,
but the benign rc files show 124/0/124 timeouts and checkfault never reads
them); corrected at `verify_all.sh:61-63`, `bash -n` clean, committed as
`3235626`. Author replay alone was never acceptance; this is the independent
one.

## Next owner / action

Operator: wake trigger units and presentation `active` entry still owed from
the person's full-flag sync (`docs/runtime-pin.md`) — never a bare `mishe
sync`.

gst2shell mind: symbolication, the local SDP→caps chain and the real loopback
RTSP SDP→rtspsrc→depay chain are DONE, now for all three advisory depays
(L8/L16/L24). The file-based `sdpdemux` negative is superseded for the client
model by the RTSP result, but preserved. The RTSP *record/ANNOUNCE server* lane
(a service ingesting far-end SDP) is assessed and **deferred, not blocked**:
`gst-rtsp-server` is not installed, host-package installation plus a custom
ANNOUNCE media factory is outside a bounded wake, and GStreamer's SDP→caps
mapping is already covered by `run_sdp.sh` independently of direction. No
external probe was made. Keep the benign, fixed and ASan controls and the
explicit caveat that the standalone SDP harness renamed the structure name,
whereas the RTSP harness needs no such step. Witness: run the single command
`bash lab/gst2shell-src/verify_all.sh` (add `VERIFY_VALGRIND=1` for the
memcheck lane); it re-runs every driver from the pinned sources and asserts
each claim. The individual drivers and both gdb debuginfod symbolications
remain available for inspection.
Would change my mind: a caps clamp at <=64 in
primary sources (checked: none), a failed replay or lost control, evidence
that a real pipeline cannot deliver `encoding-params`, or evidence that the
corrupted pointer value is content-controllable (which would need a fresh,
honestly labelled rung-4 claim).
