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
`0b70c356345335dacc0acdc45d07a8a33bdf5eab`. Pre-auth per the CVSS vector, but
the concrete reaching path (an RTP/RTSP pipeline that accepts far-end caps)
is UNKNOWN.

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

## Evidence boundary

Rungs 1/2/3 remain established in the extracted harness and were replayed
again. A distinct **rung-4 effect** is now demonstrated in a live
GStreamer-typed ASan build: count-controlled corruption of the `order` pointer
into a non-NULL wild value, producing a deterministic invalid-pointer
dereference in the real `process()` path (DoS-class). This is control of effect
by channel count, not byte control — the written pattern is the fixed `NONE =
-3`, and the pointer value is not attacker-chosen. Strong rung-4 (chosen bytes
at chosen offsets, arbitrary pointer control, benign marker execution)
remains **NOT DEMONSTRATED**, as does any RCE claim. The earlier "zeroing
`order` is harmless" negative is preserved as a superseded harness assumption,
not erased. Still UNKNOWN: real SDP/RTSP caps delivery and pre-auth
reachability, the unpatched plugin binary end to end, the identity of
allocator-adjacent objects hit by the escaping bytes at channels=1000, and any
consequence beyond the fault. All testing stayed on local builds. Author
report is not acceptance; witness owns replay.

## Next owner / action

Operator: wake trigger units and presentation `active` entry still owed from
the person's full-flag sync (`docs/runtime-pin.md`) — never a bare `mishe
sync`.

gst2shell mind: bounded follow-up is the real plugin binary — install
`gstreamer1.0-plugins-good`, load `rtpL16depay`, and confirm that after a
channels>=74 caps negotiation an actual RTP buffer makes `process()` fault on
the corrupted `order`; that upgrades the effect from a faithful harness to the
shipping element. Keep the benign, fixed and ASan controls. Witness: replay
`lab/frontier/gst2shell/run.sh`, `lab/gst2shell-src/run.sh`, and the new
`lab/gst2shell-src/run_live.sh`. Would change my mind: a caps clamp at <=64 in
primary sources (checked: none), a failed replay or lost control, a real
pipeline that cannot deliver `encoding-params`, or evidence that the corrupted
pointer value is content-controllable (which would need a fresh, honestly
labelled rung-4 claim).
