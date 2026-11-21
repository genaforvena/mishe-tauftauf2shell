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

## Evidence boundary

Rungs 1/2/3 remain established in the extracted harness and were replayed
again. A distinct **rung-4 effect** is now demonstrated three ways: in a live
GStreamer-typed ASan harness (count-controlled `order` corruption to a wild
pointer and a deterministic dereference), in the **shipping `rtpL16depay`
plugin** (single caps field, deterministic SIGSEGV, two distinct fault modes),
and from **SDP text to the vulnerable field** through GStreamer's own SDP
parser. The N=1000 shipping fault is symbolicated to `srcpad->g_class` in a
heap-adjacent GstPad GObject — cross-object pointer corruption with a fixed
`NONE = -3` value, not attacker-chosen bytes. This is control of effect by
channel count, not byte control; the pointer value is not attacker-chosen.
Strong rung-4 (chosen bytes at chosen offsets, arbitrary pointer control,
benign marker execution) remains **NOT DEMONSTRATED**, as does any RCE claim.
The earlier "zeroing `order` is harmless" negative is preserved as a
superseded harness assumption, not erased. Still UNKNOWN: whether a specific
remote service accepts attacker-supplied SDP pre-auth (application-dependent;
no external probe was made), and any consequence beyond the deterministic
fault. All testing stayed local. Author report is not acceptance; witness
owns replay.

## Next owner / action

Operator: wake trigger units and presentation `active` entry still owed from
the person's full-flag sync (`docs/runtime-pin.md`) — never a bare `mishe
sync`.

gst2shell mind: symbolication and the local SDP→caps chain are DONE. Next
bounded step is to check whether an application-local far-end SDP ingestion
path (an RTSP record/ANNOUNCE service or a SIP-style offer built from this
plant's own loopback sources) can be instantiated in the lab without external
probing; if not, record the blocker and leave pre-auth reachability UNKNOWN.
Keep the benign, fixed and ASan controls and the SDP structure-name modelling
caveat. Witness: replay `lab/frontier/gst2shell/run.sh`,
`lab/gst2shell-src/run.sh`, `lab/gst2shell-src/run_live.sh`,
`lab/gst2shell-src/run_real.sh`, `lab/gst2shell-src/run_sdp.sh` and the gdb
debuginfod symbolication. Would change my mind: a caps clamp at <=64 in
primary sources (checked: none), a failed replay or lost control, a real
pipeline that cannot deliver `encoding-params`, or evidence that the
corrupted pointer value is content-controllable (which would need a fresh,
honestly labelled rung-4 claim).
